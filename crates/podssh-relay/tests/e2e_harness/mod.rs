//! The tests' operator, node and stand-in relay for the end-to-end channel
//! (T-088). The stand-in relay reads the channel's frames, does one fault to
//! one of them, and keeps each byte that it carried, so that a test can look
//! for plain text in it.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::e2e::ends::{self, Node};
use podssh_relay::e2e::{Error, MAGIC};
use podssh_relay::identity::{Identity, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

pub const PIPE: usize = 256 * 1024;
pub const LIMIT: Duration = Duration::from_secs(30);

/// What the stand-in relay does to the frames of one direction, counted
/// from 0 with the handshake's: an operator's first data is its frame 2,
/// and a node's verdict is its frame 1, its first data its frame 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    /// One bit of the message changed.
    Flip(usize),
    Drop(usize),
    Repeat(usize),
    /// The frame and the next, in the other order.
    Swap(usize),
    /// The stream ends before this frame.
    CutBefore(usize),
}

/// An identity for the tests, from one byte.
pub fn identity(seed: u8) -> Arc<Identity> {
    Arc::new(Identity::from_seed(&[seed; 32]))
}

/// A node with this identity and admission, whose lines are kept.
pub fn node(
    me: Arc<Identity>,
    admit: impl Fn(&PublicKey) -> Result<(), String> + Send + Sync + 'static,
) -> (Node, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    let say = Arc::new(move |line: String| kept.lock().unwrap().push(line));
    (Node { identity: me, admit: Arc::new(admit), say }, lines)
}

/// A target that echoes each byte, and counts how often it is opened.
pub fn echo(opened: Arc<AtomicUsize>) -> impl FnOnce() -> std::future::Ready<Result<DuplexStream, String>> {
    move || {
        opened.fetch_add(1, Ordering::SeqCst);
        let (ours, mut theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if theirs.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = theirs.shutdown().await;
        });
        std::future::ready(Ok(ours))
    }
}

/// One session: the operator's application end, its session's task, the
/// node's lines, how often the target opened, and what the relay carried.
pub struct Run {
    pub app: DuplexStream,
    pub session: JoinHandle<Result<PublicKey, Error>>,
    pub node_task: JoinHandle<()>,
    pub lines: Arc<Mutex<Vec<String>>>,
    pub opened: Arc<AtomicUsize>,
    pub carried: Arc<Mutex<Vec<u8>>>,
    /// The operator's frames that the relay has read.
    pub up_frames: Arc<AtomicUsize>,
}

/// An operator of `operator` that checks the node's key with `check`, to the
/// node `node` with an echo target, through a stand-in relay that does
/// `up` to the operator's frames and `down` to the node's.
pub fn run(
    operator: Arc<Identity>,
    check: impl FnOnce(&PublicKey) -> Result<(), String> + Send + 'static,
    node: (Node, Arc<Mutex<Vec<String>>>),
    up: Fault,
    down: Fault,
) -> Run {
    let opened = Arc::new(AtomicUsize::new(0));
    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, session) = ends::operator(app_end, operator, check);
    let (node_link, relay_end) = tokio::io::duplex(PIPE);
    let (node_end, lines) = node;
    let target = echo(opened.clone());
    let node_task = tokio::spawn(async move { ends::serve_node(node_link, &node_end, target).await });
    let carried = Arc::new(Mutex::new(Vec::new()));
    let up_frames = Arc::new(AtomicUsize::new(0));
    stand_in(cipher, relay_end, (up, up_frames.clone()), down, carried.clone());
    Run { app, session: tokio::spawn(session), node_task, lines, opened, carried, up_frames }
}

/// The stand-in relay between `a` and `b`, each direction on its own task.
pub fn stand_in(
    a: DuplexStream,
    b: DuplexStream,
    up: (Fault, Arc<AtomicUsize>),
    down: Fault,
    carried: Arc<Mutex<Vec<u8>>>,
) {
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    tokio::spawn(direction(ar, bw, up.0, carried.clone(), up.1));
    tokio::spawn(direction(br, aw, down, carried, Arc::default()));
}

async fn direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut from: R,
    mut to: W,
    fault: Fault,
    carried: Arc<Mutex<Vec<u8>>>,
    frames: Arc<AtomicUsize>,
) {
    let mut magic = [0u8; MAGIC.len()];
    if from.read_exact(&mut magic).await.is_err() || pass(&mut to, &magic, &carried).await.is_err() {
        return;
    }
    let mut held: Option<Vec<u8>> = None;
    let mut index = 0usize;
    while let Some(frame) = next_frame(&mut from).await {
        frames.fetch_add(1, Ordering::SeqCst);
        let out: Vec<Vec<u8>> = match fault {
            Fault::Flip(k) if k == index => {
                let mut changed = frame.clone();
                let last = changed.len() - 1;
                changed[last] ^= 0x01;
                vec![changed]
            }
            Fault::Drop(k) if k == index => vec![],
            Fault::Repeat(k) if k == index => vec![frame.clone(), frame],
            Fault::Swap(k) if k == index => {
                held = Some(frame);
                vec![]
            }
            Fault::Swap(k) if k + 1 == index => vec![frame, held.take().unwrap_or_default()],
            Fault::CutBefore(k) if k == index => break,
            _ => vec![frame],
        };
        index += 1;
        for frame in out {
            if pass(&mut to, &frame, &carried).await.is_err() {
                return;
            }
        }
    }
    let _ = to.shutdown().await;
}

/// One whole frame, its length included; `None` at the stream's end.
async fn next_frame<R: AsyncRead + Unpin>(from: &mut R) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    from.read_exact(&mut len).await.ok()?;
    let mut frame = vec![0u8; 2 + usize::from(u16::from_be_bytes(len))];
    frame[..2].copy_from_slice(&len);
    from.read_exact(&mut frame[2..]).await.ok()?;
    Some(frame)
}

async fn pass<W: AsyncWrite + Unpin>(to: &mut W, bytes: &[u8], carried: &Mutex<Vec<u8>>) -> std::io::Result<()> {
    carried.lock().unwrap().extend_from_slice(bytes);
    to.write_all(bytes).await?;
    to.flush().await
}

/// Send `chunk` through the session's echo and read it back at the same
/// time, as each pipe holds less than a large chunk: a small one is one
/// message each way.
pub async fn echo_back(app: &mut DuplexStream, chunk: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut back = vec![0u8; chunk.len()];
    let (mut r, mut w) = tokio::io::split(&mut *app);
    let both = async { tokio::try_join!(w.write_all(chunk), r.read_exact(&mut back)) };
    tokio::time::timeout(LIMIT, both).await.map_err(|_| std::io::Error::other("no echo within the limit"))??;
    Ok(back)
}

/// Whether `needle` occurs in `haystack`.
pub fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
