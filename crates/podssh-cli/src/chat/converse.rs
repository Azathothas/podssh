//! One conversation over a byte stream (T-099): the user's lines in, the
//! peer's records out, and the files between. A writer task drains two
//! queues to the peer: one for the small records, and a bounded one for the
//! chunks of a file, which the loop fills only when there is room, beside
//! its read. So the loop never stops reading for a full queue, and two sides
//! that send files at once cannot wait on each other.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;

use podssh_core::chat::{record::MAX_CHUNK, Decoder, Record, Session};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::files::Incoming;
use super::lines::Lines;
use super::output::Output;
use super::talk::Talk;

/// The chunks of files that may wait for the writer.
const CHUNKS_QUEUED: usize = 8;

/// What one run does besides talking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Once {
    /// Talk until stdin ends and each message and file went, or the peer
    /// leaves.
    No,
    /// Send this message, and end once it is acknowledged.
    Send(String),
    /// Offer this file, and end once it arrived.
    File(PathBuf),
}

/// How the conversation runs.
#[derive(Debug, Clone)]
pub struct Options {
    pub nick: String,
    /// The user's accept of each file, into this directory.
    pub accept_dir: Option<PathBuf>,
    /// Where an accept with no path puts a file.
    pub here: PathBuf,
    pub once: Once,
}

/// How the conversation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// stdin ended (or `/quit`) and each message and file went, or the one
    /// thing of `--send` or `--file` is done.
    Done,
    /// The peer ended the conversation.
    PeerLeft,
    /// The side that waits has another peer.
    Busy,
    /// `--file`: the peer declined the file.
    Declined,
    /// `--file`: the file arrived with another SHA-256, and was not kept.
    Damaged,
    /// The `--timeout` passed.
    TimedOut,
    /// Ctrl-C or SIGTERM.
    Stopped,
    /// The peer broke the protocol, or the stream or the road failed: why.
    Failed(String),
}

/// The end, and the messages that the peer never acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub ended: Ended,
    pub undelivered: Vec<String>,
    /// The peer's nick, once it greeted: with none, no peer was there.
    pub peer: Option<String>,
}

/// Talk over `stream`: the user's lines come from `lines` (none are read for
/// `--send` and `--file`), and what the user sees goes to `out`.
pub async fn converse<S, W>(stream: S, lines: &mut Lines, out: &mut Output<W>, opts: Options) -> Summary
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    W: AsyncWrite + Unpin,
{
    converse_until(stream, lines, out, opts, std::future::pending()).await
}

/// [`converse`], which an end from outside stops too: when `until` comes
/// first, the conversation ends with its end, and its summary still lists
/// the messages that went with no acknowledgement.
pub async fn converse_until<S, W, U>(
    stream: S,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: U,
) -> Summary
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    W: AsyncWrite + Unpin,
    U: Future<Output = Ended>,
{
    let (from_peer, to_peer) = tokio::io::split(stream);
    let (control, control_rx) = mpsc::unbounded_channel();
    let (chunks, chunks_rx) = mpsc::channel(CHUNKS_QUEUED);
    let writer = write_records(to_peer, control_rx, chunks_rx);
    let talk = Talk::new(control, opts);
    let conversation = run(talk, from_peer, lines, chunks, out, until);
    let (written, summary) = tokio::join!(writer, conversation);
    match (written, summary.ended.clone()) {
        (Err(e), Ended::Done) => Summary { ended: Ended::Failed(format!("the stream failed: {e}")), ..summary },
        _ => summary,
    }
}

/// The writer: the small records first, then the chunks, until both queues
/// close; then the stream's end.
async fn write_records<W: AsyncWrite + Unpin>(
    mut to_peer: W,
    mut control: mpsc::UnboundedReceiver<Record>,
    mut chunks: mpsc::Receiver<Record>,
) -> std::io::Result<()> {
    loop {
        let record = tokio::select! {
            biased;
            Some(record) = control.recv() => record,
            Some(record) = chunks.recv() => record,
            else => break,
        };
        to_peer.write_all(&record.encode()).await?;
        to_peer.flush().await?;
    }
    to_peer.shutdown().await
}

async fn run<R, W, U>(
    mut talk: Talk,
    mut from_peer: R,
    lines: &mut Lines,
    chunks: mpsc::Sender<Record>,
    out: &mut Output<W>,
    until: U,
) -> Summary
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    U: Future<Output = Ended>,
{
    tokio::pin!(until);
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut input_open = matches!(talk.opts.once, Once::No);
    if let Err(why) = talk.start(out).await {
        return talk.end(Ended::Failed(why));
    }
    let ended = loop {
        if let Some(ended) = talk.finished(input_open) {
            break ended;
        }
        tokio::select! {
            line = lines.recv(), if input_open => match line {
                Some(line) => {
                    if let Some(ended) = talk.act(&line, out).await {
                        break ended;
                    }
                }
                None => input_open = false,
            },
            read = from_peer.read(&mut buf) => match read {
                Ok(0) => break talk.peer_ended(),
                Ok(n) => {
                    decoder.push(&buf[..n]);
                    if let Some(ended) = talk.records(&mut decoder, out).await {
                        break ended;
                    }
                }
                Err(e) => break Ended::Failed(format!("the stream failed: {e}")),
            },
            permit = chunks.reserve(), if talk.sending() => match permit {
                Ok(permit) => match talk.next_chunk().await {
                    Ok(record) => permit.send(record),
                    Err(why) => break Ended::Failed(why),
                },
                Err(_) => break Ended::Failed("the writer ended".into()),
            },
            ended = &mut until => break ended,
        }
    };
    drop(chunks);
    talk.end(ended)
}

/// A file of this side that the peer accepted, as its chunks go.
pub(super) struct Sending {
    pub id: u64,
    pub file: tokio::fs::File,
}

impl Sending {
    /// The next `want` bytes of the file, at most a chunk.
    pub async fn read(&mut self, want: u64) -> Result<Vec<u8>, String> {
        let mut data = vec![0u8; (want as usize).min(MAX_CHUNK)];
        self.file.read_exact(&mut data).await.map_err(|e| format!("a file to send: {e}"))?;
        Ok(data)
    }
}

/// The files of the peer that wait for the user, and those that the user
/// accepted, as their bytes come; this side's offers, and the files that go.
#[derive(Default)]
pub(super) struct Files {
    pub offered: HashMap<u64, (String, u64)>,
    pub writing: HashMap<u64, Incoming>,
    pub ours: HashMap<u64, PathBuf>,
    pub sending: VecDeque<Sending>,
}

/// A session's state, as the loop holds it.
pub(super) type State = Session;
