//! UDP through a node (T-168): `udp:node:NAME` is the session to the node
//! of the pair under NAME, whose TARGET is `udp:HOST:PORT`, with each
//! datagram after its 16-bit length in the session's bytes
//! (`podssh_relay::udp`). Nothing on this host sends UDP, and nothing binds.
//!
//! The other side gives and takes the same framing: stdin and stdout, a
//! descriptor, a socket. A program of `exec:` beside it gets one end of an
//! AF_UNIX `SOCK_DGRAM` socketpair as its stdin and stdout on Unix, which
//! needs no bind: each datagram that it sends is one at the target, and
//! each reply one that it receives. Where that socketpair is refused, and
//! on Windows, which has none, its stdin and stdout carry the framing.
//!
//! The node's session has no half-close: its layer ends the session at the
//! end of input. A reply to the last datagram may still be on its way, so
//! at the end of this side's input the session stays until no datagram came
//! back for [`REPLY_WAIT`]. A datagram socket has no end of input either:
//! when the other side ends, a program learns nothing from its socket, so
//! it gets [`CHILD_WAIT`] to exit, then SIGTERM.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use podssh_relay::udp::{framed, Frames};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::local::Unopened;
use super::pump::{End, Ending, Reader, Verdict, Writer};
use crate::exit_codes::EXIT_SOFTWARE;
use crate::exitmap::sysexits::EX_DATAERR;
use crate::ssh::args::SshArgs;

/// Each direction of the pipe between the pump and the session, or the
/// program's socket.
const PIPE: usize = 256 * 1024;
/// Each read of the node's bytes.
const CHUNK: usize = 32 * 1024;
/// Each receive from the program's socket: one byte more than the longest
/// datagram of UDP, so that a longer one shows, and is dropped.
#[cfg(unix)]
const RECEIVE: usize = 64 * 1024;
/// How long the session waits for a reply after this side's input ended,
/// from the last bytes that came: as long as a DNS client waits.
pub const REPLY_WAIT: Duration = Duration::from_secs(5);
/// How long a program of datagrams may run after the other side ended,
/// before SIGTERM; and after SIGTERM, before SIGKILL.
pub const CHILD_WAIT: Duration = Duration::from_secs(10);

/// The session to the node of `label`, for datagrams: the end, or the exit
/// code once `say` has the lines.
pub async fn open_node(label: &str, args: &SshArgs, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    let End { read, write, child, last_word, ending } = super::node::open(label, args, say).await?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (done, stop) = oneshot::channel();
    let task = tokio::spawn(carry(theirs, read, write, stop, format!("udp:node:{label}")));
    let (read, write) = tokio::io::split(ours);
    let ending = Bridged { task, done, inner: ending };
    Ok(End { read: Box::new(read), write: Box::new(write), child, last_word, ending: Some(Box::new(ending)) })
}

/// The bytes between the pump and the node's session. This side's are read
/// as datagrams, so that a stream that is not the framing is refused here,
/// with its reason; the node's pass as they come. After this side's input
/// ended, the session lasts until no reply came for [`REPLY_WAIT`], or until
/// the pump is done (`stop`). The verdict: a stream that is not the
/// framing (65).
async fn carry(
    pump: DuplexStream,
    mut from_node: Reader,
    mut to_node: Writer,
    mut stop: oneshot::Receiver<()>,
    shown: String,
) -> Verdict {
    let (from_pump, mut to_pump) = tokio::io::split(pump);
    let mut frames = Frames::new(from_pump);
    let mut buf = vec![0u8; CHUNK];
    // Whether this side still sends; once it ended, the wait for replies.
    let mut sending = true;
    let wait = tokio::time::sleep(REPLY_WAIT);
    tokio::pin!(wait);
    let verdict = loop {
        tokio::select! {
            next = frames.recv(), if sending => match next {
                Ok(Some(datagram)) => {
                    let Some(bytes) = framed(&datagram) else { continue };
                    if to_node.write_all(&bytes).await.is_err() || to_node.flush().await.is_err() {
                        // The session ended: its ending says why.
                        break None;
                    }
                }
                Ok(None) => {
                    sending = false;
                    wait.as_mut().reset(Instant::now() + REPLY_WAIT);
                }
                Err(e) => break Some((EX_DATAERR, vec![format!("{shown}: {e}")])),
            },
            got = from_node.read(&mut buf) => match got {
                Ok(0) | Err(_) => {
                    let _ = to_pump.shutdown().await;
                    break None;
                }
                Ok(n) => {
                    if to_pump.write_all(&buf[..n]).await.is_err() {
                        break None;
                    }
                    if !sending {
                        wait.as_mut().reset(Instant::now() + REPLY_WAIT);
                    }
                }
            },
            () = &mut wait, if !sending => break None,
            _ = &mut stop => break None,
        }
    };
    // The node's side gets the end of its input, and its layer ends the
    // session.
    let _ = to_node.shutdown().await;
    verdict
}

/// The bridge and the node's session under it, judged when the pump is
/// done.
struct Bridged {
    task: JoinHandle<Verdict>,
    done: oneshot::Sender<()>,
    inner: Option<Box<dyn Ending>>,
}

impl Ending for Bridged {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        let Bridged { task, done, inner } = *self;
        Box::pin(async move {
            // Nobody reads a reply now: the session ends at once.
            let _ = done.send(());
            let bridged = match task.await {
                Ok(verdict) => verdict,
                Err(e) => Some((EXIT_SOFTWARE, vec![format!("the task of the datagrams failed: {e}")])),
            };
            let session = match inner {
                Some(inner) => inner.finish().await,
                None => None,
            };
            // A stream that is not the framing says more than the end of
            // the session that it caused.
            bridged.or(session)
        })
    }
}

/// `exec:CMD` beside `udp:node:`: on Unix, the program's stdin and stdout
/// are one end of an AF_UNIX datagram socketpair. Where that is refused,
/// the stream of `exec:`, which carries the framing, and one line says so.
#[cfg(unix)]
pub fn exec(words: &[String], say: &mut dyn FnMut(&str)) -> Result<End, Unopened> {
    use std::os::fd::OwnedFd;
    use std::process::Stdio;

    let (ours, theirs) = match std::os::unix::net::UnixDatagram::pair() {
        Ok(pair) => pair,
        Err(e) => {
            say(&format!(
                "exec:{}: no datagram socketpair here ({e}): its stdin and stdout carry each datagram after its \
                 16-bit length",
                words[0]
            ));
            return super::local::exec(words, &super::local::socketpair);
        }
    };
    let failed =
        |e: std::io::Error| Unopened { code: 126, why: format!("exec:{}: a datagram socketpair: {e}", words[0]) };
    let theirs_out = theirs.try_clone().map_err(failed)?;
    let mut cmd = tokio::process::Command::new(&words[0]);
    cmd.args(&words[1..]).stderr(Stdio::inherit());
    cmd.stdin(Stdio::from(OwnedFd::from(theirs))).stdout(Stdio::from(OwnedFd::from(theirs_out)));
    let child = cmd.spawn().map_err(|e| super::local::not_started(&words[0], e))?;
    // The program's ends stay only in the program.
    drop(cmd);
    ours.set_nonblocking(true).map_err(failed)?;
    let ours = tokio::net::UnixDatagram::from_std(ours).map_err(failed)?;
    let (stream, theirs) = tokio::io::duplex(PIPE);
    let task = tokio::spawn(datagrams(ours, theirs, child, words[0].clone()));
    let (read, write) = tokio::io::split(stream);
    // Its output is its last word: once the program exited, nobody reads a
    // reply.
    let ending = Some(Box::new(Exited { task }) as Box<dyn Ending>);
    Ok(End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending })
}

/// `exec:CMD` beside `udp:node:` where there is no datagram socketpair
/// (Windows): the stream of `exec:`, which carries the framing.
#[cfg(not(unix))]
pub fn exec(words: &[String], _say: &mut dyn FnMut(&str)) -> Result<End, Unopened> {
    super::local::exec(words, &super::local::socketpair)
}

/// The program's datagrams into the pump, each after its length, and the
/// pump's to the program, until it exits: its exit code, as a shell gives
/// it. What it sent before it exited still goes.
#[cfg(unix)]
async fn datagrams(
    socket: tokio::net::UnixDatagram,
    pump: DuplexStream,
    mut child: tokio::process::Child,
    program: String,
) -> i32 {
    let (from_pump, mut to_pump) = tokio::io::split(pump);
    let mut frames = Frames::new(from_pump);
    let mut buf = vec![0u8; RECEIVE];
    let mut dropped = 0u64;
    let exited = loop {
        tokio::select! {
            got = socket.recv(&mut buf) => match got {
                Ok(n) => {
                    if !into_pump(&buf[..n], &mut to_pump, &mut dropped).await {
                        break None;
                    }
                }
                Err(_) => break None,
            },
            next = frames.recv() => match next {
                Ok(Some(datagram)) => {
                    // A program that closed its socket takes no more.
                    if socket.send(&datagram).await.is_err() {
                        break None;
                    }
                }
                // The other side ended, or its bytes are not the framing.
                Ok(None) | Err(_) => break None,
            },
            status = child.wait() => break Some(status),
        }
    };
    let status = match exited {
        Some(status) => {
            while let Ok(n) = socket.try_recv(&mut buf) {
                if !into_pump(&buf[..n], &mut to_pump, &mut dropped).await {
                    break;
                }
            }
            let _ = to_pump.shutdown().await;
            status
        }
        None => {
            drop((socket, to_pump, frames));
            ended(&mut child).await
        }
    };
    if dropped > 0 {
        let most = podssh_relay::udp::MAX_DATAGRAM;
        podssh_ssh::err_line!("podssh pipe: exec:{program}: {dropped} datagrams over {most} bytes were dropped");
    }
    match status {
        Ok(status) => super::local::code_of(status),
        Err(_) => EXIT_SOFTWARE,
    }
}

/// One datagram of the program into the pump, after its length: `false`
/// when nobody reads it any more. One too long for UDP is counted, and
/// dropped.
#[cfg(unix)]
async fn into_pump(datagram: &[u8], to: &mut tokio::io::WriteHalf<DuplexStream>, dropped: &mut u64) -> bool {
    match framed(datagram) {
        Some(bytes) => to.write_all(&bytes).await.is_ok(),
        None => {
            *dropped += 1;
            true
        }
    }
}

/// The exit of a program that the other side's end did not reach:
/// [`CHILD_WAIT`], then SIGTERM, then [`CHILD_WAIT`], then SIGKILL.
#[cfg(unix)]
async fn ended(child: &mut tokio::process::Child) -> std::io::Result<std::process::ExitStatus> {
    if let Ok(status) = tokio::time::timeout(CHILD_WAIT, child.wait()).await {
        return status;
    }
    if let Some(pid) = child.id() {
        // SAFETY: kill only sends a signal, to the program that this end
        // started and has not waited for, so its pid is still its own.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    if let Ok(status) = tokio::time::timeout(CHILD_WAIT, child.wait()).await {
        return status;
    }
    let _ = child.start_kill();
    child.wait().await
}

/// The program's exit code, once its datagrams are done: one that is not 0
/// is the pipe's, with no line of its own, as a road's failure is.
#[cfg(unix)]
struct Exited {
    task: JoinHandle<i32>,
}

#[cfg(unix)]
impl Ending for Exited {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        let Exited { task } = *self;
        Box::pin(async move {
            match task.await {
                Ok(0) => None,
                Ok(code) => Some((code, Vec::new())),
                Err(e) => Some((EXIT_SOFTWARE, vec![format!("the task of the program's datagrams failed: {e}")])),
            }
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The program's datagrams come into the pump each after its length,
    /// and the pump's reach it whole; at its exit, its status, and the end
    /// of its output.
    #[tokio::test]
    async fn a_program_sends_and_takes_whole_datagrams_and_its_status_comes_back() {
        // `sh` reads one datagram from its socket and sends it back, as
        // `head -c` would cut a stream: a datagram socket gives one whole
        // datagram to each read.
        let words: Vec<String> =
            ["sh", "-c", "dd bs=65536 count=1 2>/dev/null; exit 3"].iter().map(|w| w.to_string()).collect();
        let mut say = |_: &str| {};
        let end = exec(&words, &mut say).expect("sh starts");
        let End { mut read, mut write, ending, .. } = end;
        write.write_all(&framed(b"first datagram").unwrap()).await.unwrap();
        write.write_all(&framed(b"second").unwrap()).await.unwrap();
        let mut frames = Frames::new(&mut read);
        let echoed = tokio::time::timeout(Duration::from_secs(10), frames.recv()).await.expect("an answer");
        assert_eq!(echoed.unwrap(), Some(b"first datagram".to_vec()), "one read is one whole datagram");
        // Then the end of its output, at its exit.
        let end = tokio::time::timeout(Duration::from_secs(10), frames.recv()).await.expect("the end");
        assert_eq!(end.unwrap(), None);
        let verdict = ending.expect("an ending").finish().await;
        assert_eq!(verdict, Some((3, Vec::new())));
    }
}
