//! One IAP session as a byte stream (T-351). SSH reads and writes one end of
//! a pipe; a task carries the other end over the WebSocket in IAP's data
//! messages of 16 KiB at most, acknowledges what comes, keeps what went
//! until the server confirms it ([`Flow`]), and after a lost link takes the
//! session up on a new one, as gcloud does: `/v4/reconnect` with the
//! session's id and the bytes received, the server's reconnect success,
//! then the bytes that it did not take, again.
//!
//! The end of SSH's input ends the session as gcloud ends it: what was read
//! goes, then a Close, as IAP's protocol has no half-close; what the server
//! sent before its own Close still reaches SSH, for [`DRAIN`] at most.

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{watch, Notify};

use super::close::{self, fate, Fate};
use super::flow::Flow;
use super::frame::{self, Message, MAX_DATA};
use super::Resume;
use crate::frame as ws;
use crate::session::{close_code_and_reason, RelaySession};
use link::{first, take_up, what, words, First, Unopened};

mod link;

/// How long the first message of a link may take: the probe's 20 s.
pub const FIRST_MESSAGE: Duration = Duration::from_secs(20);
/// New links for one that was lost, before the session ends.
pub const RECONNECTS: u32 = 3;
/// The wait before the first new link, doubled for each next one: gcloud
/// waits 1.5 s first.
pub const RECONNECT_WAIT: Duration = Duration::from_millis(1500);
/// How long received bytes wait for their acknowledgement when nothing
/// else goes up.
pub const ACK_WAIT: Duration = Duration::from_secs(1);
/// How long the server's last bytes may take after the end of SSH's input.
pub const DRAIN: Duration = Duration::from_secs(5);
/// Each direction of the pipe to SSH.
const PIPE: usize = 256 * 1024;

/// A link of the session, on its way.
pub type Dialing<S, E> = Pin<Box<dyn Future<Output = Result<RelaySession<S>, E>> + Send>>;
/// Opens a link of the session: the first with `None`, then each that takes
/// it up. Each call takes a token of its own, as one may have expired.
pub type Dial<S, E> = Arc<dyn Fn(Option<Resume>) -> Dialing<S, E> + Send + Sync>;
/// Where the task says what it does.
pub type Say = Arc<dyn Fn(Line) + Send + Sync>;

/// A line of the task's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// For the user: a lost link, and the new one.
    Info(String),
    /// For `-v`.
    Verbose(String),
}

/// Why no session opened.
#[derive(Debug)]
pub enum NotOpen<E> {
    /// The link did not open: the dial's own reason.
    Dial(E),
    /// The server closed the link before the session: its code and reason.
    Closed { code: Option<u16>, reason: String },
    /// No message of IAP within the wait.
    Silent(Duration),
    /// A message out of the protocol, or a link that broke.
    Fault(String),
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The stream's own end: SSH's, or the far end's.
    Normal,
    /// A Close of the server that ends the session: its code and reason.
    Closed { code: Option<u16>, reason: String },
    /// A lost link that no new one took up: why.
    Lost(String),
    /// A fault of the protocol: why.
    Fault(String),
}

/// How the session ended, once it did. The task sets it before the end of
/// the stream reaches SSH.
#[derive(Clone)]
pub struct Carried(watch::Receiver<Option<Ended>>);

impl Carried {
    /// The end, when the session has ended.
    pub fn get(&self) -> Option<Ended> {
        self.0.borrow().clone()
    }

    /// Until the session ends.
    pub async fn ended(&mut self) -> Ended {
        let got = self.0.wait_for(Option::is_some).await.map(|end| (*end).clone());
        match got {
            Ok(Some(end)) => end,
            _ => self.get().unwrap_or_else(|| Ended::Lost("the session's task ended before it said why".into())),
        }
    }
}

/// The session on its first link: the link, then IAP's connect success
/// within [`FIRST_MESSAGE`]; then a task carries it, and the stream is SSH's.
pub async fn open<S, E>(dial: Dial<S, E>, say: Say) -> Result<(DuplexStream, Carried), NotOpen<E>>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Display + Send + 'static,
{
    open_within(dial, say, FIRST_MESSAGE).await
}

/// [`open`], with `wait` for the first message, so that a test waits less.
pub(crate) async fn open_within<S, E>(
    dial: Dial<S, E>,
    say: Say,
    wait: Duration,
) -> Result<(DuplexStream, Carried), NotOpen<E>>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Display + Send + 'static,
{
    let link = dial(None).await.map_err(NotOpen::Dial)?;
    let sid = match first(&link, true, wait).await {
        Ok(First::Sid(sid)) => sid,
        Ok(First::Took(_)) => return Err(NotOpen::Fault("IAP answered a connect as a reconnect".into())),
        Err(Unopened::Closed { code, reason }) => return Err(NotOpen::Closed { code, reason }),
        Err(Unopened::Silent) => return Err(NotOpen::Silent(wait)),
        Err(Unopened::Fault(why)) => return Err(NotOpen::Fault(why)),
    };
    say(Line::Verbose(format!("IAP opened the session (an id of {} bytes)", sid.len())));
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (tell, carried) = watch::channel(None);
    tokio::spawn(run(link, sid, dial, theirs, say, tell, wait));
    Ok((ours, Carried(carried)))
}

/// The flow, also after a task that held it panicked: its counts stay true.
fn lock(flow: &Mutex<Flow>) -> MutexGuard<'_, Flow> {
    flow.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How one link's carriage ended.
enum Turn {
    /// SSH's input ended.
    SshDone,
    /// SSH took no more.
    SshGone,
    /// The server closed the link.
    Closed { code: Option<u16>, reason: String },
    /// The link broke.
    Broken(String),
    /// The server broke the protocol.
    Fault(String),
}

/// The session, a link after another, until it ends; then its end is told,
/// and SSH sees the end of its stream.
async fn run<S, E>(
    first_link: RelaySession<S>,
    sid: Vec<u8>,
    dial: Dial<S, E>,
    pipe: DuplexStream,
    say: Say,
    tell: watch::Sender<Option<Ended>>,
    wait: Duration,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Display + Send + 'static,
{
    let (mut from_ssh, mut to_ssh) = tokio::io::split(pipe);
    let flow = Mutex::new(Flow::new());
    let mut link = first_link;
    let ended = loop {
        let lost = match carry(&link, &mut from_ssh, &mut to_ssh, &flow).await {
            Turn::SshDone => break finish(&link, &mut to_ssh, &flow).await,
            Turn::SshGone => {
                let _ = link.send_close(close::NORMAL, "").await;
                break Ended::Normal;
            }
            Turn::Closed { code, reason } => match fate(code) {
                Fate::End => break Ended::Normal,
                Fate::Fail(_) => break Ended::Closed { code, reason },
                Fate::Reauthenticate | Fate::Resume => words(code, &reason),
            },
            Turn::Broken(why) => why,
            Turn::Fault(why) => {
                let _ = link.send_close(1002, "").await;
                break Ended::Fault(why);
            }
        };
        say(Line::Info(format!("the link to IAP was lost ({lost}); a new one takes the session up")));
        match take_up(&dial, &sid, &flow, &say, wait).await {
            Ok(new) => {
                link = new;
                say(Line::Info("IAP took the session up on a new link".into()));
            }
            Err(end) => break end,
        }
    };
    tell.send_replace(Some(ended));
    let _ = to_ssh.shutdown().await;
}

/// Both directions on `link`, until one ends.
async fn carry<S>(
    link: &RelaySession<S>,
    from_ssh: &mut ReadHalf<DuplexStream>,
    to_ssh: &mut WriteHalf<DuplexStream>,
    flow: &Mutex<Flow>,
) -> Turn
where
    S: AsyncRead + AsyncWrite,
{
    let due = Notify::new();
    tokio::select! {
        turn = up(link, from_ssh, flow, &due) => turn,
        turn = down(link, to_ssh, flow, &due) => turn,
    }
}

/// SSH's bytes up, in data messages; an acknowledgement goes when one is
/// due, before data when bytes came since the last, as IAP Desktop sends
/// it, and after [`ACK_WAIT`] with nothing to send, as gcloud does.
async fn up<S>(link: &RelaySession<S>, from_ssh: &mut ReadHalf<DuplexStream>, flow: &Mutex<Flow>, due: &Notify) -> Turn
where
    S: AsyncRead + AsyncWrite,
{
    let mut buf = vec![0u8; MAX_DATA];
    loop {
        let event = tokio::select! {
            read = from_ssh.read(&mut buf) => Up::Read(read),
            () = due.notified() => Up::Ack,
            () = tokio::time::sleep(ACK_WAIT) => Up::Ack,
        };
        let n = match event {
            Up::Read(Ok(0) | Err(_)) => return Turn::SshDone,
            Up::Read(Ok(n)) => n,
            Up::Ack => {
                if let Err(why) = send_ack(link, flow).await {
                    return Turn::Broken(why);
                }
                continue;
            }
        };
        let chunk = &buf[..n];
        let message = match frame::data(chunk) {
            Ok(message) => message,
            Err(e) => return Turn::Fault(e.to_string()),
        };
        // Kept before anything goes: the server's acknowledgement can come
        // first, and a link that breaks on the acknowledgement before them
        // must not lose bytes that SSH already gave.
        lock(flow).sending(chunk);
        if let Err(why) = send_ack(link, flow).await {
            return Turn::Broken(why);
        }
        if let Err(e) = link.send_binary(&message).await {
            return Turn::Broken(e.to_string());
        }
    }
}

/// What woke the sender: SSH's bytes, or an acknowledgement to send.
enum Up {
    Read(std::io::Result<usize>),
    Ack,
}

/// The acknowledgement of the bytes that came since the last one, if any.
async fn send_ack<S>(link: &RelaySession<S>, flow: &Mutex<Flow>) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite,
{
    let Some(received) = lock(flow).ack() else { return Ok(()) };
    link.send_binary(&frame::ack(received)).await.map_err(|e| e.to_string())
}

/// The server's messages: data to SSH, acknowledgements to the flow.
async fn down<S>(link: &RelaySession<S>, to_ssh: &mut WriteHalf<DuplexStream>, flow: &Mutex<Flow>, due: &Notify) -> Turn
where
    S: AsyncRead + AsyncWrite,
{
    loop {
        let f = match link.read_frame().await {
            Ok(f) => f,
            Err(e) => return Turn::Broken(e.to_string()),
        };
        match f.opcode {
            ws::OPCODE_BINARY => {}
            ws::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                return Turn::Closed { code, reason };
            }
            other => return Turn::Fault(format!("IAP sent a WebSocket message of opcode {other:#x}")),
        }
        match frame::decode(&f.payload) {
            Ok(Message::Data(data)) => {
                if !deliver(to_ssh, &data, flow).await {
                    return Turn::SshGone;
                }
                let due_now = lock(flow).ack_due();
                if due_now {
                    due.notify_one();
                }
            }
            Ok(Message::Ack(n)) => {
                let confirmed = lock(flow).confirm(n);
                if let Err(e) = confirmed {
                    return Turn::Fault(e.to_string());
                }
            }
            Ok(Message::Unknown(_) | Message::LongClose { .. }) => {}
            Ok(other) => return Turn::Fault(format!("IAP sent {} on an open session", what(&other))),
            Err(e) => return Turn::Fault(e.to_string()),
        }
    }
}

/// `data` to SSH, each part counted as it goes: a new link resumes at what
/// SSH took, so a write cut short counts what it wrote. False when SSH
/// takes no more.
async fn deliver(to_ssh: &mut WriteHalf<DuplexStream>, data: &[u8], flow: &Mutex<Flow>) -> bool {
    let mut at = 0;
    while at < data.len() {
        match to_ssh.write(&data[at..]).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                at += n;
                lock(flow).delivered(n);
            }
        }
    }
    true
}

/// SSH's input ended, and each byte of it went: an acknowledgement, a
/// Close, and what the server sent before its own Close goes to SSH, for
/// [`DRAIN`] at most.
async fn finish<S>(link: &RelaySession<S>, to_ssh: &mut WriteHalf<DuplexStream>, flow: &Mutex<Flow>) -> Ended
where
    S: AsyncRead + AsyncWrite,
{
    let _ = send_ack(link, flow).await;
    let _ = link.send_close(close::NORMAL, "").await;
    let drain = async {
        loop {
            match link.read_frame().await {
                Ok(f) if f.opcode == ws::OPCODE_BINARY => {
                    if let Ok(Message::Data(data)) = frame::decode(&f.payload) {
                        if !deliver(to_ssh, &data, flow).await {
                            return;
                        }
                    }
                }
                Ok(f) if f.opcode == ws::OPCODE_CLOSE => return,
                Ok(_) => {}
                Err(_) => return,
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN, drain).await;
    Ended::Normal
}

#[cfg(test)]
mod tests;
