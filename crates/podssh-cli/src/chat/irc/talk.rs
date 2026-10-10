//! A chat in one IRC channel over a byte stream (T-252): the user's lines go
//! to the channel as messages, and the channel's messages come out, with the
//! IRC session of `podssh_core::irc` doing the protocol. With `echo-message`,
//! a message is delivered once the server echoes it; with no such
//! capability, nothing proves that a message arrived, and podssh says so.

use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;

use podssh_core::irc::{Event, Message, Registered, Session};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::chat::converse::{Ended, Once};
use crate::chat::input::{self, Act};
use crate::chat::lines::Lines;
use crate::chat::output::Output;

/// How often the keepalive is weighed.
const TICK: Duration = Duration::from_secs(1);
/// How long the last lines may take to go once the conversation ended.
const FLUSH: Duration = Duration::from_secs(5);

/// What a run in one channel does.
#[derive(Debug, Clone)]
pub struct IrcOptions {
    pub channel: String,
    pub once: Once,
    /// The user takes each file (`--accept-dir`): the run stays until it is
    /// ended, as a file can come from anyone in the channel.
    pub stays: bool,
}

/// How one connection's conversation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcSummary {
    pub ended: Ended,
    /// The messages that the server never echoed, with `echo-message`.
    pub undelivered: Vec<String>,
    /// Whether this connection got as far as the channel.
    pub joined: bool,
}

/// Talk in `opts.channel` over `stream`, with `session`, which a reconnect
/// keeps (`first` is false then: the burst of a reconnect, and its rejoin).
pub async fn irc_converse<S, W, U>(
    stream: S,
    session: &mut Session,
    first: bool,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: &IrcOptions,
    until: U,
) -> IrcSummary
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    U: Future<Output = Ended>,
{
    let (mut from_server, to_server) = tokio::io::split(stream);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(write_lines(to_server, rx));
    let mut talk = Talk { session, tx, opts, out_of_band: Vec::new(), state: State::new(opts) };
    // A reconnect's burst rejoins the channels that the session remembers.
    talk.state.join_sent =
        !first && talk.session.memory().channels().iter().any(|c| c.eq_ignore_ascii_case(&opts.channel));
    let burst = if first { talk.session.initial_burst() } else { talk.session.reconnect_burst() };
    talk.send_all(burst);
    tokio::pin!(until);
    let mut buf = vec![0u8; 16 * 1024];
    let mut tick = tokio::time::interval(TICK);
    let ended = loop {
        if let Some(ended) = talk.finished(lines) {
            break ended;
        }
        let reading = talk.state.joined && talk.state.input_open;
        tokio::select! {
            ended = &mut until => break ended,
            read = from_server.read(&mut buf) => match read {
                Ok(0) | Err(_) => {
                    if let Some(lost) = talk.session.on_stream_end() {
                        let line = format!("the connection ended inside a line: {lost:?}");
                        out.notice("lost", json!({ "error": line }), line.clone()).await;
                    }
                    break Ended::PeerLeft;
                }
                Ok(n) => {
                    if let Some(ended) = talk.bytes(&buf[..n], out).await {
                        break ended;
                    }
                }
            },
            line = lines.recv(), if reading => match line {
                Some(line) => {
                    if let Some(ended) = talk.act(&line, out).await {
                        break ended;
                    }
                }
                None => talk.state.input_open = false,
            },
            _ = tick.tick() => talk.keepalive(),
        }
    };
    // The user's own end says goodbye; a lost connection cannot.
    if matches!(ended, Ended::Done | Ended::Stopped | Ended::TimedOut) {
        talk.send(&Session::quit("podssh"));
    }
    let undelivered = talk.state.pending.iter().cloned().collect();
    let joined = talk.state.ever_joined;
    drop(talk);
    let _ = tokio::time::timeout(FLUSH, writer).await;
    IrcSummary { ended, undelivered, joined }
}

/// The writer: each line, in order, until the conversation drops its end.
async fn write_lines<W: AsyncWrite + Unpin>(mut to_server: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = rx.recv().await {
        if to_server.write_all(&bytes).await.is_err() || to_server.flush().await.is_err() {
            return;
        }
    }
    let _ = to_server.shutdown().await;
}

/// The conversation's state, apart from the session.
struct State {
    joined: bool,
    ever_joined: bool,
    join_sent: bool,
    input_open: bool,
    /// The messages sent and not echoed yet, with `echo-message`.
    pending: VecDeque<String>,
    /// Whether the server echoes each message, once registration said.
    echo: Option<bool>,
    once_sent: bool,
    last_send: Instant,
    last_recv: Instant,
    received_since_beat: bool,
    generation: u64,
}

impl State {
    fn new(opts: &IrcOptions) -> State {
        let now = Instant::now();
        State {
            joined: false,
            ever_joined: false,
            join_sent: false,
            input_open: matches!(opts.once, Once::No),
            pending: VecDeque::new(),
            echo: None,
            once_sent: false,
            last_send: now,
            last_recv: now,
            received_since_beat: false,
            generation: 0,
        }
    }
}

struct Talk<'a> {
    session: &'a mut Session,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    opts: &'a IrcOptions,
    /// Lines that could not be written as IRC lines, said once.
    out_of_band: Vec<String>,
    state: State,
}

impl Talk<'_> {
    fn send(&mut self, message: &Message) {
        match message.to_wire() {
            Ok(wire) => {
                // The writer gone, the loop learns it from the stream.
                let _ = self.tx.send(wire.into_bytes());
                self.state.last_send = Instant::now();
            }
            Err(e) => self.out_of_band.push(format!("a line was not sent: {e}")),
        }
    }

    fn send_all(&mut self, messages: Vec<Message>) {
        for message in &messages {
            self.send(message);
        }
    }

    /// The end, when it came: the one thing done, or the input ended with
    /// each message echoed.
    fn finished(&self, lines: &Lines) -> Option<Ended> {
        let idle = self.state.pending.is_empty();
        match &self.opts.once {
            Once::Send(_) => (self.state.once_sent && idle).then_some(Ended::Done),
            Once::File(_) => None,
            Once::No => (!self.state.input_open && lines.done() && idle && !self.opts.stays && self.state.joined)
                .then_some(Ended::Done),
        }
    }

    /// The keepalive: a `PING` once this side was quiet for a period.
    fn keepalive(&mut self) {
        let now = Instant::now();
        let since = |t: Instant| now.saturating_duration_since(t).as_millis() as u64;
        let plan = self.session.policy().plan(
            0,
            since(self.state.last_send),
            since(self.state.last_recv),
            self.state.received_since_beat,
        );
        if plan.send_heartbeat {
            if let Some(ping) = self.session.heartbeat(self.state.generation) {
                self.state.generation += 1;
                self.state.received_since_beat = false;
                self.send(&ping);
            }
        }
    }

    /// The server's bytes: what the session answers, what it shows, and the
    /// channel once registration is done.
    async fn bytes<W: AsyncWrite + Unpin>(&mut self, bytes: &[u8], out: &mut Output<W>) -> Option<Ended> {
        self.state.last_recv = Instant::now();
        self.state.received_since_beat = true;
        let (replies, events) = self.session.on_bytes(bytes);
        self.send_all(replies);
        for event in events {
            if let Some(ended) = self.event(event, out).await {
                return Some(ended);
            }
        }
        match self.session.registered() {
            Registered::Refused(why) => {
                return Some(Ended::Refused(format!("the server refused the registration: {why:?}")));
            }
            Registered::Yes if self.state.echo.is_none() => {
                let echo = self.session.negotiation().enabled().iter().any(|c| c == "echo-message");
                self.state.echo = Some(echo);
                if !echo {
                    let line = "this server does not echo messages (no echo-message): podssh cannot prove that a \
                                message arrived";
                    out.notice("no-echo", json!({}), line.to_string()).await;
                }
            }
            _ => {}
        }
        if self.session.registered() == Registered::Yes && !self.state.join_sent {
            self.state.join_sent = true;
            match self.session.send_join(&self.opts.channel, None) {
                Ok(join) => self.send_all(join),
                Err(e) => return Some(Ended::Refused(format!("{}: {e}", self.opts.channel))),
            }
        }
        for why in std::mem::take(&mut self.out_of_band) {
            out.notice("error", json!({ "error": why }), why.clone()).await;
        }
        self.once(out).await;
        None
    }

    /// The one message of `--send`, once the channel is joined.
    async fn once<W: AsyncWrite + Unpin>(&mut self, out: &mut Output<W>) {
        let Once::Send(text) = self.opts.once.clone() else { return };
        if self.state.joined && !self.state.once_sent {
            self.state.once_sent = true;
            self.say(&text, out).await;
        }
    }

    /// One message to the channel.
    async fn say<W: AsyncWrite + Unpin>(&mut self, text: &str, out: &mut Output<W>) {
        match self.session.send_privmsg(&self.opts.channel, text) {
            Ok(message) => {
                self.send(&message);
                if self.state.echo == Some(true) {
                    self.state.pending.push_back(text.to_string());
                }
            }
            Err(e) => {
                let why = format!("not sent: {e}");
                out.notice("error", json!({ "error": why }), why.clone()).await;
            }
        }
    }

    /// A line of the user.
    async fn act<W: AsyncWrite + Unpin>(&mut self, line: &str, out: &mut Output<W>) -> Option<Ended> {
        match input::parse(line) {
            Ok(Act::Nothing) => {}
            Ok(Act::Quit) => return Some(Ended::Done),
            Ok(Act::Say(text)) => self.say(&text, out).await,
            Ok(Act::Offer(_) | Act::Accept { .. } | Act::Decline(_)) => {
                let why = "files over IRC come with the next part of T-252; nothing was sent";
                out.notice("error", json!({ "error": why }), why.to_string()).await;
            }
            Err(why) => out.notice("error", json!({ "error": why }), why.clone()).await,
        }
        None
    }

    /// One event of the session: what the user sees, and the ends that it
    /// brings.
    async fn event<W: AsyncWrite + Unpin>(&mut self, event: Event, out: &mut Output<W>) -> Option<Ended> {
        let ours = |name: &str| name.eq_ignore_ascii_case(&self.opts.channel);
        match event {
            Event::Privmsg { from, target, text } => {
                let to_me = target.eq_ignore_ascii_case(self.session.nick());
                if ours(&target) || to_me {
                    out.said(&from.nick, to_me, &text).await;
                }
            }
            Event::Echo { text, .. } => {
                if let Some(at) = self.state.pending.iter().position(|t| *t == text) {
                    self.state.pending.remove(at);
                    out.notice("delivered", json!({ "text": text }), String::new()).await;
                }
            }
            Event::Joined { channel } if ours(&channel) => {
                self.state.joined = true;
                self.state.ever_joined = true;
                let line = format!("joined {channel} as {}", self.session.nick());
                out.notice("joined", json!({ "channel": channel, "nick": self.session.nick() }), line).await;
            }
            Event::Kicked { channel, by, reason } if ours(&channel) => {
                let why = reason.map(|r| format!(": {r}")).unwrap_or_default();
                return Some(Ended::Refused(format!("{by} removed this client from {channel}{why}")));
            }
            Event::PeerJoined { nick, channel } if ours(&channel) => {
                out.notice("peer-joined", json!({ "nick": nick }), format!("{nick} joined")).await;
            }
            Event::PeerLeft { nick, channel, reason } if ours(&channel) => {
                let why = reason.clone().map(|r| format!(" ({r})")).unwrap_or_default();
                out.notice("peer-left", json!({ "nick": nick, "reason": reason }), format!("{nick} left{why}")).await;
            }
            Event::Numeric { code, text } => {
                if let Some(why) = join_refused(code) {
                    let said = text.map(|t| format!(" ({t})")).unwrap_or_default();
                    return Some(Ended::Refused(format!("{}: {why}{said}", self.opts.channel)));
                }
            }
            Event::Notice { from, text, .. } => {
                out.notice("server-notice", json!({ "from": from.nick, "text": text }), String::new()).await;
            }
            // Before the channel, the server refused this client; after it,
            // the link ends, and a new one is made.
            Event::ServerError(words) => {
                let why = format!("the server closed the link: {words}");
                if !self.state.ever_joined {
                    return Some(Ended::Refused(why));
                }
                out.notice("server-error", json!({ "error": words }), why).await;
            }
            Event::Protocol(why) => out.notice("protocol", json!({ "error": why }), why.clone()).await,
            _ => {}
        }
        None
    }
}

/// The numerics that refuse a `JOIN`, in words.
fn join_refused(code: u16) -> Option<&'static str> {
    Some(match code {
        403 => "no such channel",
        405 => "this client joined too many channels",
        471 => "the channel is full",
        473 => "the channel takes invited users only",
        474 => "this client is banned from the channel",
        475 => "the channel needs a key",
        477 => "the channel takes registered nicks only",
        _ => return None,
    })
}
