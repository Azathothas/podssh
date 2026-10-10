//! The side of `podssh chat` that waits (T-099): the node of the pair NAME,
//! whose every session, once the end-to-end channel let its key in, is a
//! conversation; one at a time, and another peer is told that the chat is
//! busy. While no peer is there, the user's lines wait. The door, the busy
//! answer and the conversations serve the iroh road too (`iroh::listen`).

use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_core::chat::Record;
use podssh_relay::e2e::ends;
use podssh_relay::identity::file::{Key, Place};
use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, E2e, Handler, Layered, NodeConfig, Opening, SessionId, Wire};
use podssh_ws::{ProxyChoice, Trust};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, watch};

use super::args::ChatArgs;
use super::converse::{converse_until, Ended, Options};
use super::lines::Lines;
use super::output::Output;
use super::run::{self, Until, CLOSE_WAIT};
use crate::relay_settings::Refusal;

/// Each direction of the pipe between a session and its conversation.
const PIPE: usize = 256 * 1024;

/// The side that waits, once each check that needs no network passed.
pub(super) struct Ready {
    pub label: String,
    pair: Pair,
    /// Whether the pair came from the store, whose copy goes when the relay
    /// says that the pair was stopped.
    stored: bool,
    trust: Trust,
    key: Key,
    allow: Option<PathBuf>,
}

/// The pins, the pair, and this side's key, loaded or made.
pub(super) fn prepare(label: String, place: &Place, allow: Option<PathBuf>, args: &ChatArgs) -> Result<Ready, Refusal> {
    crate::pins::apply(args.relay_addr.as_deref())?;
    let (pair, stored) = match &args.pair_file {
        Some(file) => (crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false),
        None => (crate::pairs::stored(&label)?, true),
    };
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let key = crate::channel::load_node_key(place)?;
    Ok(Ready { label, pair, stored, trust, key, allow })
}

/// Serve the pair until the run ends; each session is a conversation.
pub(super) async fn run<W: AsyncWrite + Unpin>(
    ready: Ready,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: Until,
) -> i32 {
    let Ready { label, pair, stored, trust, key, allow } = ready;
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "podssh chat: {label}: waiting for the peer as the node of the pair, through {}, one peer at a time; the \
         pair expires {}",
        pair.relay.host,
        crate::pairs::utc(pair.expires_ms)
    );
    let kept = match (&key.path, key.made) {
        (None, _) => "a key for this run only".to_string(),
        (Some(path), true) => format!("a new key, in {}", path.display()),
        (Some(path), false) => format!("in {}", path.display()),
    };
    let _ = writeln!(err, "podssh chat: {label}: key {} ({kept})", key.identity.public());
    let _ = writeln!(err, "podssh chat: {label}: {}", crate::channel::who_may(allow.as_deref()));
    let shown = label.clone();
    let node = ends::Node {
        identity: Arc::new(key.identity),
        admit: crate::channel::admit_of(allow),
        say: Arc::new(move |line: String| eprintln!("podssh chat: {shown}: {line}")),
    };
    let (door, mut peers) = Door::new();
    let layer = crate::layered::settings();
    let rejoin = layer.resume_deadline;
    let handler = Arc::new(Layered::new(E2e::new(door.clone(), node), layer, reverse::layered::NODE_BUDGET));
    let shown = label.clone();
    let say = move |line: String| eprintln!("podssh chat: {shown}: {line}");
    let proxy = ProxyChoice::FromEnvironment;
    let mut config = NodeConfig {
        pair,
        label: stored.then(|| label.clone()),
        trust: &trust,
        proxy: &proxy,
        timeout: crate::pairs::REQUEST_LIMIT,
        // A lost socket is taken again for as long as the layer keeps a
        // session (T-261).
        settings: reverse::Settings { rejoin, ..reverse::Settings::default() },
        repair: None,
        wire: Wire::Tls,
        say: Some(&say),
    };
    let (stop, stopped) = watch::channel(false);
    let (gone_tx, gone) = watch::channel(false);
    let node_part = async {
        let exit = Box::pin(reverse::run(&mut config, handler, flipped(stopped))).await;
        let _ = gone_tx.send(true);
        exit
    };
    let talk_part = async {
        let ended = talk(&label, &mut peers, lines, out, &opts, until, gone, "the pair's road ended").await;
        // No peer from now on; the last one's session gets a while to close.
        peers.close();
        while let Ok(late) = peers.try_recv() {
            busy(late, &label);
        }
        door.closed(CLOSE_WAIT).await;
        let _ = stop.send(true);
        ended
    };
    let (exit, (ended, lost)) = tokio::join!(node_part, talk_part);
    match crate::node::ended(&label, exit) {
        Some((fault, why)) => run::refused(fault.code(), why, lines, out).await,
        None => run::finish(&ended, lost, lines, out).await,
    }
}

/// The conversations, one peer at a time, until the run ends: its end, and
/// how many messages of the last conversation went with no acknowledgement.
/// `gone` flips when the roads ended, which `road` says.
#[allow(clippy::too_many_arguments)]
pub(super) async fn talk<W: AsyncWrite + Unpin>(
    label: &str,
    peers: &mut mpsc::Receiver<DuplexStream>,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: &Options,
    until: Until,
    gone: watch::Receiver<bool>,
    road: &'static str,
) -> (Ended, usize) {
    let road_ended = move || Ended::Failed(road.into());
    loop {
        let stream = tokio::select! {
            stream = peers.recv() => match stream {
                Some(stream) => stream,
                None => return (road_ended(), 0),
            },
            ended = until.wait() => return (ended, 0),
            () = flipped(gone.clone()) => return (road_ended(), 0),
            () = lines.until_quit() => return (Ended::Done, 0),
        };
        let stop = {
            let gone = gone.clone();
            async move {
                tokio::select! {
                    ended = until.wait() => ended,
                    () = flipped(gone) => road_ended(),
                }
            }
        };
        let summary = {
            let conversation = converse_until(stream, lines, out, opts.clone(), stop);
            tokio::pin!(conversation);
            loop {
                tokio::select! {
                    summary = &mut conversation => break summary,
                    Some(other) = peers.recv() => busy(other, label),
                }
            }
        };
        run::undelivered(&summary.undelivered, out).await;
        match summary.ended {
            Ended::PeerLeft if run::goes_on(lines, opts) => {
                if summary.peer.is_some() {
                    out.notice("waiting", json!({}), "the peer left; podssh waits for the next".into()).await;
                }
            }
            ended => return (ended, summary.undelivered.len()),
        }
    }
}

/// Once the flag is up, or its sender is gone.
pub(super) async fn flipped(mut flag: watch::Receiver<bool>) {
    let _ = flag.wait_for(|up| *up).await;
}

/// Another peer, while one talks: told that the chat is busy, then its end.
pub(super) fn busy(mut stream: DuplexStream, label: &str) {
    eprintln!("podssh chat: {label}: another peer came, and was told that the chat is busy");
    tokio::spawn(async move {
        let _ = stream.write_all(&Record::Busy.encode()).await;
        let _ = stream.shutdown().await;
        // Read to its end, so that the channel closes both ways.
        let _ = tokio::time::timeout(CLOSE_WAIT, tokio::io::copy(&mut stream, &mut tokio::io::sink())).await;
    });
}

/// The handler of the side that waits: each session that the channel lets
/// in goes to the conversations as a stream, counted while it is open.
#[derive(Clone)]
pub(super) struct Door {
    peers: mpsc::Sender<DuplexStream>,
    open: Arc<watch::Sender<usize>>,
}

impl Door {
    pub fn new() -> (Door, mpsc::Receiver<DuplexStream>) {
        let (peers, rx) = mpsc::channel(4);
        (Door { peers, open: Arc::new(watch::channel(0).0) }, rx)
    }

    /// Once no session is open, or after `limit`.
    pub async fn closed(&self, limit: Duration) {
        let mut open = self.open.subscribe();
        let _ = tokio::time::timeout(limit, open.wait_for(|n| *n == 0)).await;
    }

    /// A session's stream, its other end handed to the conversations; on
    /// either road.
    pub fn session(&self) -> Opening<Counted> {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (peers, open) = (self.peers.clone(), self.open.clone());
        Box::pin(async move {
            peers.send(theirs).await.map_err(|_| "the chat has ended".to_string())?;
            open.send_modify(|n| *n += 1);
            Ok(Counted { stream: ours, open })
        })
    }
}

impl Handler for Door {
    type Stream = Counted;

    fn open(&self, _: SessionId) -> Opening<Counted> {
        self.session()
    }
}

/// A session's stream, counted while it is open.
pub(super) struct Counted {
    stream: DuplexStream,
    open: Arc<watch::Sender<usize>>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.open.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl AsyncRead for Counted {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
