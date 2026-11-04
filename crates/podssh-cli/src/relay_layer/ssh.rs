//! `podssh ssh` in the resumable layer at podssh's relay role (T-173), as
//! `podssh proxy` takes it (`crate::relay_layer`): where
//! `PODSSH_RELAY_LAYER=yes` asks for it and the first relay host offers it,
//! the first hop's stream is a pipe whose other end the layer carries to the
//! process that holds the session, on a new link after each lost one, as on
//! a node's `cf://` road. Each command that reaches its first hop as `podssh
//! ssh` does takes it the same way; each other case is the contract's
//! `/connect/`, as before, and so is a run of `--no-resume`, whose session
//! ends with its link.
//!
//! The road runs on a thread of its own, with a runtime of its own, from
//! the read of the offer to the session's end: the forward opener's future
//! holds the lines that it says, so no task can take it, and the session
//! goes on while the command's own task runs SSH.

use std::sync::Arc;

use podssh_relay::forward_layer;
use podssh_relay::relay::RelayList;
use podssh_relay::session::client;
use podssh_relay::session::resume::Note;
use podssh_relay::session::{Ask, OsEntropy};
use podssh_ssh::keep::Offer;
use podssh_ssh::notice::Silence;
use podssh_ssh::Log;
use podssh_ws::Trust;
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

use crate::exitmap::sysexits;
use crate::layered::{self, Line};
use crate::ssh::transport::{NotReached, Reached};

/// Each direction of the pipe between the SSH client and the layer.
const PIPE: usize = 256 * 1024;

/// What the road's thread found, for the command's task.
enum Begun {
    /// The layer carries the session: the SSH client's end of its pipe.
    Layer(DuplexStream),
    /// The contract's road, whose line was said.
    Contract,
    /// A refusal that the contract's road would get too, or a handshake
    /// that failed.
    Failed(NotReached),
}

/// What the road takes of the run, owned, for its thread.
struct Road {
    relays: RelayList,
    trust: Trust,
    family: Option<u8>,
    host: String,
    port: u16,
    /// Whether the far end keeps shells (T-158), and its silence (T-302).
    offer: Offer,
    silence: Silence,
    log: Arc<Log>,
    /// `PODSSH_RELAY_LAYER`: asked for, or unset.
    asked_for: super::Asked,
}

/// The first hop `host:port` through the layer at the first host of
/// `relays`, where the run asked for it: `None` for the contract's road;
/// `Some(Err)` for a word of the variable that is neither yes nor no, a
/// refusal that the contract's road would get too, or a handshake that
/// failed.
pub(crate) async fn reach(
    relays: &RelayList,
    trust: &Trust,
    family: Option<u8>,
    (host, port): (&str, u16),
    opts: &podssh_ssh::options::Options,
    log: &Arc<Log>,
) -> Option<Result<Reached, NotReached>> {
    let asked_for = match super::asked_here() {
        Ok(super::Asked::No) => return None,
        Ok(asked_for) => asked_for,
        Err(refusal) => return Some(Err(NotReached { lines: vec![refusal.message], code: refusal.code })),
    };
    // --no-resume (T-612): a session that ends with its link.
    if crate::no_resume::asked() {
        log.verbose("--no-resume: the session ends with its link, so it takes the contract's road, with no layer");
        return None;
    }
    // PODSSH_OFFLINE: the contract's road says it.
    if podssh_relay::open::offline() {
        return None;
    }
    let road = Road {
        relays: relays.clone(),
        trust: trust.clone(),
        family,
        host: host.to_string(),
        port,
        offer: opts.keep.offer.clone(),
        silence: opts.silence.clone(),
        log: log.clone(),
        asked_for,
    };
    let (tell, told) = oneshot::channel();
    let (ended, done) = oneshot::channel();
    let started = std::thread::Builder::new().name("podssh-relay-layer".into()).spawn(move || run(road, tell, ended));
    if let Err(e) = started {
        log.info(&format!("the resumable layer's thread did not start ({e}): {}", super::WITHOUT));
        return None;
    }
    match told.await {
        Ok(Begun::Layer(stream)) => {
            Some(Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: Some(done) }))
        }
        Ok(Begun::Contract) => None,
        Ok(Begun::Failed(not)) => Some(Err(not)),
        // The thread ended before it said anything: the contract's road.
        Err(_) => None,
    }
}

/// The road on its thread, in a runtime of its own; `ended` once the
/// session ended, its `CLOSE` sent and its last line said.
fn run(road: Road, tell: oneshot::Sender<Begun>, ended: oneshot::Sender<()>) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            road.log.info(&format!("the resumable layer could not start its runtime ({e}): {}", super::WITHOUT));
            let _ = tell.send(Begun::Contract);
            return;
        }
    };
    runtime.block_on(carried(road, tell));
    let _ = ended.send(());
}

/// The offer, the first link and its handshake, each told to `tell`; then
/// the session in the layer, until its end.
async fn carried(road: Road, tell: oneshot::Sender<Begun>) {
    let Road { relays, trust, family, host, port, offer, silence, log, asked_for } = road;
    let mut say = |line: String| log.info(&line);
    let Some((dialer, at)) = super::chosen(&relays, &trust, (host.as_str(), port), asked_for, &mut say).await else {
        let _ = tell.send(Begun::Contract);
        return;
    };
    let dialer = dialer.with_family(family);
    let first = match dialer.link(&mut |note: &str| log.info(note)).await {
        Ok(link) => link,
        Err(missed) => {
            let lines = missed.lines(dialer.target());
            let begun = if let Some(line) = super::unserved(&relays, &missed, &at) {
                log.info(&line);
                Begun::Contract
            } else if missed.is_final() {
                let code = missed.failure().map_or(sysexits::EX_UNAVAILABLE, |f| crate::proxy::sysexit(f.last()));
                Begun::Failed(NotReached { lines, code })
            } else {
                let why = lines.first().cloned().unwrap_or_default();
                log.info(&format!("{at}: the resumable layer's first link failed ({why}): {}", super::WITHOUT));
                Begun::Contract
            };
            let _ = tell.send(begun);
            return;
        }
    };
    let settings = layered::ssh_settings().off_the_pair();
    let client = match client::start(first, Ask::New, settings, &mut OsEntropy).await {
        Ok(client) => client,
        Err(e) => {
            let begun = match forward_layer::no_room(&e) {
                // Nothing of the session went: the contract's road carries it.
                Some(words) => {
                    log.info(&super::no_room_line(&at, words));
                    Begun::Contract
                }
                None => {
                    let line = format!("{at}: the resumable layer's handshake failed: {e}");
                    Begun::Failed(NotReached { lines: vec![line], code: sysexits::EX_UNAVAILABLE })
                }
            };
            let _ = tell.send(begun);
            return;
        }
    };
    log.verbose(&format!("{at}: {}", client.found()));
    podssh_ssh::outcome::relay_host(&dialer.relay().host);
    layered::learn(client.found(), &offer);
    let client = layered::heard(client, &silence);
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    // A command that went before it took the stream reads nothing of it.
    if tell.send(Begun::Layer(ssh_end)).is_err() {
        return;
    }
    let note = |note: Note| {
        if layered::folded(&note, Some(&silence)) {
            return;
        }
        match layered::line_of(note) {
            Line::Always(text) => log.info(&format!("{at}: {text}")),
            Line::Verbose(text) => log.verbose(&format!("{at}: {text}")),
        }
    };
    let outcome = forward_layer::carry(&dialer, client, layer_end, note).await;
    if let Some(why) = layered::why_ended(outcome) {
        log.error(&format!("{at}: {why}"));
    }
}
