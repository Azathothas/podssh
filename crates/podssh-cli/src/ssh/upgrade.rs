//! `podssh ssh --upgrade DEST` (T-167): log in over the forward road, or
//! `--direct`, as each run does; then, when a podssh answers on the server,
//! start a temporary node there in that session (`podssh node --temporary
//! KEY`, `node_temp`), whose one line comes back in the SSH channel,
//! encrypted: the operator's part of a pair that no file keeps, and the
//! node's key. The client opens the resumable layer to that node, logs in
//! again through it with DEST's host key, and closes the first connection
//! once the second has logged in. When no podssh answers, the node gives no
//! line, or it offers no layer, the session stays on the first connection,
//! with one note. Nothing is copied to the server.

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::Identity;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Wire};
use podssh_relay::session::{client, Ask as LayerAsk, OsEntropy};
use podssh_ssh::exec::{self, Captured, NoLine};
use podssh_ssh::options::Options;
use podssh_ssh::russh::client::Msg;
use podssh_ssh::russh::Channel;
use podssh_ssh::{Connection, Log, RelayStatus, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};

use super::args::SshArgs;
use super::resolve::{Env, Resolved, Transport};
use crate::channel::{Expect, Operator};
use crate::layered::{Begin, Line};
use crate::relay_settings::Refusal;
use crate::upgrade_line::{self, Offer};

/// How long `podssh --version` may take on the server.
const PROBE_LIMIT: Duration = Duration::from_secs(10);
/// How long the temporary node may take to give its line: it checks sshd,
/// makes a pair, and waits for the relay to take its sessions.
const LINE_LIMIT: Duration = Duration::from_secs(60);
/// What the server's commands may print that is read.
const CAP: usize = 16 * 1024;
/// Each direction of the pipes between the SSH client, the layer and the leg.
const PIPE: usize = 256 * 1024;
/// How long the first connection may take to close.
const CLOSE_LIMIT: Duration = Duration::from_secs(5);

/// What the move needs from the command line.
#[derive(Debug, Clone)]
pub struct Upgrade {
    /// This client's key file for the channel to the node: `--client-key`.
    pub client_key: Option<String>,
    /// The trust store for the relay of the node's pair.
    pub trust: Trust,
}

/// `--upgrade`, checked: a standard sshd on the forward road or `--direct`,
/// and nothing that two connections would each ask for.
pub(super) fn check(args: &SshArgs, env: &Env, resolved: &mut Resolved) -> Result<(), Refusal> {
    if !args.upgrade {
        return Ok(());
    }
    let why = if !matches!(resolved.transport, Transport::Relay { .. } | Transport::Direct) {
        Some("--upgrade starts from an sshd, on the forward road or --direct; node:// and iroh: are podssh ends")
    } else if args.persist {
        Some("--upgrade and --persist each keep a session across a lost link: give one")
    } else if !resolved.options.remote_forwards.is_empty() {
        Some("--upgrade carries no -R or RemoteForward yet: each would be asked on two connections")
    } else if resolved.control.command.is_some() {
        Some("-O asks a control master, and --upgrade makes none")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(why.into());
    }
    if resolved.control.path.take().is_some() {
        resolved.notes.push("--upgrade makes connections of its own: ControlPath has no effect".into());
    }
    let trust = match super::resolve::ca_file(args, env) {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    resolved.upgrade = Some(Upgrade { client_key: args.client_key.clone().or_else(|| args.iroh_key.clone()), trust });
    Ok(())
}

/// The run of `--upgrade`; its exit code.
pub(super) async fn run(resolved: &Resolved, upgrade: &Upgrade, log: Arc<Log>) -> i32 {
    let mut opts = resolved.options.clone();
    // The login through the node asks nothing that the first one answered
    // (T-025).
    opts.remembered.get_or_insert_with(Default::default);
    let host = podssh_ws::dial::authority(&opts.destination.host, opts.destination.port);
    let reached = match super::transport::reach(resolved, &log).await {
        Ok(reached) => reached,
        Err(failure) => {
            for line in &failure.lines {
                log.error(line);
            }
            let leg = if matches!(resolved.transport, Transport::Relay { .. }) { "relay" } else { "connect" };
            podssh_ssh::outcome::failure_is(leg);
            return EXIT_FAILURE;
        }
    };
    let relay = reached.relay;
    let handles = match podssh_ssh::upgrade::login(reached.stream, &opts, relay.as_ref(), &log).await {
        Ok(handles) => handles,
        Err(lines) => {
            for line in &lines {
                log.error(line);
            }
            return EXIT_FAILURE;
        }
    };
    let found = match handles.last() {
        Some(handle) => offer(handle, upgrade.client_key.as_deref(), &host, &log).await,
        None => Err("no connection to probe".into()),
    };
    let (offer, kept, me) = match found {
        Ok(found) => found,
        Err(why) => return stay(handles, &opts, relay, log, &host, why).await,
    };
    let road = Road { handles, opts: &opts, relay, trust: &upgrade.trust, host: &host };
    Box::pin(through(offer, kept, me, road, log)).await
}

/// What a temporary node offers: its line, the command's channel, kept open
/// while the node needs it, and this client's key, which the node lets in.
type Found = (Offer, Channel<Msg>, Arc<Identity>);

/// A podssh on the server, by its answer to `podssh --version`; then this
/// client's key (`client_key`, else the cache's), and the line of the
/// temporary node that the server's podssh starts for it; else why not.
async fn offer(handle: &Connection, client_key: Option<&str>, host: &str, log: &Log) -> Result<Found, String> {
    // A line `podssh VERSION`: a login's own lines may come before it.
    let answers = |out: &Captured| out.stdout.split(|b| *b == b'\n').any(|line| line.starts_with(b"podssh "));
    match exec::capture(handle, "podssh --version", PROBE_LIMIT, CAP).await {
        Ok(out) if out.status == Some(0) && answers(&out) => {
            log.verbose(&format!("{host}: a podssh answers there; it starts a temporary node"));
        }
        Ok(out) => return Err(format!("no podssh answers there (podssh --version: {})", said(&out))),
        Err(e) => return Err(format!("no podssh answers there (podssh --version: {e})")),
    }
    let say = |line: String| log.info(&format!("{host}: {line}"));
    let me = crate::channel::client_identity(client_key, &say)?;
    let key = exec::shell_word(&me.public().fingerprint()).unwrap_or_default();
    let command = format!("podssh node --temporary {key}");
    match exec::first_line(handle, &command, upgrade_line::MARK, LINE_LIMIT, CAP).await {
        Ok((rest, channel)) => match upgrade_line::read(&rest) {
            Ok(offer) => Ok((offer, channel, me)),
            Err(why) => Err(format!("its temporary node gave an offer that podssh cannot read: {why}")),
        },
        Err(NoLine::Ended(out)) => Err(format!("its podssh started no temporary node ({})", said(&out))),
        Err(NoLine::Failed(e)) => Err(format!("its podssh started no temporary node: {e}")),
    }
}

/// A command's end in a few words: its status, and its last line of error,
/// which says why.
fn said(out: &Captured) -> String {
    let status = out.status.map_or_else(|| "no exit status".to_string(), |s| format!("exit {s}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    match stderr.lines().rev().map(podssh_ws::text::one_line).find(|l| !l.is_empty()) {
        Some(line) => format!("{status}: {line}"),
        None => status,
    }
}

/// The first connection, and what a session on it needs.
struct Road<'a> {
    handles: Vec<Connection>,
    opts: &'a Options,
    relay: Option<RelayStatus>,
    trust: &'a Trust,
    host: &'a str,
}

/// The session through the temporary node: the leg, the layer's greeting,
/// then the login with DEST's host key. The first connection stays open
/// until that login is done, so that a failure before it leaves the session
/// there; and for the whole session when the node could not leave its own.
async fn through(offer: Offer, node: Channel<Msg>, me: Arc<Identity>, road: Road<'_>, log: Arc<Log>) -> i32 {
    let Road { handles, opts, relay, trust, host } = road;
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &offer.relay,
        name: &offer.name,
        connect_token: offer.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    let (link_end, leg_end) = tokio::io::duplex(PIPE);
    let leg = match operator::start(&config, leg_end).await {
        Ok(leg) => leg,
        Err(e) => {
            let why = format!("its temporary node could not be reached: {e}");
            return stay(handles, opts, relay, log, host, why).await;
        }
    };
    // The greeting first: a node with no layer never gets OPEN, and never
    // dials sshd for this session.
    let greeted = match client::greeted(link_end).await {
        Ok(greeted) if greeted.layer() => greeted,
        Ok(_) => {
            let why = "its podssh offers no resumable layer: the node's greeting does not name it".to_string();
            return stay(handles, opts, relay, log, host, why).await;
        }
        Err(e) => return stay(handles, opts, relay, log, host, format!("its temporary node did not greet: {e}")).await,
    };
    let started = match greeted.start(LayerAsk::New, crate::layered::settings(), &mut OsEntropy).await {
        Ok(started) => started,
        Err(e) => {
            let why = format!("the layer's handshake with its temporary node failed: {e}");
            return stay(handles, opts, relay, log, host, why).await;
        }
    };
    log.verbose(&format!("{host}: the temporary node took the session: {}", started.found()));
    if !offer.detached {
        log.verbose(&format!("{host}: its podssh cannot leave its SSH session: the first connection stays open"));
    }
    // SSH to DEST's sshd, which the node dials: no -J, and the host key
    // under DEST's own name, so known_hosts needs no change.
    let mut via = opts.clone();
    via.jump.clear();
    via.jump_options.clear();
    let channel = Some(Operator { identity: me, expect: Expect::Named(offer.node_key.clone()), route: None });
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{host}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{host}: {text}")),
    };
    let pin_say = {
        let (log, host) = (log.clone(), host.to_string());
        move |line: String| log.info(&format!("{host}: {line}"))
    };
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    podssh_ssh::upgrade::begin();
    let (expires, detached) = (Some(offer.expires_ms), offer.detached);
    let mut first = Some(handles);
    let (outcome, carried) = {
        let session = podssh_ssh::run::run_outcome(ssh_end, &via, None, log.clone());
        let begin = Begin::Started(Box::new(started));
        // The far end's silence, for a notice (T-302).
        let shell = Some(crate::layered::Shell { offer: &via.keep.offer, silence: &via.silence });
        let layer =
            crate::layered::carry_keeping(&config, begin, leg, layer_end, expires, &say, channel, pin_say, shell);
        // On the heap: the two futures are large, and Windows gives the main
        // thread 1 MiB of stack.
        let mut both = Box::pin(async { tokio::join!(session, layer) });
        tokio::select! {
            ended = &mut both => ended,
            () = podssh_ssh::upgrade::logged_in() => {
                if detached {
                    close(&mut first, host, &log).await;
                }
                both.await
            }
        }
    };
    if let Some(handles) = first.take() {
        if !podssh_ssh::upgrade::reached() {
            // Nothing went out through the node: the session stays.
            let said = carried.channel.as_ref().map(|(_, why)| why.clone());
            let why = said.or_else(|| outcome.lines.first().cloned()).unwrap_or_default();
            let why = format!("the login through its temporary node failed ({why})");
            drop(node);
            return stay(handles, opts, relay, log, host, why).await;
        }
        let _ = tokio::time::timeout(CLOSE_LIMIT, podssh_ssh::run::disconnect_all(&handles)).await;
    }
    drop(node);
    if let Some((fault, why)) = &carried.channel {
        log.error(&format!("{host}: {why}"));
        super::result::channel_failed(fault);
        return EXIT_FAILURE;
    }
    for line in &outcome.lines {
        log.error(line);
    }
    if outcome.code == EXIT_FAILURE {
        if let Some(why) = carried.why.or_else(|| carried.leg.as_ref().and_then(super::node::explain)) {
            log.error(&format!("{host}: {why}"));
        }
    }
    outcome.code
}

/// Close the first connection, once the session runs through the node.
async fn close(first: &mut Option<Vec<Connection>>, host: &str, log: &Log) {
    if let Some(handles) = first.take() {
        let _ = tokio::time::timeout(CLOSE_LIMIT, podssh_ssh::run::disconnect_all(&handles)).await;
        log.verbose(&format!("{host}: logged in through the temporary node; the first connection is closed"));
    }
}

/// The session on the first connection, after one note of why it stays.
async fn stay(
    handles: Vec<Connection>,
    opts: &Options,
    relay: Option<RelayStatus>,
    log: Arc<Log>,
    host: &str,
    why: String,
) -> i32 {
    log.info(&format!(
        "{host}: --upgrade: {why}; the session stays on this connection, which does not resume after a lost link"
    ));
    podssh_ssh::upgrade::request(handles, opts, relay.as_ref(), log).await
}
