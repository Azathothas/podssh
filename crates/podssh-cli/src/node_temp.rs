//! `podssh node --temporary KEY` (T-167): the far end of `podssh ssh
//! --upgrade`, which that command starts in its SSH session on this server.
//! It is a roost (T-166) in front of the sshd that the session came through
//! (`SSH_CONNECTION`), with a pair that no file keeps and a key for this run
//! only, and it lets in the client key KEY alone. Once the relay takes the
//! pair's sessions, it writes one line to stdout, which the SSH channel
//! carries to the client (`upgrade_line`), and leaves the session that
//! started it, so that the end of that connection does not end it. It ends
//! with its last session, or 10 minutes after its start with none, and stops
//! its pair.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::e2e::ends;
use podssh_relay::identity::{file, KeyName, PublicKey};
use podssh_relay::pair;
use podssh_relay::relay::{self, Relay};
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, E2e, Layered, NodeConfig, TcpHandler, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;
use tokio::io::DuplexStream;
use tokio::sync::Notify;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// Bound on each dial of sshd, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// How long the node waits for its first session.
const IDLE_LIMIT: Duration = Duration::from_secs(600);
/// How often the node looks at its sessions.
const WATCH_EVERY: Duration = Duration::from_secs(2);
/// The label of the node's lines when the command line gives none.
const LABEL: &str = "upgrade";

/// Run the temporary node for the client key `key`; returns the process
/// exit code.
pub fn run(args: &NodeArgs, key: &str, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args, key) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    // On the heap, as each large future here: Windows gives the main
    // thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(serve(ready, err)));
    runtime.shutdown_background();
    code
}

/// Each check that needs no network, done.
struct Ready {
    label: String,
    /// The sshd to stand in front of: the first that answers as one.
    candidates: Vec<Route>,
    client: KeyName,
    control: Relay,
    trust: Trust,
}

fn prepare(args: &NodeArgs, key: &str) -> Result<Ready, Refusal> {
    let client = KeyName::parse(key).ok_or_else(|| {
        Refusal::usage(format!(
            "--temporary {key:?}: not a key (64 hex digits, or base32) nor a fingerprint (SHA256:...)"
        ))
    })?;
    // The node makes its own pair and key, and lets in KEY alone.
    let refused = [
        ("--iroh", args.iroh),
        ("--pair-file", args.pair_file.is_some()),
        ("--plain", args.plain),
        ("--no-e2e", args.no_e2e),
        ("--key", args.key.is_some() || args.iroh_key.is_some()),
        ("--allow", args.allow.is_some() || args.iroh_allow.is_some()),
        ("--ephemeral-key", args.ephemeral_key || args.iroh_ephemeral),
        ("--iroh-relay", args.iroh_relay.is_some()),
        ("--derp", args.derp),
        ("--derp-server", args.derp_server.is_some()),
    ];
    if let Some((flag, _)) = refused.iter().find(|(_, given)| *given) {
        return Err(Refusal::usage(format!(
            "{flag} does not go with --temporary, which makes its own pair and key, and lets in the key KEY alone"
        )));
    }
    let label = args.name.clone().unwrap_or_else(|| LABEL.to_string());
    crate::pairs::check_label(&label)?;
    let candidates = candidates(&args.targets, std::env::var("SSH_CONNECTION").ok().as_deref())?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let relays = crate::relay_settings::relays(None, std::env::var(relay::RELAY_ENV).ok())?;
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    Ok(Ready { label, candidates, client, control: relays.primary().clone(), trust })
}

/// The sshd to stand in front of: TARGET, when the command line gives one;
/// else the one that this command's SSH session came through, by
/// `SSH_CONNECTION` (the client's address and port, then the server's), on
/// the loopback first, where no proxy is in the way, then at the server's
/// address; else 127.0.0.1:22.
pub(crate) fn candidates(words: &[String], session: Option<&str>) -> Result<Vec<Route>, Refusal> {
    if !words.is_empty() {
        let targets = crate::node::targets_of(words, false)?;
        if targets.len() > 1 || targets[0].name.is_some() {
            return Err(Refusal::usage("--temporary stands in front of one sshd: give one TARGET, with no route"));
        }
        return Ok(targets);
    }
    let words: Vec<&str> = session.unwrap_or_default().split_whitespace().collect();
    let Some(port) = words.get(3).and_then(|p| p.parse::<u16>().ok()).filter(|p| *p != 0) else {
        return crate::node::targets_of(&[crate::node::SSHD.to_string()], false);
    };
    let server = words[2].trim_start_matches('[').trim_end_matches(']');
    let loopback = if server.contains(':') { "::1" } else { "127.0.0.1" };
    let mut out = vec![Route { name: None, host: loopback.to_string(), port }];
    if server != loopback {
        out.push(Route { name: None, host: server.to_string(), port });
    }
    Ok(out)
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, candidates, client, control, trust } = ready;
    let proxy = ProxyChoice::FromEnvironment;
    let Some((target, versions)) = sshd(&candidates, &label, err).await else {
        return Fault::RelayUnreachable.code();
    };
    let ctx = crate::pairs::context(&control, &trust, &proxy);
    let pair = match pair::create(&ctx).await {
        Ok(pair) => pair,
        Err(e) => return crate::pairs::refusal(&e).report("node", err),
    };
    // A key for this run only: the client learns it from the line.
    let key = match crate::channel::load_node_key(&file::Place::Ephemeral) {
        Ok(key) => key,
        Err(refusal) => {
            let _ = pair::stop(&ctx, &pair).await;
            return refusal.report("node", err);
        }
    };
    let shown = crate::node::serving(std::slice::from_ref(&target), &versions);
    let _ = writeln!(
        err,
        "podssh node: {label}: serving {shown} through {} for the client key {client} alone",
        control.host
    );
    // The line says whether the node can leave its session, so that is
    // known before it is written.
    let null = open_null();
    let line = crate::upgrade_line::line(&pair, &key.identity.public(), null.is_some());
    let say: Arc<dyn Fn(String) + Send + Sync> = {
        let label = label.clone();
        Arc::new(move |line: String| {
            let _ = writeln!(std::io::stderr(), "podssh node: {label}: {line}");
        })
    };
    let admit = move |key: &PublicKey| {
        if client.matches(key) {
            Ok(())
        } else {
            Err(format!("refused the operator key {key}: this node lets in {client} alone"))
        }
    };
    let node = ends::Node { identity: Arc::new(key.identity), admit: Arc::new(admit), say: say.clone() };
    let settings = crate::layered::settings();
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(settings.resume_deadline));
    let tcp = TcpHandler { host: target.host.clone(), port: target.port, timeout: DIAL_LIMIT, sshd: true };
    let budget = reverse::layered::NODE_BUDGET;
    let handler = Arc::new(Layered::with_keeper(E2e::new(tcp, node), settings, budget, keeper.clone()));
    // The relay takes the pair's sessions from the line `online` on: the
    // offer goes out then, and not before.
    let online = Arc::new(Notify::new());
    let node_say = {
        let (online, say) = (online.clone(), say.clone());
        move |line: String| {
            if line.starts_with("online") {
                online.notify_one();
            }
            say(line);
        }
    };
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: crate::pairs::REQUEST_LIMIT,
        settings: reverse::Settings { rejoin: settings.resume_deadline, ..reverse::Settings::default() },
        repair: None,
        wire: Wire::Tls,
        say: Some(&node_say),
    };
    let until = async {
        tokio::select! {
            () = crate::node::stop_signal() => {}
            () = idle(&keeper) => {}
        }
    };
    let ended = {
        let serving = reverse::run(&mut config, handler, until);
        tokio::pin!(serving);
        let early = tokio::select! {
            exit = &mut serving => Some(exit),
            () = online.notified() => None,
        };
        match early {
            Some(exit) => {
                let _ = writeln!(err, "podssh node: {label}: the relay did not take the pair's sessions");
                exit
            }
            None => {
                give(&line, null);
                serving.await
            }
        }
    };
    // The pair ends with the node: nobody else holds it.
    let _ = pair::stop(&ctx, &config.pair).await;
    match crate::node::ended(&label, ended) {
        None => 0,
        Some((fault, why)) => {
            let _ = writeln!(err, "podssh node: {label}: {why}");
            fault.code()
        }
    }
}

/// The first of `candidates` that answers as an sshd, and its version line.
/// Each that does not is said; with none, the node ends.
async fn sshd(candidates: &[Route], label: &str, err: &mut dyn Write) -> Option<(Route, Vec<String>)> {
    for target in candidates {
        match crate::node::probe(std::slice::from_ref(target), true).await {
            Ok(versions) => return Some((target.clone(), versions)),
            Err(refusal) => {
                let _ = writeln!(err, "podssh node: {label}: {}", refusal.message);
            }
        }
    }
    let _ = writeln!(err, "podssh node: {label}: no sshd answered, so no session could be served");
    None
}

/// Until the node's last session ends, or [`IDLE_LIMIT`] passes with none:
/// a session kept for a resume counts until its deadline.
async fn idle(keeper: &Keeper<DuplexStream>) {
    let started = Instant::now();
    let mut seen = false;
    loop {
        tokio::time::sleep(WATCH_EVERY).await;
        match keeper.kept() {
            0 if seen || started.elapsed() >= IDLE_LIMIT => return,
            0 => {}
            _ => seen = true,
        }
    }
}

/// Give the line on stdout, then leave the SSH session that started this
/// node: stdin, stdout and stderr become `null`, so that the end of that
/// session, which closes them, does not end the node.
fn give(line: &str, null: Option<std::fs::File>) {
    let mut out = std::io::stdout();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    leave(null);
}

/// `/dev/null`, when the node can leave its session; SIGHUP, which the end
/// of a session may send, is ignored from here on.
#[cfg(unix)]
fn open_null() -> Option<std::fs::File> {
    // SAFETY: setting a signal's disposition to ignored has no preconditions.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").ok()
}

/// On Windows the node does not leave its session: the line says so, and
/// the client keeps that connection open while the session runs.
#[cfg(not(unix))]
fn open_null() -> Option<std::fs::File> {
    None
}

#[cfg(unix)]
fn leave(null: Option<std::fs::File>) {
    use std::os::fd::AsRawFd;
    let Some(null) = null else { return };
    for fd in 0..=2 {
        // SAFETY: dup2 of an open file onto a standard descriptor of this
        // process; a failure leaves that descriptor as it was.
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
    // SAFETY: setsid has no preconditions; in a process that leads its
    // group already it fails, and nothing changes.
    unsafe { libc::setsid() };
}

#[cfg(not(unix))]
fn leave(_: Option<std::fs::File>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(routes: Result<Vec<Route>, Refusal>) -> Vec<String> {
        routes.expect("candidates").iter().map(|r| podssh_ws::dial::authority(&r.host, r.port)).collect()
    }

    #[test]
    fn the_sshd_of_the_session_is_tried_on_the_loopback_first() {
        let session = Some("203.0.113.9 50000 198.51.100.7 2222");
        assert_eq!(shown(candidates(&[], session)), ["127.0.0.1:2222", "198.51.100.7:2222"]);
        assert_eq!(shown(candidates(&[], Some("127.0.0.1 50000 127.0.0.1 22"))), ["127.0.0.1:22"]);
        assert_eq!(shown(candidates(&[], Some("2001:db8::9 50000 2001:db8::7 22"))), ["[::1]:22", "[2001:db8::7]:22"]);
    }

    #[test]
    fn with_no_session_the_sshd_is_127_0_0_1_22_and_a_target_wins() {
        assert_eq!(shown(candidates(&[], None)), ["127.0.0.1:22"]);
        assert_eq!(shown(candidates(&[], Some("garbage"))), ["127.0.0.1:22"]);
        let words = ["10.0.0.5:2200".to_string()];
        assert_eq!(shown(candidates(&words, Some("a 1 b 22"))), ["10.0.0.5:2200"]);
        assert!(candidates(&["web=127.0.0.1:22".to_string()], None).is_err());
    }
}
