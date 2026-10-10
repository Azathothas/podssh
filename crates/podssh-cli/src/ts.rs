//! `podssh ts` behaviour (Tailscale): status, `-W` pipe, exits.
//!
//! stdout carries the answer and nothing else — the status line for the
//! bare form, the byte stream for `-W`. Every other path writes stderr only,
//! and every error path exits non-zero (pinned in `tests/ts_behave.rs`: the
//! VERB_OWNER `ts` row is gone because this module, not the refusal table,
//! owns the verb now).
//!
//! This module is the first sync→async bridge in the CLI: dispatch is
//! synchronous, `TsNode` is async, so a current-thread runtime is built per
//! invocation and driven with `block_on`. The `--timeout` bound (required
//! with no TTY) caps the whole operation: one deadline, made when the run
//! starts, and each wait gets what remains of it. On a terminal with no
//! `--timeout` the start attempt is unbounded — a human can interrupt —
//! while each wait for the first network map (the status, a peer's name, the
//! node's own address) is limited by `--ts-wait-allowlist`, else by
//! `FIRST_MAP_WAIT`: the fork waits for ever when no map comes.

use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use podssh_ts::wait::{Deadline, FIRST_MAP_WAIT};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::pager::Tty;

pub mod exits;
pub mod links;
pub mod probe;

use exits::{no_map, node_error_exit};

/// The `ts` inputs, straight from `Parsed::Ts` — plain data, no fork types.
pub struct TsArgs {
    pub destination: Option<String>,
    pub args: Vec<String>,
    pub w_target: Option<String>,
    pub mode: String,
    pub proxy: Option<String>,
    pub auth_key_file: Option<String>,
    pub state: Option<String>,
    pub ephemeral: bool,
    pub relay: Option<String>,
    pub wait_allowlist: Option<String>,
    pub timeout: Option<String>,
    pub jsonl: bool,
}

/// Run the `ts` verb: gate, then behaviour. Returns the process exit code.
pub fn run_ts(a: &TsArgs, out: &mut dyn Write, err: &mut dyn Write, tty: Tty) -> i32 {
    // The `--timeout` gate, same as every other verb with a `--timeout` row: required
    // with no TTY, parsed always. The bound caps the whole operation below.
    let attachment = crate::non_interactive::resolve_tty(tty, a.jsonl);
    let bound = match crate::non_interactive::require_timeout_or_env("ts", attachment, a.timeout.as_deref(), |n| {
        std::env::var(n).ok()
    }) {
        Ok(b) => b,
        Err(refusal) => {
            let _ = writeln!(err, "{}", refusal.message);
            return refusal.fault.code();
        }
    };
    // `--ts-wait-allowlist` parses with the `--timeout` parser; the refusal names the
    // ts flag, not `--timeout`, so the message is re-pointed (the fault stays).
    let wait = match a.wait_allowlist.as_deref() {
        None => None,
        Some(raw) => match crate::non_interactive::parse_timeout(raw) {
            Ok(d) => Some(d),
            Err(r) => {
                let _ = writeln!(err, "{}", r.message.replace("--timeout", "--ts-wait-allowlist"));
                return r.fault.code();
            }
        },
    };

    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh ts: cannot start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    rt.block_on(ts_async(a, out, err, bound, wait))
}

/// The async body: shared by every form after the gate.
async fn ts_async(
    a: &TsArgs,
    out: &mut dyn Write,
    err: &mut dyn Write,
    bound: Option<Duration>,
    wait: Option<Duration>,
) -> i32 {
    let deadline = Deadline::after(bound);
    // The host form needs an SSH session over the tailnet, which is not built yet.
    // It names the session rather than the tailnet: the node may be fine.
    if a.destination.is_some() && a.w_target.is_none() {
        let _ = writeln!(
            err,
            "podssh ts: an SSH session over the tailnet is not implemented yet;\nnothing was done. For a byte pipe to a tailnet peer, use -W HOST:PORT."
        );
        return EXIT_NOT_IMPLEMENTED;
    }
    // Mode → selection. `tun`/`socks` parse (closed values) but their daemon
    // mechanisms do not exist yet: capability, not usage — the flag was fine.
    let relay_mode = podssh_ts::config::TsMode::Relay {
        host: a.relay.clone().unwrap_or_else(|| "tcp.ts.relay.ajam.dev".to_string()),
        port: 443,
    };
    let forced = match a.mode.as_str() {
        "auto" => None,
        "tcp" => Some(podssh_ts::config::TsMode::Tcp),
        "relay" => Some(relay_mode.clone()),
        "tun" | "socks" => {
            let _ = writeln!(
                err,
                "podssh ts: --ts-mode {} needs a local tailscale daemon, which arrives\nwith the chain selection. Use --ts-mode tcp or --ts-mode relay.",
                a.mode
            );
            return crate::exitmap::Fault::Capability.code();
        }
        _ => {
            let _ = writeln!(err, "podssh ts: --ts-mode {} is not a mode.", a.mode);
            return EXIT_USAGE;
        }
    };
    // The key's presence, then its bytes: a missing flag reads as an auth
    // refusal (77, per r2) rather than a capability verdict (78). Each local
    // check runs before the chain, whose network checks take seconds.
    let key_path = match a.auth_key_file.as_deref() {
        None => {
            let _ = writeln!(
                err,
                "podssh ts: no auth key. Pass --ts-auth-key-file FILE with a tailnet\nauth key (file only, never argv). Without it the node cannot auth (77)."
            );
            return crate::exitmap::Fault::Auth.code();
        }
        Some(p) => p,
    };
    // Auth key bytes: unreadable → 64 naming the path; empty → 77 naming
    // the file. Presence was checked above, so this is readability, not
    // configuration.
    // Read into memory that is cleared, and trimmed in place: no plain copy.
    let mut raw = match std::fs::read(key_path) {
        Ok(b) => zeroize::Zeroizing::new(b),
        Err(e) => {
            let _ = writeln!(err, "podssh ts: cannot read --ts-auth-key-file {key_path}: {e}");
            return EXIT_USAGE;
        }
    };
    trim_key(&mut raw);
    let mut key = match podssh_ts::secret::AuthKey::new(raw) {
        Ok(k) => k,
        Err(_) => {
            let _ = writeln!(err, "podssh ts: --ts-auth-key-file {key_path} is empty.");
            return crate::exitmap::Fault::Auth.code();
        }
    };
    // State file: required in v1 (a default path for state files is not yet built);
    // its parent must exist — the fork creates the file, not directories.
    let state_path = match a.state.as_deref() {
        None => {
            let _ = writeln!(
                err,
                "podssh ts: pass --ts-state FILE for the node key-state file.\nIt is created when missing and must persist, or the node key rotates."
            );
            return EXIT_USAGE;
        }
        Some(p) => p,
    };
    if let Some(parent) = std::path::Path::new(state_path).parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            let _ = writeln!(err, "podssh ts: --ts-state {state_path}: directory {parent:?} does not exist.");
            return EXIT_USAGE;
        }
    }
    // The proxy of each connection: `--ts-proxy`, else the environment's,
    // as each podssh command reads it (T-103). No message quotes its URL,
    // which may hold a password.
    let proxy = match podssh_ts::config::choose_proxy(a.proxy.as_deref(), |n| std::env::var(n).ok()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(err, "podssh ts: {e}");
            return EXIT_USAGE;
        }
    };
    if a.proxy.as_deref().is_some_and(holds_credentials) {
        let _ = writeln!(
            err,
            "podssh ts: --ts-proxy holds credentials, which other users of this host can read\nin its list of processes. HTTPS_PROXY names the proxy as well."
        );
    }
    // Each mode's network check, in chain order, before anything registers:
    // the selected mode is the first that passed, never a default that no
    // check blessed (T-102).
    let modes = match &forced {
        Some(m) => vec![m.clone()],
        None => podssh_ts::chain::default_chain(relay_mode),
    };
    let selected = match probe::select(&modes, &probe::proxy_choice(proxy.as_ref()), deadline, err).await {
        Ok(m) => m,
        Err(code) => return code,
    };
    // A drop of a link, and its return, are said on stderr while the node runs, from its start
    // on: a start that waits says why (T-104).
    let (link_events, changes) = tokio::sync::broadcast::channel(64);
    let printer = tokio::spawn(links::print(changes));
    let cfg = podssh_ts::config::TsConfig {
        state_file: state_path.into(),
        control_url: None,
        hostname: None,
        ephemeral: a.ephemeral,
        mode: selected,
        proxy_url: proxy.as_ref().map(podssh_ts::config::TsProxy::url),
        no_proxy: proxy.and_then(|p| p.no_proxy),
        // While it waits for its key's admission, a refused node dials again (T-104).
        retry_refused: wait.is_some(),
        link_events: Some(link_events),
    };

    let started = if let Some(left) = deadline.remaining() {
        match tokio::time::timeout(left, podssh_ts::node::TsNode::start(&cfg, &key)).await {
            Ok(r) => r,
            Err(_) => {
                let _ = writeln!(err, "podssh ts: start did not finish within the bound.");
                // 78, recorded as a v1 choice: the flags were fine (not
                // 64), it is not auth (not 77), not a bug (not 70) and not
                // the relay refusing (not 69) — the run could not establish
                // in the bound given.
                return crate::exitmap::Fault::Capability.code();
            }
        }
    } else {
        podssh_ts::node::TsNode::start(&cfg, &key).await
    };
    // The fork holds its own copy now; podssh needs the key no more.
    key.expire();
    let node = match started {
        Ok(n) => n,
        Err(e) => return node_error_exit(&e, err),
    };
    // The first network map may never come: each wait for it gets the
    // allowlist's window, else `FIRST_MAP_WAIT`, and never more than remains.
    let window = wait.unwrap_or(FIRST_MAP_WAIT);
    let code = if let Some(target) = a.w_target.as_deref() {
        pipe_form(&node, target, err, deadline, window).await
    } else {
        status_form(&node, out, err, deadline, window, wait.is_some(), a.jsonl).await
    };
    // Each form ends here, after an error too (T-102).
    printer.abort();
    end(node, err).await;
    code
}

/// How long the fork's actors get to stop at the end of a run.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// Shut the node down; an ephemeral node logs out first, in 5 s at most and
/// after `--timeout`'s bound, so a bound that passed still leaves no device
/// behind. A logout that fails is said and changes no exit: the control
/// server removes an offline ephemeral node itself, later.
async fn end(node: podssh_ts::node::TsNode, err: &mut dyn Write) {
    if let Some(Err(why)) = node.shutdown(Some(STOP_WAIT)).await.logout {
        let _ = writeln!(
            err,
            "podssh ts: the ephemeral node was not logged out: {why}.\nThe control server removes it once it has been offline for a while."
        );
    }
}

/// The status as one JSON object on one line, for `--jsonl`: the event and
/// the three facts, never a key (`StatusFacts` has no field for one).
pub fn status_json(facts: &podssh_ts::status::StatusFacts) -> String {
    serde_json::json!({
        "event": "status",
        "nodekey_prefix": facts.nodekey_prefix,
        "tailnet_ip": facts.tailnet_ip,
        "home_region": facts.home_region,
    })
    .to_string()
}

/// Whether a proxy URL holds a user name or a password.
fn holds_credentials(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())].contains('@')
}

/// Strip trailing newline bytes, in place: key files commonly end with one,
/// and the key itself never contains it. Interior bytes are untouched.
fn trim_key(raw: &mut Vec<u8>) {
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
}

/// Bare `podssh ts`: one machine-readable line on stdout. The first network
/// map is awaited for `window`, never past the deadline; with
/// `--ts-wait-allowlist` (`poll`), a map with no home region yet is polled
/// until the window ends, and with none the first answer decides.
async fn status_form(
    node: &podssh_ts::node::TsNode,
    out: &mut dyn Write,
    err: &mut dyn Write,
    deadline: Deadline,
    window: Duration,
    poll: bool,
    jsonl: bool,
) -> i32 {
    let until = tokio::time::Instant::now() + deadline.limit(window);
    // In `relay` mode the relay is the only DERP link: no status line without it, and a key that
    // it refuses is said at once (T-105).
    if let Err(e) = node.derp_ready_within(until.saturating_duration_since(tokio::time::Instant::now())).await {
        return node_error_exit(&e, err);
    }
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match node.status_within(left).await {
            Ok(facts) => {
                let line = if jsonl { status_json(&facts) } else { facts.render() };
                let _ = writeln!(out, "{line}");
                return 0;
            }
            Err(podssh_ts::node::NodeError::NetmapPending) => {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                if !poll || left.is_zero() {
                    return no_map(err);
                }
                // 2 s poll cadence: a v1 design constant, not a measurement —
                // short enough to notice admission, long enough to not spin on
                // the runtime.
                tokio::time::sleep(std::cmp::min(left, Duration::from_secs(2))).await;
            }
            Err(e) => return node_error_exit(&e, err),
        }
    }
}

/// `podssh ts -W HOST:PORT`: stdio becomes the stream. HOST is a tailnet IP
/// literal or a peer name from the netmap; anything else is a route error
/// (78), never a hang. The peer's name and the node's own address each wait
/// for the first network map for `window`, never past the deadline.
async fn pipe_form(
    node: &podssh_ts::node::TsNode,
    target: &str,
    err: &mut dyn Write,
    deadline: Deadline,
    window: Duration,
) -> i32 {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, p),
        _ => {
            let _ = writeln!(err, "podssh ts: -W {target:?} is not HOST:PORT.");
            return EXIT_USAGE;
        }
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = writeln!(err, "podssh ts: -W {target:?} has no numeric port.");
            return EXIT_USAGE;
        }
    };
    let ip: std::net::IpAddr = if let Ok(ip) = host.parse() {
        ip
    } else {
        match node.peer_ip_within(host, deadline.limit(window)).await {
            Ok(Some(ip)) => ip,
            Ok(None) => {
                let _ = writeln!(err, "podssh ts: {host:?} is not in the netmap: no route.");
                return crate::exitmap::Fault::Capability.code();
            }
            Err(e) => return node_error_exit(&e, err),
        }
    };
    if let Err(e) = node.address_within(deadline.limit(window)).await {
        return node_error_exit(&e, err);
    }
    if let Err(e) = node.derp_ready_within(deadline.limit(window)).await {
        return node_error_exit(&e, err);
    }
    let open = if let Some(left) = deadline.remaining() {
        match tokio::time::timeout(left, node.tcp_connect(SocketAddr::new(ip, port))).await {
            Ok(r) => r,
            Err(_) => {
                let _ = writeln!(err, "podssh ts: connect to {target} did not finish within the bound.");
                return crate::exitmap::Fault::Capability.code();
            }
        }
    } else {
        node.tcp_connect(SocketAddr::new(ip, port)).await
    };
    let stream = match open {
        Ok(s) => s,
        Err(e) => return node_error_exit(&e, err),
    };
    // stdin/stdout stay split: stdin is not writable and stdout is not
    // readable, so neither can be a `copy_bidirectional` leg. Counts and the
    // ending go to stderr — stdout carries the stream and nothing else.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    match podssh_ts::pipe::pipe_streams(&mut stdin, &mut stdout, stream).await {
        Ok(ends) => {
            let why = match ends.end {
                podssh_ts::pipe::End::RemoteEof => "the peer closed the stream".to_string(),
                // Its reader left: a clean end, as for `podssh proxy`.
                podssh_ts::pipe::End::StdoutClosed => "stdout closed".to_string(),
                podssh_ts::pipe::End::Idle => format!(
                    "the peer sent nothing for {} s after the end of input",
                    podssh_ts::pipe::IDLE_AFTER_EOF.as_secs()
                ),
            };
            let _ = writeln!(err, "podssh ts: pipe closed: up={}, down={}: {why}.", ends.up, ends.down);
            0
        }
        Err(e) => {
            let _ = writeln!(err, "podssh ts: the pipe failed: {e}");
            EXIT_NOT_IMPLEMENTED
        }
    }
}
