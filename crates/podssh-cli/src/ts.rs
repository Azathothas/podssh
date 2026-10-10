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
    // Chain inputs. `has_key` is presence only — readability is checked next,
    // so a missing file cannot read as "no key configured". The presence
    // check runs before the chain so a missing flag reads as an auth refusal
    // (77, per r2) rather than a capability verdict (78).
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
    let inputs = podssh_ts::chain::ChainInputs { addrs: vec![], socks_endpoint: None, has_key: true };
    let modes = match &forced {
        Some(m) => vec![m.clone()],
        None => podssh_ts::chain::default_chain(relay_mode),
    };
    // One probe pass, one selection: `select_chain` returning `Some` is the
    // same condition, so the mode below is the probed winner — never a
    // default the probe did not bless.
    let selected = match podssh_ts::chain::select_chain(&modes, &inputs) {
        Some(m) => m,
        None => {
            for m in &modes {
                let name = match m {
                    podssh_ts::config::TsMode::Tcp => "tcp".to_string(),
                    podssh_ts::config::TsMode::Relay { host, port } => {
                        format!("relay {host}:{port}")
                    }
                };
                let verdict = podssh_ts::chain::probe(m, &inputs);
                let _ = writeln!(err, "podssh ts: mode {name}: {verdict:?}");
            }
            let _ = writeln!(err, "podssh ts: no mode is ready.");
            return crate::exitmap::Fault::Capability.code();
        }
    };
    // Auth key bytes: unreadable → 64 naming the path; empty → 77 naming
    // the file. Presence was checked above, so this is readability, not
    // configuration.
    let raw = match std::fs::read(key_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "podssh ts: cannot read --ts-auth-key-file {key_path}: {e}");
            return EXIT_USAGE;
        }
    };
    let key = match podssh_ts::secret::AuthKey::new(trim_key(&raw)) {
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
    // Proxy: validated with the fork's own parser (the same one the dialer
    // uses), so the validator and the dialer never disagree.
    if let Some(u) = a.proxy.as_deref() {
        if podssh_ts::config::parse_proxy_url(u).is_err() {
            let _ = writeln!(err, "podssh ts: --ts-proxy {u:?} is not an http:// URL with a host.");
            return EXIT_USAGE;
        }
    }
    let cfg = podssh_ts::config::TsConfig {
        state_file: state_path.into(),
        control_url: None,
        hostname: None,
        ephemeral: a.ephemeral,
        mode: selected,
        proxy_url: a.proxy.clone(),
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
    let node = match started {
        Ok(n) => n,
        Err(e) => return node_error_exit(&e, err),
    };
    // The first network map may never come: each wait for it gets the
    // allowlist's window, else `FIRST_MAP_WAIT`, and never more than remains.
    let window = wait.unwrap_or(FIRST_MAP_WAIT);
    if let Some(target) = a.w_target.as_deref() {
        return pipe_form(&node, target, err, deadline, window).await;
    }
    status_form(&node, out, err, deadline, window, wait.is_some()).await
}

/// Strip trailing newline bytes: key files commonly end with one, and the key
/// itself never contains it. Interior bytes are untouched.
fn trim_key(raw: &[u8]) -> Vec<u8> {
    let mut v = raw.to_vec();
    while v.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        v.pop();
    }
    v
}

/// Map a node failure to its exit. Fork strings carrying "not authorized"
/// split 77 via `classify_1008`; everything else is 70.
fn node_error_exit(e: &podssh_ts::node::NodeError, err: &mut dyn Write) -> i32 {
    use podssh_ts::node::NodeError;
    match e {
        NodeError::Config(c) => {
            let _ = writeln!(err, "podssh ts: bad configuration: {c:?}");
            EXIT_USAGE
        }
        NodeError::KeyExpired | NodeError::KeyNotUtf8 => {
            let _ = writeln!(err, "podssh ts: the auth key is unusable: {e:?}");
            crate::exitmap::Fault::Auth.code()
        }
        NodeError::NetmapPending => no_map(err),
        NodeError::NotYet(what) => {
            let _ = writeln!(err, "podssh ts: not yet: {what}");
            EXIT_NOT_IMPLEMENTED
        }
        NodeError::Fork(text) => {
            let _ = writeln!(err, "podssh ts: the tailnet engine failed: {text}");
            match podssh_ts::classify::classify_1008(Some(text)) {
                podssh_ts::classify::Fault::NotAuthorized => {
                    let _ = writeln!(
                        err,
                        "The relay refused the node key (1008 \"not authorized\").\nSync the allowlist, or pass --ts-wait-allowlist to wait for admission."
                    );
                    crate::exitmap::Fault::Auth.code()
                }
                podssh_ts::classify::Fault::Session => EXIT_NOT_IMPLEMENTED,
            }
        }
    }
}

/// No network map within the wait: 78, and one message for each wait.
fn no_map(err: &mut dyn Write) -> i32 {
    // MEASURED 2026-10-07: an allowlisted-but-unsynced node sits here, not on
    // the 1008 arm — the fork never surfaces the relay's close through the
    // Device API, so "no netmap" IS the unlisted-key symptom and the message
    // must name the sync, not just the wait.
    let _ = writeln!(
        err,
        "podssh ts: no netmap yet. Pass --ts-wait-allowlist DURATION to wait\nfor relay admission instead of failing fast. If the wait expires, the relay's\nallowlist likely lacks this node's key: sync it, then retry with the\nsame --ts-state file so the node keeps its key."
    );
    crate::exitmap::Fault::Capability.code()
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
) -> i32 {
    let until = tokio::time::Instant::now() + deadline.limit(window);
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match node.status_within(left).await {
            Ok(facts) => {
                let _ = writeln!(out, "{}", facts.render());
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
            let _ = writeln!(
                err,
                "podssh ts: pipe closed: up={}, down={}, first={:?}.",
                opt(ends.up),
                opt(ends.down),
                ends.first
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "podssh ts: the pipe failed: {e}");
            EXIT_NOT_IMPLEMENTED
        }
    }
}

/// A count for stderr: a number, or `?` when that leg never ran to EOF.
fn opt(n: Option<u64>) -> String {
    n.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string())
}
