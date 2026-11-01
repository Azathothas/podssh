//! The flag rows of `ts`, the Tailscale road (T-100 to T-105), apart from
//! the table of verbs so that `flags.rs` stays within 500 lines.

use super::{row, FlagKind, FlagRow};

/// **`ts` and its `tailscale` alias (Tailscale, the cargo feature `ts`).** The
/// spelling: `ts`-prefixed flags; `-W` is the byte-pipe target with ssh's own
/// `stdio-forward` row shape. All three forms parse; `ts.rs` runs them, and a
/// build without the feature refuses them, naming the feature.
#[rustfmt::skip]
pub const TS_FLAGS: &[FlagRow] = &[
    row(None, "ts-mode", Some("MODE"), FlagKind::Supported,
        "auto tun socks tcp relay: auto takes the first of tcp, relay whose check passes", None),
    row(None, "ts-proxy", Some("URL"), FlagKind::Supported,
        "HTTP CONNECT or SOCKS5 proxy for each connection; default: the environment's", None),
    row(None, "ts-auth-key-file", Some("FILE"), FlagKind::Supported,
        "tailnet auth key file; never passed on argv", None),
    row(None, "ts-state", Some("FILE"), FlagKind::Supported,
        "node key-state file, created when missing", None),
    row(None, "ts-ephemeral", None, FlagKind::Supported,
        "register an ephemeral node, logged out at the end of the run", None),
    row(None, "ts-relay", Some("HOST[:PORT]"), FlagKind::Supported,
        "DERP-over-WebSocket relay for relay mode; port 443 when none is given", None),
    row(None, "ts-control-url", Some("URL"), FlagKind::Supported,
        "the tailnet's control server, https://HOST[:PORT]; tcp's check asks it for its key \
         (default: Tailscale's)", None),
    row(None, "ts-wait-allowlist", Some("DURATION"), FlagKind::Supported,
        "wait this long for relay admission; default fail-fast", None),
    row(Some('W'), "stdio-forward", Some("HOST:PORT"), FlagKind::Supported,
        "byte pipe over the tailnet: stdio becomes the stream", None),
    row(None, "jsonl", None, FlagKind::Supported,
        "the status as one JSON object on stdout; refused with -W", None),
    row(None, "timeout", Some("DURATION"), FlagKind::Supported,
        "bound the run; required when stdin is not a TTY (default: env PODSSH_TIMEOUT)", None),
];
