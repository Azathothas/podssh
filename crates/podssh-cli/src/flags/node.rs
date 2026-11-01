//! The flag rows of `node`: those of a pair, as `operator` has them, the
//! plain mode (T-263), the resume deadline (T-306), a roost in front of a
//! standard sshd (T-166), the node's key and allowlist on each road and the
//! end-to-end channel (T-087, T-088), and those of the iroh road (T-163),
//! which a build has with the feature `iroh` only; in another build,
//! `--iroh` is refused with exit 70. The key's flags of T-163 keep their
//! names beside the new ones. And the client's resume deadline, which
//! `ssh` and `operator` name in their tables.

use super::{row, FlagKind, FlagRow};

/// `ssh`'s flags of a service (T-393), beside the node's of this table.
pub const SSH_INSTALL: FlagRow = row(None, "install", Some("NAME"), FlagKind::Supported,
    "make this tunnel, with -N and --persist, a service of this user named NAME, which starts it again whenever it ends: the ways of podssh node --install, with these words but --install NAME", None);
pub const SSH_UNINSTALL: FlagRow = row(None, "uninstall", Some("NAME"), FlagKind::Supported,
    "remove the service that --install NAME made, its file of variables and its lock, and nothing else", None);
pub const SSH_ENV_FILE: FlagRow = row(None, "env-file", Some("FILE"), FlagKind::Supported,
    "read the variables of FILE, a private file of NAME=VALUE lines, before anything else, and hold FILE.lock while it runs, so that a second start ends at once: the file that --install writes", None);

/// A client's own resume deadline (T-306), of `ssh` and `operator`.
pub const OWN_DEADLINE: FlagRow = row(None, "resume-deadline", Some("TIME"), FlagKind::Supported,
    "node://NAME and iroh:TICKET: wait at most TIME for a new link after a loss, though the node keeps the session longer: 90s, 30m, 8h or 3d, from 1 minute to 72 h (default: as long as the node keeps it)", None);

/// `node` (T-083, T-163): the flags of a pair, and those of the iroh road,
/// which a build has with the feature `iroh` only.
pub const NODE_FLAGS: &[FlagRow] = &[
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "use the pair in FILE, a private file, not the one stored under NAME (operator: its operator's part will do)", None),
    row(None, "plain", None, FlagKind::Supported,
        "carry each session's bytes as they are, with no resumable layer, for an operator that does not speak it; a lost link ends the session", None),
    row(None, "resume-deadline", Some("TIME"), FlagKind::Supported,
        "keep a session whose link is lost for TIME, on each road, and tell its operator so: 90s, 30m, 8h or 3d, from 1 minute to 72 h (default 10m)", None),
    row(None, "sshd", None, FlagKind::Supported,
        "a roost: each TARGET (default 127.0.0.1:22) is a standard sshd, which must send its SSH version line first, at the start and on each session's connection", None),
    row(None, "temporary", Some("KEY"), FlagKind::Supported,
        "the far end that podssh ssh --upgrade starts on its server: a roost in front of the session's sshd, with a pair and a key that no file keeps, for the client key KEY alone; one line on stdout gives the offer; it ends with its last session, or after 10 minutes with none", None),
    row(None, "key", Some("FILE"), FlagKind::Supported,
        "the node's key in FILE, on each road, made when missing (default: node-NAME.key in the cache); its fingerprint is said as the node starts", None),
    row(None, "ephemeral-key", None, FlagKind::Supported,
        "a new key for this run only, kept in no file; an operator that pinned the node's key refuses it", None),
    row(None, "allow", Some("FILE"), FlagKind::Supported,
        "the operator keys that may come in, on each road: one key or fingerprint on each line, read again for each session (default: on the pair's road, each operator with the connect token; on the iroh road, none)", None),
    row(None, "no-e2e", None, FlagKind::Supported,
        "carry each session's bytes with no end-to-end channel, to operators that run none either; the relay then sees them", None),
    row(None, "iroh", None, FlagKind::Supported,
        "serve TARGET over the iroh road, with no pair: a client dials the ticket that the node prints; a build with the feature iroh", None),
    super::derp::NODE_DERP,
    row(None, "quick-tunnel", None, FlagKind::Supported,
        "serve TARGET at https://NAME.trycloudflare.com, a quick tunnel of Cloudflare's that podssh makes itself, with no pair and no account; the name, new each run, is the line on stdout; needs --allow, and TCP port 7844 of Cloudflare's edge, directly or through a proxy that allows it", None),
    row(None, "warp", None, FlagKind::Supported,
        "with --quick-tunnel: reach the edge's TCP port 7844 inside WARP's tunnel first, over HTTP/2 to Cloudflare on port 443; without it, WARP's tunnel is tried after QUIC and TCP fail; a build with the feature warp", None),
    row(None, "iroh-key", Some("FILE"), FlagKind::Supported,
        "the same as --key, by its earlier name", None),
    row(None, "iroh-allow", Some("FILE"), FlagKind::Supported,
        "the same as --allow, by its earlier name", None),
    row(None, "iroh-ephemeral", None, FlagKind::Supported,
        "the same as --ephemeral-key, by its earlier name; with --iroh, the ticket lasts as long as the run", None),
    row(None, "detach", None, FlagKind::Supported,
        "go to the background once the node is online, as podssh itself (T-380); for a node that must outlive a logout, --install", None),
    row(None, "restart", None, FlagKind::Supported,
        "with --detach: a small process in the background starts the run again whenever it ends, but after 64, 77 or 78 or a stop of that process; it never gives up (T-390)", None),
    super::detach::DETACH_NAME,
    row(None, "install", None, FlagKind::Supported,
        "make this node a service of this user, which starts it again whenever it ends, as a probe finds one: a user unit of systemd, else a LaunchAgent, else a line of the crontab at boot and one each 5 minutes; on Windows a task at logon; no privilege is asked for, and no token is written into it", None),
    row(None, "uninstall", None, FlagKind::Supported,
        "remove the service that --install made for NAME, its file of variables and its lock, and nothing else", None),
    row(None, "env-file", Some("FILE"), FlagKind::Supported,
        "read the node's variables from FILE, a private file of NAME=VALUE lines, before anything else, and hold FILE.lock while it runs, so that a second start ends at once: the file that --install writes beside the pair", None),
    row(None, "iroh-relay", Some("URLS"), FlagKind::Supported,
        "with --iroh: the relays, https://HOST[:PORT][,...]; the first that answers is the home relay (default: env PODSSH_IROH_RELAY, else n0's)", None),
    super::derp::NODE_DERP_SERVER,
];
