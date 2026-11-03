//! The flag rows of `node`: those of a pair, as `operator` has them, the
//! plain mode (T-263), the resume deadline (T-306), a roost in front of a
//! standard sshd (T-166), the node's key and allowlist on each road and the
//! end-to-end channel (T-087, T-088), and those of the iroh road (T-163),
//! which a build has with the feature `iroh` only; in another build,
//! `--iroh` is refused with exit 70. The key's flags of T-163 keep their
//! names beside the new ones. And the client's resume deadline, which
//! `ssh` and `operator` name in their tables; the exit of the net (T-431):
//! `node --exit`, `--exit NAME` of the clients, and the verb `exit`.

use super::{row, FlagKind, FlagRow};

/// `ssh`'s flags of a service (T-393), beside the node's of this table.
pub const SSH_INSTALL: FlagRow = row(None, "install", Some("NAME"), FlagKind::Supported,
    "make this tunnel, with -N and --persist, a service of this user named NAME, which starts it again whenever it ends: the ways of podssh node --install, with these words but --install NAME", None);
pub const SSH_UNINSTALL: FlagRow = row(
    None,
    "uninstall",
    Some("NAME"),
    FlagKind::Supported,
    "remove the service that --install NAME made, its file of variables and its lock, and nothing else",
    None,
);
pub const SSH_ENV_FILE: FlagRow = row(None, "env-file", Some("FILE"), FlagKind::Supported,
    "read the variables of FILE, a private file of NAME=VALUE lines, before anything else, and hold FILE.lock while it runs, so that a second start ends at once: the file that --install writes", None);

/// A client's own resume deadline (T-306), of `ssh` and `operator`.
pub const OWN_DEADLINE: FlagRow = row(None, "resume-deadline", Some("TIME"), FlagKind::Supported,
    "node://NAME and iroh:TICKET: wait at most TIME for a new link after a loss, though the node keeps the session longer: 90s, 30m, 8h or 3d, from 1 minute to 72 h (default: as long as the node keeps it)", None);

/// `--exit NAME` of `ssh`, `cp`, `scp` and `sftp` (T-431).
pub const EXIT: FlagRow = row(None, "exit", Some("NAME"), FlagKind::Supported,
    "start the road at NAME, a node of your net that lends its egress (podssh node --exit): it dials the destination, or the first hop of -J, from its own host, on each road between the two; the host key is the destination's", None);
/// `--exit NAME` of `proxy`.
pub const PROXY_EXIT: FlagRow = row(None, "exit", Some("NAME"), FlagKind::Supported,
    "carry the pipe from NAME, a node of your net that lends its egress (podssh node --exit), in place of the relay: it dials HOST PORT from its own host", None);
/// `--client-key FILE` of `proxy`, for its exit and for a node (T-587).
pub const PROXY_CLIENT_KEY: FlagRow = row(
    None,
    "client-key",
    Some("FILE"),
    FlagKind::Supported,
    "with --exit, and node://NAME: this client's key in FILE, made when missing (default: client.key in the cache)",
    None,
);
/// The flags of a pair and of its channel, of `proxy node://NAME` (T-587),
/// as `operator` has them.
pub const PROXY_PAIR_FILE: FlagRow = row(
    None,
    "pair-file",
    Some("FILE"),
    FlagKind::Supported,
    "node://NAME: the pair in FILE, or its operator's part, not the one stored under NAME",
    None,
);
pub const PROXY_NODE_KEY: FlagRow = row(
    None,
    "node-key",
    Some("KEY"),
    FlagKind::Supported,
    "node://NAME: the node's key, or its fingerprint SHA256:..., in place of the pins of known-nodes",
    None,
);
pub const PROXY_NO_E2E: FlagRow = row(
    None,
    "no-e2e",
    None,
    FlagKind::Supported,
    "node://NAME: no end-to-end channel, to a node that runs none either; the relay then sees each byte",
    None,
);
pub const PROXY_DEADLINE: FlagRow = row(None, "resume-deadline", Some("TIME"), FlagKind::Supported,
    "node://NAME: wait at most TIME for a new link after a loss, though the node keeps the session longer: 90s, 30m, 8h or 3d, from 1 minute to 72 h (default: as long as the node keeps it)", None);
/// `--exit NAME` of `pipe`.
pub const PIPE_EXIT: FlagRow = row(None, "exit", Some("NAME"), FlagKind::Supported,
    "relay:HOST:PORT and relay:%h:%p start at NAME, a node of your net that lends its egress (podssh node --exit), in place of the relay", None);

/// `exit NAME --listen ADDR:PORT` (T-431): a local proxy whose connections
/// start at the exit NAME.
#[rustfmt::skip]
pub const EXIT_FLAGS: &[FlagRow] = &[
    row(None, "listen", Some("ADDR:PORT"), FlagKind::Supported,
        "serve SOCKS5, SOCKS4a and HTTP CONNECT on ADDR:PORT, a loopback address, a listener that you ask for (127.0.0.1:0 takes a free port); PODSSH_LISTEN=no refuses it", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "the pair in FILE, or its operator's part, not the one stored under NAME", None),
    row(None, "client-key", Some("FILE"), FlagKind::Supported,
        "this client's key in FILE, made when missing (default: client.key in the cache)", None),
    row(None, "node-key", Some("KEY"), FlagKind::Supported,
        "the node's key, or its fingerprint SHA256:..., in place of the net's or the pins of known-nodes", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE for the relay (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "no line for each connection; errors still go to stderr", None),
];

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
        "a roost: each TARGET (default 127.0.0.1:22) is a standard sshd that runs already, which must send its SSH version line first, at the start and on each session's connection; podssh brings no sshd (podssh doctor's line sshd says whether this host has one)", None),
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
    row(None, "exit", None, FlagKind::Supported,
        "lend this host's egress to the members of its net: a session may name a target of its own, which the node resolves, then dials at a public address alone, or in a range of --routes; needs a net that gives this node the role exit; TARGET is then optional", None),
    row(None, "routes", Some("RANGES"), FlagKind::Supported,
        "with --exit: the private ranges that the exit dials too, ADDR/BITS or one address, separated by commas, each for the members that the net's policy lets reach the address", None),
    // A stream that exists already as the node's one road (T-595).
    row(None, "carrier", Some("ADDR"), FlagKind::Supported,
        "serve TARGET over ADDR, a stream that exists already, with no relay and no pair: stdio (or -), as the exec channel of a platform's own SSH gives it, fd:N (Unix), or exec:CMD, a program started with no shell; the other end runs podssh operator --carrier, or proxy, ssh, cp, scp or sftp --carrier to node://NAME; stdin may not be a terminal", None),
    row(None, "iroh", None, FlagKind::Supported,
        "serve TARGET over the iroh road, with no pair: a client dials the ticket that the node prints; a build with the feature iroh", None),
    super::derp::NODE_DERP, super::opentunnel::NODE_OPENTUNNEL,
    row(None, "quick-tunnel", None, FlagKind::Supported,
        "serve TARGET at https://NAME.trycloudflare.com, a quick tunnel of Cloudflare's that podssh makes itself, with no pair and no account; the name, new each run, is the line on stdout; needs --allow, and TCP port 7844 of Cloudflare's edge, directly or through a proxy that allows it", None),
    row(None, "warp", None, FlagKind::Supported,
        "with --quick-tunnel: reach the edge's TCP port 7844 inside WARP's tunnel first, over HTTP/2 to Cloudflare on port 443; without it, WARP's tunnel is tried after QUIC and TCP fail; a build with the feature warp", None),
    // The relay role behind the quick tunnel, with no listener (T-428).
    row(None, "relay", None, FlagKind::Supported,
        "with --quick-tunnel: serve the relay's forward and reverse roads too, those of podssh relay serve, at the tunnel's name, with no listener; a client names https://NAME.trycloudflare.com as its relay host; with no TARGET, the relay alone", None),
    row(None, "mint", Some("WHO"), FlagKind::Supported,
        "with --relay: who may mint a token and make a pair: keys:FILE, the keys of FILE, each by its signature of the relay's challenge; anyone; or nobody (default: the keys of --allow)", None),
    row(None, "pairs", Some("FILE"), FlagKind::Supported,
        "with --relay: keep the pairs of its reverse road in FILE, of mode 0600, so that they outlive a restart (the digests of their tokens, never a token)", None),
    row(None, "allow-private", None, FlagKind::Supported,
        "with --relay: dial private, loopback and other non-public addresses too (by default only public targets, as the default relay)", None),
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

/// **`net`** (T-429): the net of a user's own nodes, a list of their names
/// and keys that the owner's key signs. Its subcommands and their words are
/// its arguments; beside the node's table, as the net names the nodes.
#[rustfmt::skip]
pub const NET_FLAGS: &[FlagRow] = &[
    row(None, "owner-key", Some("FILE"), FlagKind::Supported,
        "init, add, rm, renew, policy set and policy clear: the owner's key that signs, a private key or a public one that the agent holds (default: the agent's key or the key of ~/.ssh that owns the net; for init, ~/.ssh/id_ed25519)", None),
    row(None, "roles", Some("LIST"), FlagKind::Supported,
        "add: what the member offers the net, of node, exit, relay and share, separated by commas (default node)", None),
    row(None, "iroh-ticket", Some("TICKET"), FlagKind::Supported,
        "add: the member's iroh ticket, which a client races for node://NAME when it names none", None),
    row(None, "derp-ticket", Some("TICKET"), FlagKind::Supported,
        "add: the member's DERP ticket, which a client dials for node://NAME when each road before it failed", None),
    row(None, "days", Some("N"), FlagKind::Supported,
        "init, add, rm, renew, policy set and policy clear: the days that the signed document lasts, 1 to 3650 (default 365); no end takes it after", None),
    row(None, "owner", Some("KEY"), FlagKind::Supported,
        "take: the owner that a first document must have, its fingerprint SHA256:... or its public key; later ones must have the owner held", None),
    row(None, "signature", None, FlagKind::Supported,
        "show: the owner's signature, as ssh-keygen -Y sign writes it, in place of the document", None),
];
