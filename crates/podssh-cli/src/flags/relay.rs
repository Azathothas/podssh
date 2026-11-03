//! The flag rows of the verbs of the relay itself: `relay`, `proxy`,
//! `doctor` and `status`, each with the relay's settings that it reads.

use super::{row, FlagKind, FlagRow};

/// `relay`: the pairs of the reverse road (T-083). Each request has its
/// own bound, so there is no `--timeout` (T-058).
#[rustfmt::skip]
pub const RELAY_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts, HOST[:PORT][,...]: status asks each, and pair, info and trace use the first (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots); with serve --acme, for the ACME directory", None),
    row(None, "operator-file", Some("FILE"), FlagKind::Supported,
        "pair: write the operator's part of the pair to FILE, a new file that only its owner can read", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "status: the pair in FILE, or its operator's part, as pair --operator-file writes it, not the one stored under NAME; NAME, when given, is the label shown", None),
    row(None, "document", Some("FILE"), FlagKind::Supported,
        "spec: check FILE, a copy of the relay's document, and read nothing from the network", None),
    row(None, "json", None, FlagKind::Supported,
        "status, info and trace: the answer as one JSON object on stdout, when the run ends; for a pair, its label, online, sessions, expires and seconds_left", None),
    row(None, "listen", Some("ADDR:PORT"), FlagKind::Supported,
        "serve: serve the relay's forward and reverse roads on ADDR:PORT, a listener that you ask for (127.0.0.1:0 takes a free port); PODSSH_LISTEN=no refuses it", None),
    row(None, "cert", Some("FILE"), FlagKind::Supported,
        "serve: the certificate chain that the relay presents, in PEM, read again on SIGHUP or when it changes", None),
    row(None, "key", Some("FILE"), FlagKind::Supported,
        "serve: the certificate's P-256 key, in PEM (EC PRIVATE KEY or PRIVATE KEY), in a file that only its owner reads; read again with --cert", None),
    row(None, "acme", Some("NAME"), FlagKind::Supported,
        "serve: a certificate for NAME from an ACME CA (Let's Encrypt by default), in place of --cert and --key: proven by TLS-ALPN-01 on the listener, which the CA reaches at NAME on port 443, kept in the cache and renewed in the role", None),
    row(None, "acme-directory", Some("URL"), FlagKind::Supported,
        "serve --acme: the https:// URL of the CA's ACME directory (default: Let's Encrypt's, https://acme-v02.api.letsencrypt.org/directory)", None),
    row(None, "port-file", Some("FILE"), FlagKind::Supported,
        "serve: write the port that it listens on to FILE, for --listen ADDR:0", None),
    row(None, "mint", Some("WHO"), FlagKind::Supported,
        "serve: who may mint a token at /v1/mint and make a pair at /v1/pair: anyone; keys:FILE, the keys of FILE (the format of podssh node --allow), each by its signature of the relay's challenge; or nobody (the default: 503, and tokens are given another way)", None),
    row(None, "allow-private", None, FlagKind::Supported,
        "serve: dial private, loopback and other non-public addresses too (by default only public targets, as the default relay)", None),
    row(None, "keepalive", Some("SECONDS"), FlagKind::Supported,
        "serve: send each client an empty frame every SECONDS (default 25)", None),
    row(None, "pairs", Some("FILE"), FlagKind::Supported,
        "serve: keep the pairs of the reverse road in FILE, of mode 0600, so that they outlive a restart (the digests of their tokens, never a token)", None),
];

/// **`proxy`.** It is **not an SSH client** (`podssh man proxy`), so not an alias of `ssh`,
/// and behaves differently, so it gets its own flag list rather than sharing
/// `ssh`'s. Sharing them is exactly how the nested-SSH mistake (an SSH client
/// as OpenSSH's ProxyCommand) gets invited.
#[rustfmt::skip]
pub const PROXY_FLAGS: &[FlagRow] = &[
    row(None, "stdin-stdout", None, FlagKind::Supported,
        "a byte pipe on stdin/stdout; not an SSH client", None),
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to try in order, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-failover", Some("MODE"), FlagKind::Supported,
        "how the relay hosts are tried: staggered (the next starts after 2 s or a failure; the default), parallel or serial; also env PODSSH_RELAY_FAILOVER", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    super::forwarder::PROXY_FORWARDER,
    super::shadowsocks::PROXY_SHADOWSOCKS,
    super::vless::PROXY_VLESS,
    super::via::VIA, super::via::VIA_AUTH_FILE, super::via::WSTUNNEL, super::via::WSTUNNEL_SECRET_FILE,
    // The exit of the net (T-431).
    super::node::PROXY_EXIT, super::node::PROXY_CLIENT_KEY,
    // The warning before the relay's idle cut (T-463).
    super::idle::PROXY_IDLE_WARN,
    // A node by its name, as operator reaches it (T-587).
    super::node::PROXY_PAIR_FILE, super::node::PROXY_NODE_KEY, super::node::PROXY_NO_E2E,
    super::node::PROXY_DEADLINE,
    // The bound on the open of each road (T-589).
    super::operator::PROXY_CONNECT_TIMEOUT,
];

/// `doctor` checks the relay path `ssh` and `proxy` would take, so it takes
/// their relay settings.
#[rustfmt::skip]
pub const DOCTOR_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to check, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-failover", Some("MODE"), FlagKind::Supported,
        "how the relay hosts are tried: staggered (the next starts after 2 s or a failure; the default), parallel or serial; also env PODSSH_RELAY_FAILOVER", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "json", None, FlagKind::Supported,
        "write the report as one JSON object on stdout, when every check has run", None),
    row(None, "full", None, FlagKind::Supported,
        "also log in to github.com through the relay with a key made for the check, which GitHub refuses, and, with no \
         proxy set, make a QUIC handshake with the quick tunnel's edge", None),
    row(None, "hop", Some("[USER@]HOST[:PORT]"), FlagKind::Supported,
        "check only this host and a first hop of -J as --direct reaches it: the connection through HTTPS_PROXY with the \
         server's banner, its host key, and the methods that it offers to a key made for the check", None),
    super::forwarder::DOCTOR_FORWARDER,
    super::shadowsocks::DOCTOR_SHADOWSOCKS,
    super::vless::DOCTOR_VLESS,
    super::via::DOCTOR_VIA, super::via::VIA_AUTH_FILE,
];

/// `status`: the relay settings that it reports, as `doctor` takes them.
#[rustfmt::skip]
pub const STATUS_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to report, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
];
