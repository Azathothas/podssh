//! The flag rows of `chat` (T-099): the two sides of a road, the end-to-end
//! channel's keys at each (T-087, T-088), and the one thing of a script.
//! There is no `--no-e2e`: chat always runs the channel.

use super::{row, FlagKind, FlagRow};

/// **`chat` and its `irc` alias.** `--jsonl` and `--timeout` feed the gate of
/// runs with no terminal; the side that waits names the pair with `--listen`.
#[rustfmt::skip]
pub const CHAT_FLAGS: &[FlagRow] = &[
    row(None, "listen", None, FlagKind::Supported,
        "wait for the peer: serve the pair PEER as its node, one peer at a time", None),
    row(None, "send", Some("MESSAGE"), FlagKind::Supported,
        "send one message, and exit once the peer acknowledged it; never prompts", None),
    row(None, "sendfile", Some("FILE"), FlagKind::Supported,
        "send each line of FILE as a message, in place of stdin, and exit once each is acknowledged", None),
    row(None, "file", Some("PATH"), FlagKind::Supported,
        "offer the file at PATH, and exit once it arrived whole", None),
    row(None, "accept-dir", Some("DIR"), FlagKind::Supported,
        "accept each file that the peer offers, into DIR, for a script (default: each file waits for /accept)", None),
    row(None, "nick", Some("NICK"), FlagKind::Supported,
        "the name that the peer sees, 64 bytes at most (default: env USER, else USERNAME, else podssh)", None),
    row(None, "jsonl", None, FlagKind::Supported,
        "one JSON object per event on stdout", None),
    row(None, "timeout", Some("DURATION"), FlagKind::Supported,
        "bound the run; required when stdin is not a TTY (default: env PODSSH_TIMEOUT)", None),
    row(None, "key", Some("FILE"), FlagKind::Supported,
        "with --listen: this side's key in FILE, made when missing (default: node-NAME.key in the cache); its fingerprint is said as it starts", None),
    row(None, "ephemeral-key", None, FlagKind::Supported,
        "with --listen: a new key for this run only, kept in no file; a peer that pinned the old key refuses it", None),
    row(None, "allow", Some("FILE"), FlagKind::Supported,
        "with --listen: the keys that may come in, one key or fingerprint on each line, read again for each peer (default: each peer with the pair's connect token)", None),
    row(None, "client-key", Some("FILE"), FlagKind::Supported,
        "this side's key in FILE when it reaches the peer, made when missing (default: client.key in the cache), which the peer's allowlist may name", None),
    row(None, "node-key", Some("KEY"), FlagKind::Supported,
        "the key of the side that waits, or its fingerprint SHA256:..., in place of the pins of known-nodes", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "use the pair in FILE, a private file, not the one stored under NAME (to reach the peer, its operator's part will do)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "iroh", None, FlagKind::Supported,
        "with --listen: serve the iroh road too, and print its ticket, which the peer reaches as iroh:TICKET; a build with the feature iroh", None),
    row(None, "iroh-relay", Some("URLS"), FlagKind::Supported,
        "the iroh relays, https://HOST[:PORT][,...]; the first that answers is the home relay (default: env PODSSH_IROH_RELAY, else n0's)", None),
];
