//! The flag rows of grants used once (T-226): a client's `--grant FILE` on
//! `operator`, `proxy`, `ssh` and `pipe`, each in its words; a node's
//! `--grant-to KEY`, which mints one with its own key, with its route and
//! its life, and `--revoked FILE`; and `relay pair --once`, a connect token
//! that takes one upgrade.

use super::{row, FlagKind, FlagRow};

/// `--grant FILE` of `operator`.
pub const OPERATOR_GRANT: FlagRow = row(None, "grant", Some("FILE"), FlagKind::Supported,
    "a grant used once, an OpenSSH certificate of this operator's key (KEY-cert.pub of ssh-keygen -s, or of podssh node --grant-to), which the end-to-end channel carries to the node, never a relay; it lets in one session, once, of the node or route that it names; a URL is refused", None);
/// `--grant FILE` of `proxy node://NAME`, as `operator` takes it.
pub const PROXY_GRANT: FlagRow = row(None, "grant", Some("FILE"), FlagKind::Supported,
    "node://NAME: a grant used once, as operator --grant takes it: one session, once, in the end-to-end channel", None);
/// `--grant FILE` of `ssh node://NAME`.
pub const SSH_GRANT: FlagRow = row(None, "grant", Some("FILE"), FlagKind::Supported,
    "node://NAME: a grant used once, an OpenSSH certificate of this client's key, which the end-to-end channel carries to the node for this session alone; a URL is refused", None);
/// `--grant FILE` of `pipe`'s `node:` side.
pub const PIPE_GRANT: FlagRow = row(None, "grant", Some("FILE"), FlagKind::Supported,
    "node:: a grant used once, as operator --grant takes it, for the first session of the side alone", None);

/// `--grant-to KEY` of `node`, and its route and life.
pub const NODE_GRANT_TO: FlagRow = row(None, "grant-to", Some("KEY"), FlagKind::Supported,
    "print a grant used once for KEY on stdout, an OpenSSH user certificate that the node's own key signs, and serve nothing: KEY is the operator's key, ssh-ed25519 BASE64, its 64 hex digits, or a file of one line; the node's key is read, never made", None);
pub const NODE_GRANT_ROUTE: FlagRow = row(None, "grant-route", Some("ROUTE"), FlagKind::Supported,
    "with --grant-to: the grant names ROUTE of the node, node://NAME/ROUTE, in place of its TARGET with no route", None);
pub const NODE_GRANT_FOR: FlagRow = row(None, "grant-for", Some("TIME"), FlagKind::Supported,
    "with --grant-to: the grant's window, from now: 90s, 30m, 8h or 3d, from 1 minute to 30 days (default 1h)", None);
/// `--revoked FILE` of `node`.
pub const NODE_REVOKED: FlagRow = row(None, "revoked", Some("FILE"), FlagKind::Supported,
    "the grants that the node refuses: a serial on each line, or a fingerprint and a serial, read again for each grant; a file that is missing lets no grant in", None);

/// `--once` of `relay pair`.
pub const RELAY_ONCE: FlagRow = row(None, "once", None, FlagKind::Supported,
    "pair: ask the relay for a connect token that takes one upgrade alone, one operator's session with no resume, which podssh relay serve offers; a relay that makes none is said so (69), and its pair stopped", None);
