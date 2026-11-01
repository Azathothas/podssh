//! The rows of `--forwarder` (T-369): for `ssh` and each command that
//! reaches its server as `ssh` does, for `proxy`, and for `doctor`, which
//! checks them.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each` and the others of `ssh`'s road.
pub const FORWARDER: FlagRow = row(None, "forwarder", Some("TEMPLATES"), FlagKind::Supported,
    "reach the first hop through other products' WebSocket forwarders, in order, in place of the relay: ws:// or \
     wss:// URLs with {host} and {port} once each, or neither for a first frame of JSON; also env PODSSH_FORWARDER", None);

/// `proxy`.
pub const PROXY_FORWARDER: FlagRow = row(None, "forwarder", Some("TEMPLATES"), FlagKind::Supported,
    "reach the target through other products' WebSocket forwarders, in order, in place of the relay: ws:// or \
     wss:// URLs with {host} and {port} once each, or neither for a first frame of JSON; also env PODSSH_FORWARDER", None);

/// `doctor`.
pub const DOCTOR_FORWARDER: FlagRow = row(None, "forwarder", Some("TEMPLATES"), FlagKind::Supported,
    "also check these forwarders: the upgrade, then one of GitHub's published host keys on github.com port 22 \
     through each (default: env PODSSH_FORWARDER, else Forwarder of the settings file)", None);
