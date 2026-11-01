//! The flag rows of `update` (T-375): only a check, a release named, the
//! trust of TLS to GitHub, and the way back to the binary before (T-396).

use super::{row, FlagKind, FlagRow};

/// **`update`.** The release for this binary's target, checked against
/// its signed `SHA256SUMS`, in place of this binary.
#[rustfmt::skip]
pub const UPDATE_FLAGS: &[FlagRow] = &[
    row(None, "check", None, FlagKind::Supported,
        "only say what an update would do: the release, its signature checked, and the file it would replace", None),
    row(None, "version", Some("TAG"), FlagKind::Supported,
        "this release, as v1.0.0-beta.3, older than this build too; default: the newest, a prerelease only if this build is one", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CAs in this PEM file for TLS to GitHub (default: SSL_CERT_FILE, else CaFile, else the system's)", None),
    row(None, "rollback", None, FlagKind::Supported,
        "put back the binary that the last update kept beside this one (podssh.prev), once it ran here, and keep this one in its place; no network", None),
];
