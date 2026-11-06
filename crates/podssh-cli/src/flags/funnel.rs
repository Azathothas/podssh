//! The flag rows of `funnel` (T-180): a local HTTP service at a public
//! `https://` name, through a quick tunnel that podssh makes itself.

use super::{row, FlagKind, FlagRow};

/// `funnel`.
#[rustfmt::skip]
pub const FUNNEL_FLAGS: &[FlagRow] = &[
    row(None, "tunnel-token-file", Some("FILE"), FlagKind::Supported,
        "a named tunnel of your own Cloudflare account, by the token in FILE, at the names that the account routes to it, in place of a new NAME.trycloudflare.com; the token goes in no line", None),
    row(None, "warp", None, FlagKind::Supported,
        "reach Cloudflare's edge inside WARP's tunnel first, for a host whose way out does not reach port 7844 (a build with WARP's road)", None),
];
