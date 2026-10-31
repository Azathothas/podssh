//! The logins of a password (T-371): a user named `pass-...` logs in with
//! [`PASSWORD`] alone, as a hop of `-J` whose password comes from
//! `SSH_ASKPASS`; `pass-nofwd-...` also refuses each direct-tcpip channel,
//! as a server with `AllowTcpForwarding no` does.

use russh::server::Auth;
use russh::{MethodKind, MethodSet};

/// The one password that the server takes.
#[allow(dead_code)]
pub const PASSWORD: &str = "hop-password";

/// The answer to `none` for `user`: a password, for a `pass-` user.
pub(super) fn none(user: &str) -> Option<Auth> {
    user.starts_with("pass-").then(|| Auth::Reject {
        proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
        partial_success: false,
    })
}

/// The answer to a password of `user`.
pub(super) fn password(user: &str, password: &str) -> Auth {
    if user.starts_with("pass-") && password == PASSWORD {
        Auth::Accept
    } else {
        Auth::reject()
    }
}

/// Whether `user` refuses forwarding.
pub(super) fn refuses_forwarding(user: &str) -> bool {
    user.starts_with("pass-nofwd-")
}
