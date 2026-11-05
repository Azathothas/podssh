//! The file of the TLS groups that servers took (T-664): podssh-ws keeps the
//! groups (`podssh_ws::tls::groups`), and this crate knows where the cache
//! is. `pod_tls::groups::Dirs` keeps a private file of the cache, as
//! [`crate::addresses::FILE`] is: mode 0600 in a directory of this user's,
//! and one that others can read is not read. It holds names and group
//! numbers, and no secret.

use std::sync::Once;

use podssh_ws::tls::groups::{self, Dirs};

/// The file, in the cache.
pub use podssh_ws::tls::groups::FILE;

static INSTALLED: Once = Once::new();

/// Give the process's TLS configurations the file of the cache, once a run:
/// with the addresses of the cache, before any dial ([`crate::addresses::install`]).
pub fn install() {
    INSTALLED.call_once(|| {
        groups::keep_in(Box::new(Dirs(crate::cache::candidate_dirs())));
    });
}
