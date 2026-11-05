//! podssh's places as the files of `pod-core` (PodUtils/podcrates) read them.

use super::DIR_ENV;

/// podssh's app for the files of `pod-core` (PodUtils/podcrates).
pub const POD_APP: pod_core::files::App<'static> = pod_core::files::App { name: "podssh", dir_env: DIR_ENV };

/// podssh's places as `pod-core` reads them, for `pod-identity`.
pub fn pod_places() -> pod_core::files::Places {
    pod_core::files::places_from(&POD_APP, &|name| std::env::var_os(name), std::env::current_dir().ok())
}
