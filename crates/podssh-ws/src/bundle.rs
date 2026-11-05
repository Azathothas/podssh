//! Where the CA bundle is, resolved from `/proc/self/exe` and never `argv[0]`.
//! The PEM reader of a bundle is `pod-tls`'s.
//!
//! **`argv[0]` is where the binary was *launched from*, not where it *is*.**
//! A binary started through `PATH`, through a symlink in `/usr/bin`, or by an
//! absolute path from another directory resolves a different bundle in each
//! case. The sibling project made exactly this mistake, and
//! its own record of the toolchain names three tools that it broke —
//! `ld.lld`, `zig`, `node`/`bun` — because of it.
//!
//! **A missing bundle is `Failed`, with the path in the message.** It is
//! never a silent fallback to a compiled-in set and never an empty store: an
//! empty `RootCertStore` rejects every chain, and it does so with a message
//! that reads like a network fault.

use std::path::PathBuf;

pub use pod_tls::bundle::{load_bundle, parse_bundle, pem_certificates};

/// The name of the file podssh looks for beside the executable. A single
/// name, so a deployment either has a bundle or does not, and the doctor can
/// say which.
pub const BUNDLE_FILE_NAME: &str = "podssh-ca.pem";

/// **Windows has no `/proc/self/exe`.** `std::env::current_exe` reads the
/// same fact through the platform's own mechanism on every target, and it
/// resolves symlinks on Linux. Naming the file literally here would make this
/// module a Linux-only one inside a multi-platform client.
pub fn executable_path() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("cannot read this process's own path: {e}"))
}

/// The default bundle path: beside the executable, named [`BUNDLE_FILE_NAME`].
pub fn default_bundle_path() -> Result<PathBuf, String> {
    let exe = executable_path()?;
    let dir =
        exe.parent().ok_or_else(|| format!("{} has no parent directory to hold {BUNDLE_FILE_NAME}", exe.display()))?;
    Ok(dir.join(BUNDLE_FILE_NAME))
}
