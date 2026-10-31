//! The stores of trust that a system keeps outside files (T-340). An
//! administrator's group policy or MDM puts the root of a proxy that re-signs
//! TLS there, and no bundle of [`crate::tls::SYSTEM_BUNDLES`] holds it.
//!
//! - Windows: `ROOT` of the current user and of the machine, through crypt32.
//!   A certificate counts when Windows would let it sign for a server: its
//!   usage allows server authentication, it is valid today, and no
//!   `Disallowed` store holds it. The `CA` stores are not read: they hold
//!   intermediates, which Windows trusts only through a root, and a process
//!   of the user adds one with no prompt, where a root of the user's asks.
//! - macOS: the trust settings of the user and of the administrator, through
//!   the Security framework: a certificate that they make a root for TLS. The
//!   user's settings come first, as in the framework.
//!
//! A store that does not open is passed over with a note, never an error: the
//! compiled-in roots are always there.

use rustls_pki_types::CertificateDer;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as system;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as system;

/// Elsewhere the roots are files.
#[cfg(not(any(windows, target_os = "macos")))]
mod system {
    pub(super) fn read() -> Vec<super::Store> {
        Vec::new()
    }
}

/// One store as it was read.
#[derive(Debug, Clone, Default)]
pub struct Store {
    /// Its name, as doctor says it.
    pub name: &'static str,
    /// The certificates that it makes roots, less those of an earlier store.
    pub roots: Vec<CertificateDer<'static>>,
    /// The certificates that it holds and that are no root for TLS here.
    pub passed_over: usize,
    /// Why it gave nothing, when it could not be read.
    pub note: Option<String>,
}

/// The stores of this system, in their order; none where the system keeps its
/// roots in the files of [`crate::tls::SYSTEM_BUNDLES`].
pub fn read() -> Vec<Store> {
    system::read()
}

/// A certificate that a store holds: its DER, and whether the system lets it
/// sign for a server today.
#[cfg(any(windows, test))]
struct Held {
    der: Vec<u8>,
    for_servers: bool,
}

/// The store `name` of `held`: each certificate that signs for servers, that
/// `refused` does not hold, and that no earlier store gave (`seen`).
#[cfg(any(windows, test))]
fn sort(
    name: &'static str,
    held: Vec<Held>,
    refused: &std::collections::HashSet<Vec<u8>>,
    seen: &mut std::collections::HashSet<Vec<u8>>,
) -> Store {
    let mut store = Store { name, ..Store::default() };
    for cert in held {
        if !cert.for_servers || refused.contains(&cert.der) {
            store.passed_over += 1;
        } else if seen.insert(cert.der.clone()) {
            store.roots.push(CertificateDer::from(cert.der));
        }
    }
    store
}

/// What doctor says of `stores`: each one's name and count, or why it gave
/// nothing. None when the system has no store.
pub fn summary(stores: &[Store]) -> Option<String> {
    if stores.is_empty() {
        return None;
    }
    let each: Vec<String> = stores
        .iter()
        .map(|store| match &store.note {
            Some(note) => format!("{}: passed over, {note}", store.name),
            None if store.passed_over > 0 => {
                format!(
                    "{}: {} root(s), {} passed over as no root for TLS",
                    store.name,
                    store.roots.len(),
                    store.passed_over
                )
            }
            None => format!("{}: {} root(s)", store.name, store.roots.len()),
        })
        .collect();
    Some(each.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_names_each_store_its_count_and_a_note() {
        assert_eq!(summary(&[]), None);
        let root = CertificateDer::from(vec![0x30, 0x00]);
        let stores = [
            Store { name: "the user's", roots: vec![root.clone(), root], passed_over: 0, note: None },
            Store { name: "the machine's", roots: Vec::new(), passed_over: 3, note: None },
            Store { name: "the other", note: Some("did not open: access is denied".into()), ..Store::default() },
        ];
        assert_eq!(
            summary(&stores).as_deref(),
            Some(
                "the user's: 2 root(s); the machine's: 0 root(s), 3 passed over as no root for TLS; \
                 the other: passed over, did not open: access is denied"
            )
        );
    }

    /// A certificate whose usage leaves out servers, or that a Disallowed
    /// store holds, is passed over; one that an earlier store gave is not
    /// given twice.
    #[test]
    fn a_store_gives_the_roots_for_servers_that_no_other_refused_or_gave() {
        let held = |der: &[u8], for_servers: bool| Held { der: der.to_vec(), for_servers };
        let refused: std::collections::HashSet<Vec<u8>> = [b"refused".to_vec()].into();
        let mut seen = std::collections::HashSet::new();
        let user = sort("user", vec![held(b"a", true), held(b"b", false), held(b"refused", true)], &refused, &mut seen);
        let given: Vec<&[u8]> = user.roots.iter().map(|cert| cert.as_ref()).collect();
        assert_eq!((given, user.passed_over), (vec![&b"a"[..]], 2));
        let machine = sort("machine", vec![held(b"a", true), held(b"c", true)], &refused, &mut seen);
        let given: Vec<&[u8]> = machine.roots.iter().map(|cert| cert.as_ref()).collect();
        assert_eq!((given, machine.passed_over), (vec![&b"c"[..]], 0));
    }

    /// On a system with no store, nothing is read and nothing is said.
    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn a_system_whose_roots_are_files_has_no_store() {
        assert!(read().is_empty());
        assert_eq!(summary(&read()), None);
    }
}
