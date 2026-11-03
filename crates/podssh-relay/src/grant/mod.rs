//! Grants used once (T-226, GitHub #35). A grant is an OpenSSH user
//! certificate over an operator's Ed25519 key: an issuer that the node
//! trusts signs it for one session of one node, or of one route of it, in a
//! window of time, with the critical option `once@podssh`. `ssh-keygen -s`
//! of OpenSSH mints one, and so does `podssh node NAME --grant-to KEY` with
//! the node's own key ([`Mint`]).
//!
//! The grant travels inside the end-to-end channel, encrypted, after the
//! node proved its key (`crate::e2e`), so no relay and no URL ever holds
//! it. The node checks it before it dials ([`Door`]): the key that the
//! channel proved is the certificate's, so a grant that leaks is worth
//! nothing without that key; then the issuer, the node, the window and each
//! critical option; and last the record of its use ([`Spent`]), written and
//! synced before the node lets the operator in, so that a second use of the
//! same grant is refused, also after a restart. A resume of the layer runs
//! no new handshake, so a used grant ends no session that it opened.

pub mod cert;
mod door;
mod spent;

use std::path::Path;

pub use cert::{openssh_public, parse_public, Cert, Mint, CERT_TYPE, HOST, USER};
pub use door::{Door, Issuers, Redeemed};
pub use spent::{NotRecorded, Spent};

use crate::identity::PublicKey;

/// The critical option of a grant: it is used once.
pub const ONCE: &str = "once@podssh";
/// The skew of the clocks that a window allows at each of its ends.
pub const SKEW_SECS: u64 = 5 * 60;
/// The largest grant that the channel carries; an Ed25519 certificate with a
/// few principals is about 300 bytes.
pub const MAX_GRANT: usize = crate::e2e::MAX_GRANT;
/// The prefix of a grant's principal: `node:` and the node's fingerprint.
pub const PRINCIPAL_PREFIX: &str = "node:";

/// The principal of a grant for the node `node`, and for its route `route`
/// when one is named: `node:SHA256:...` or `node:SHA256:.../ROUTE`.
pub fn principal(node: &PublicKey, route: Option<&str>) -> String {
    match route {
        Some(route) => format!("{PRINCIPAL_PREFIX}{}/{route}", node.fingerprint()),
        None => format!("{PRINCIPAL_PREFIX}{}", node.fingerprint()),
    }
}

/// Whether `word` names a URL, never a file: a grant goes in the channel,
/// and a URL would put it in a request line, a proxy's log and a history.
pub fn looks_like_url(word: &str) -> bool {
    let lower = word.trim().to_ascii_lowercase();
    ["http://", "https://", "ws://", "wss://", "ftp://", "file://"].iter().any(|s| lower.starts_with(s))
        || lower.contains("?grant=")
        || lower.contains("&grant=")
}

/// The grant in the file at `path`: its first line that is no comment, as
/// `ssh-keygen -s` writes `KEY-cert.pub`, read and checked for its form.
/// A URL is refused before anything is read. A certificate is public, and
/// worth nothing without its key, so the file may be one that others read.
pub fn read_file(path: &Path) -> Result<Cert, String> {
    let shown = path.display();
    if looks_like_url(&path.to_string_lossy()) {
        return Err(format!("{shown}: a grant is a file, never a URL: it goes in the end-to-end channel alone"));
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    // A line of base64 for each certificate: a file much larger is no grant.
    if meta.len() > (4 * MAX_GRANT) as u64 {
        return Err(format!("{shown} is larger than a grant can be"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
    Cert::from_text(&text).map_err(|why| format!("{shown}: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_principal_names_the_node_by_its_fingerprint_and_the_route_after_it() {
        let node = PublicKey([7; 32]);
        let fp = node.fingerprint();
        assert_eq!(principal(&node, None), format!("node:{fp}"));
        assert_eq!(principal(&node, Some("web")), format!("node:{fp}/web"));
    }

    #[test]
    fn a_url_is_never_a_grant_s_file() {
        for word in ["https://relay.example/g", "WSS://h/x", "lab?grant=AAAA", "a&grant=b", " http://x"] {
            assert!(looks_like_url(word), "{word}");
        }
        for word in ["grant-cert.pub", "/home/u/.ssh/id-cert.pub", "C:\\grants\\lab.pub", "https-cert.pub"] {
            assert!(!looks_like_url(word), "{word}");
        }
        let refused = read_file(Path::new("https://relay.example/grant")).unwrap_err();
        assert!(refused.contains("never a URL"), "{refused}");
    }
}
