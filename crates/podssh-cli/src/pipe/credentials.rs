//! The credentials of `http-listen:` (T-367): `USER:PASSWORD`, one a line,
//! in a private file that the user names with `--proxy-auth-file`, read as a
//! pair's file is: a regular file of this user that nobody else can read. A
//! client gives one in `Proxy-Authorization: Basic` (RFC 7617). Only the
//! SHA-256 of each is kept, and a client's is compared with each of them in
//! constant time, so that neither the time of a refusal nor a copy in memory
//! tells a password.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;

/// The flag that names the file.
pub const FLAG: &str = "--proxy-auth-file";

/// The credentials that a proxy admits.
pub struct Credentials {
    digests: Vec<[u8; 32]>,
    /// The file, for podssh's own lines; never its contents.
    pub file: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({} of {})", self.digests.len(), self.file)
    }
}

impl Credentials {
    /// The credentials of the private file at `path`: a line of a comment
    /// (`#`) or blanks is skipped, each other line is `USER:PASSWORD`, with
    /// no `:` in USER, and the blanks at its ends are not a part of it.
    pub fn read(path: &str) -> Result<Credentials, Refusal> {
        let text = podssh_relay::cache::read_private(std::path::Path::new(path))
            .map_err(|e| Refusal::config(format!("{FLAG}: {e}")))?;
        Credentials::parse(&Zeroizing::new(text), path)
    }

    /// The credentials of `text`, a file's, which `file` names.
    pub fn parse(text: &str, file: &str) -> Result<Credentials, Refusal> {
        let mut digests: Vec<[u8; 32]> = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fits = line.split_once(':').is_some_and(|(user, _)| !user.is_empty());
            if !fits || line.chars().any(char::is_control) {
                let at = n + 1;
                return Err(Refusal::config(format!("{FLAG}: {file}: line {at} is not USER:PASSWORD")));
            }
            digests.push(Sha256::digest(line.as_bytes()).into());
        }
        if digests.is_empty() {
            return Err(Refusal::config(format!("{FLAG}: {file} holds no line USER:PASSWORD")));
        }
        Ok(Credentials { digests, file: file.to_string() })
    }

    /// Whether `header`, a request's `Proxy-Authorization`, gives one of the
    /// credentials. Each is compared, also after a match, with no branch on
    /// a byte of it.
    pub fn admit(&self, header: Option<&str>) -> bool {
        let Some(given) = header.and_then(basic) else { return false };
        let given: [u8; 32] = Sha256::digest(given.as_slice()).into();
        let mut found = 0u8;
        for digest in &self.digests {
            found |= u8::from(same(digest, &given));
        }
        std::hint::black_box(found) == 1
    }
}

/// The credentials of a header `Basic TOKEN`, decoded: the scheme in any
/// case (RFC 9110 section 11.1), the token with its padding or without.
fn basic(header: &str) -> Option<Zeroizing<Vec<u8>>> {
    let (scheme, token) = header.trim().split_once([' ', '\t'])?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT.decode(token.trim()).ok()?;
    Some(Zeroizing::new(decoded))
}

/// Whether two digests are the same, in a time that depends on neither.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let differ = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(differ) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(credential: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(credential))
    }

    #[test]
    fn a_client_is_admitted_by_any_line_and_refused_without_one() {
        let text = "# who may use the proxy\n\ntester:a long secret\n  npm:p:with:colons  \r\n";
        let credentials = Credentials::parse(text, "creds").unwrap();
        assert!(credentials.admit(Some(&header("tester:a long secret"))));
        assert!(credentials.admit(Some(&header("npm:p:with:colons"))));
        assert!(credentials.admit(Some("basic dGVzdGVyOmEgbG9uZyBzZWNyZXQ")), "no padding, any case");
        for wrong in ["tester:a long secre", "tester:a long secret ", "Tester:a long secret", "npm:p", ""] {
            assert!(!credentials.admit(Some(&header(wrong))), "{wrong:?}");
        }
        assert!(!credentials.admit(None));
        assert!(!credentials.admit(Some("Bearer dGVzdGVyOmEgbG9uZyBzZWNyZXQ=")));
        assert!(!credentials.admit(Some("Basic not*base64")));
        assert!(!credentials.admit(Some("Basic")));
        assert!(!format!("{credentials:?}").contains("secret"));
    }

    #[test]
    fn a_line_that_is_not_user_password_or_a_file_with_none_is_refused() {
        for bad in ["no colon here\n", ":no user\n", "a:b\u{7}\n", "# a comment alone\n", ""] {
            let refusal = Credentials::parse(bad, "creds").unwrap_err();
            assert_eq!(refusal.code, 78, "{bad:?}");
            assert!(!refusal.message.contains("no user"), "the line itself is never shown: {}", refusal.message);
        }
    }
}
