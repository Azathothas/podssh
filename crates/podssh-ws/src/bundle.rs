//! Where the CA bundle is, resolved from `/proc/self/exe` and never `argv[0]`.
//!
//! **`argv[0]` is where the binary was *launched from*, not where it *is*.**
//! A binary started through `PATH`, through a symlink in `/usr/bin`, or by an
//! absolute path from another directory resolves a different bundle in each
//! case. The sibling project made exactly this mistake, and
//! `docs/decisions/toolchain-contract.md:82-93` names three tools it broke —
//! `ld.lld`, `zig`, `node`/`bun` — because of it.
//!
//! **A missing bundle is `Failed`, with the path in the message.** It is
//! never a silent fallback to a compiled-in set and never an empty store: an
//! empty `RootCertStore` rejects every chain, and it does so with a message
//! that reads like a network fault.

use std::path::{Path, PathBuf};

use rustls_pki_types::CertificateDer;

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

/// **A missing file and an unparseable file are different failures** and the
/// doctor reports the path in both. The path is in the error because a
/// deployment that cannot find its trust store cannot be diagnosed from "TLS
/// failed".
pub fn load_bundle(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_bundle(path, &bytes)
}

/// **The count is checked, not dropped.** "Loaded 0 certificates" is a
/// different failure from "could not read the file", and a bundle that parses
/// to nothing is a configuration error that must never read as a loaded
/// bundle — an empty `RootCertStore` would reject every chain with a message
/// that looks like a network fault.
pub fn parse_bundle(path: &Path, bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = pem_certificates(bytes).map_err(|why| format!("{}: {why}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: parsed as PEM but held no CERTIFICATE block", path.display()));
    }
    Ok(certs)
}

/// **A deliberately small PEM reader, written here rather than pulled in.**
/// A CA bundle is a sequence of `-----BEGIN CERTIFICATE-----` / base64 /
/// `-----END CERTIFICATE-----` blocks and nothing else. The alternative was a
/// dependency for forty lines, and this repository's central rule is about
/// what a build pulls in, not about saving them. The decoder is asserted
/// byte-exactly against a known certificate in the tests.
///
/// It accepts ONLY `CERTIFICATE` blocks. A `PRIVATE KEY` block in a trust
/// bundle is a key in a file that is world-readable, and a parser that
/// silently ignored it would hide that.
pub fn pem_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = std::str::from_utf8(bytes).map_err(|_| "a PEM bundle must be UTF-8 text")?;
    let mut out = Vec::new();
    // **`\r` is stripped from every line before decoding.** A PEM file
    // written on Windows carries CRLF, and `body.trim()` removes it only at the
    // two ends of the block — every interior line kept its `\r`, and the
    // decoder then rejected the whole bundle as "not valid base64". This was
    // found by a test holding a real certificate in a file this repository's
    // own line-ending rules make CRLF, not by reading the code.
    let normalised = text.replace("\r\n", "\n");
    let mut rest = normalised.as_str();

    while let Some(after_begin) = rest.find(BEGIN) {
        let body_start = after_begin + BEGIN.len();
        let Some(rel_end) = rest[body_start..].find(END) else {
            return Err("a BEGIN CERTIFICATE block has no matching END".into());
        };
        let body_end = body_start + rel_end;
        let body = &rest[body_start..body_end];

        // **Whitespace is removed before decoding.** A PEM body is one
        // base64 string wrapped at 64 columns, so it arrives with embedded
        // newlines. The first version passed it to the decoder as-is, and the
        // length check failed at once — the decoder had never been given
        // single-line input, which is why every real certificate was rejected
        // as "not valid base64" and no unit test had caught it.
        let der = base64_decode(&strip_whitespace(body))?;
        out.push(CertificateDer::from(der));
        rest = &rest[body_end + END.len()..];
    }
    Ok(out)
}

/// Every ASCII space character, and nothing else. Not `split_whitespace`,
/// which would also treat a non-ASCII byte as whitespace and let a mangled
/// bundle decode to something plausible.
fn strip_whitespace(input: &str) -> String {
    input.chars().filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c')).collect()
}

/// Standard base64 with padding, rejecting anything else. A trust bundle is
/// machine-generated, so an input that needs a lenient decoder is an input
/// that is not a trust bundle.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const INVALID: &str = "not valid base64";
    if input.len() % 4 != 0 {
        return Err(INVALID.into());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.as_bytes().chunks_exact(4) {
        let hi = base64_value(chunk[0]).ok_or(INVALID)?;
        let mid = base64_value(chunk[1]).ok_or(INVALID)?;

        out.push((hi << 2) | (mid >> 4));

        // **The padding is checked BEFORE the sextets it pads are read.**
        // The first version read all four characters first and so rejected
        // every block containing `=`, which is every block with a length that
        // is not a multiple of three — that is, most of a real certificate.
        // It was found by a test holding a real root, not by reading the code.
        if chunk[2] == b'=' {
            // `xx==` is the last block of the input: padding may not appear
            // anywhere else, and a `=` here followed by more data is a bundle
            // that is not base64.
            if chunk[3] != b'=' {
                return Err(INVALID.into());
            }
            continue;
        }
        let lo = base64_value(chunk[2]).ok_or(INVALID)?;
        out.push((mid << 4) | (lo >> 2));

        if chunk[3] == b'=' {
            continue;
        }
        let last = base64_value(chunk[3]).ok_or(INVALID)?;
        out.push((lo << 6) | last);
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
