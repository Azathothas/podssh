//! E12 and E13's shared test fixtures.
//!
//! ⛔ **Every value in here was produced by a real tool on this machine, and
//! that is the only reason it is in a file rather than inline.** ⛔ An earlier
//! version of `tests/known_hosts.rs` carried the keys as constants *and* the
//! fixture file that used them, and the two copies drifted far enough that
//! ⛔ **18 of 21 tests failed on a fabricated key** ⛔ — a "changed" key that was
//! two characters appended to a real RSA blob and was ⛔ not base64 at all.
//! ⛔ One place per value is the fix, and this is it.
//!
//! ⛔ **No private key is here, and no token is here.** ⛔ Only `.pub` lines,
//! and ⛔ the token-shaped strings carry an all-zero MAC ⛔ because
//! `docs/TODO/security/tokens.md` records that two research agents minted live
//! credentials while building this repository's evidence base.

#![allow(dead_code)] // each test file uses a subset; a shared harness is expected.

use base64::Engine as _;
use podssh_cli::security::fingerprint::{parse_field, PublicKey};

/// ⛔ `ssh-keygen -t ed25519 -N '' -C 'podssh-e13-fixture' -f hk_ed25519`.
///
/// ⛔ **MEASURED 2026-10-02, this machine (Git Bash on Windows),
/// OpenSSH_10.3p1**, and `ssh-keygen -lf` on the `.pub`:
/// ⛔ `256 SHA256:4O3mcGjDJyHK7YSiDsALEFjJld1EqknjJ10Dhyc1hTg`.
/// ⛔ **The comment on the end is not decoration**: it is what
/// `ssh-keygen -C` writes, and ⛔ it is why a parser that refuses a third field
/// cannot read a single key this repository is made of.
pub const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU podssh-e13-fixture";
pub const ED25519_FP: &str = "SHA256:4O3mcGjDJyHK7YSiDsALEFjJld1EqknjJ10Dhyc1hTg";

/// ⛔ `ssh-keygen -t rsa -b 2048 -m PEM -N '' -C 'podssh-e13-fixture' -f hk_rsa`.
///
/// ⛔ **MEASURED 2026-10-02, same host and command**, `ssh-keygen -lf`:
/// ⛔ `2048 SHA256:Ltx3kMIiAnz4aWwbRKpcm97NN7yA5Y8TKDnTZpBEYDs`.
/// ⛔ **An RSA blob is `string name`, `mpint e`, `mpint n`** ⛔ and a parser
/// that reads a second *string* takes the 3-byte exponent and loses the
/// modulus. ⛔ That bug was in podssh's own decoder and the fingerprint it
/// produced is in `docs/TODO/security/host-keys.md`.
pub const RSA_A: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUsEgykBCciXnieg9lY+obR1NEVF8GZpUb1b4OywhI3AMXOVK9QAfJsFtDiI/Ryivm3gVlBCgbPvcErvSnqj11O2E1qF4wGYLUByRjGjCq6r4epKE8Dw/cLZUJ7UGqKcNV3je8U1Ozl74uZYSmZnSE3K2C97VWnCcp69r5JYyqFYmDBOe8oQCE4TKXrsz3FP0dU46BhAhcWThuTzkl5OhsWTtr3plx3B31OAjanOA+EloYdIqkwsy7wGchy5rv0zAJnNBZaoHKodD9XKkUMv/PRXMaTVzuYqBtNw0cywCjmFDpDh9OH/2uVKHm7HYHEG9azWNjSgOHIhWnieJSW9NT podssh-e13-fixture";
pub const RSA_A_FP: &str = "SHA256:Ltx3kMIiAnz4aWwbRKpcm97NN7yA5Y8TKDnTZpBEYDs";

/// ⛔ A **second, real** ed25519 key: `ssh-keygen -t ed25519 -N '' -C
/// 'podssh-hashed-fixture' -f kh2`, then `-H` on a `known_hosts` line naming
/// `github.com`.
///
/// ⛔ `ssh-keygen -lf` on its `.pub`: ⛔
/// `256 SHA256:gH97A7eMM4f85HmlmoVxpeXtdYxzwieBVdbPrUUNEEA github.com (ED25519)`.
///
/// ⛔ **The "changed key" plant is this key, not a doctored copy of another.**
/// ⛔ A planted key has to be a key the same way, or the plant proves nothing
/// about the code and everything about the fixture.
pub const CHANGED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOX/mVzEsJGjGIDTByXMDQpiwHNyiN2iHWeAC79l0I0U";
pub const CHANGED_FP: &str = "SHA256:gH97A7eMM4f85HmlmoVxpeXtdYxzwieBVdbPrUUNEEA";

/// ⛔ The line `ssh-keygen -H` wrote for `github.com`, verbatim, with the salt
/// `7VxMAYCtkkfcxLDU4i9dktuD4hM=`.
///
/// ⛔ **MEASURED, and this is the measurement that settles the algorithm.**
/// ⛔ For that salt and the name `github.com`:
/// ⛔ `printf '%s' 'hostkey' | openssl dgst -sha1 -hmac <salt-b64> -binary` and
/// ⛔ OpenSSH's own file both give `vWs7gM52cv1zvZLddNKcOSlslOQ=`, and SHA-256
/// ⛔ over the same input gives something else entirely. ⛔ **The hash is SHA-1**,
/// ⛔ and a reader who \u201cimproved\u201d it to SHA-256 would match nothing.
pub const HASHED_ED25519: &str = "|1|7VxMAYCtkkfcxLDU4i9dktuD4hM=|vWs7gM52cv1zvZLddNKcOSlslOQ= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOX/mVzEsJGjGIDTByXMDQpiwHNyiN2iHWeAC79l0I0U";

/// ⛔ **The file the tests read.** ⛔ Every line is OpenSSH's spelling and the
/// line numbers are load-bearing ⛔ `Prove` names the line, and the tests name
/// them in assertions.
///
/// | line | what it is | the control it gives |
/// | --- | --- | --- |
/// | 1 | a comment | ⛔ comments are not entries and do not shift the numbering |
/// | 2 | `github.com`, unhashed, `ED25519` | the plain match |
/// | 3 | `example.com:2222`, `RSA_A` | ⛔ a host **with a port** is its own name |
/// | 4 | `github.com`, hashed, `CHANGED` | ⛔ the hash matches and the key is ⛔ **different** |
/// | 5 | `h1.example,h2.example`, `ED25519` | a comma list |
pub const FILE: &str = "\
# podssh E13 fixture
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
example.com:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUsEgykBCciXnieg9lY+obR1NEVF8GZpUb1b4OywhI3AMXOVK9QAfJsFtDiI/Ryivm3gVlBCgbPvcErvSnqj11O2E1qF4wGYLUByRjGjCq6r4epKE8Dw/cLZUJ7UGqKcNV3je8U1Ozl74uZYSmZnSE3K2C97VWnCcp69r5JYyqFYmDBOe8oQCE4TKXrsz3FP0dU46BhAhcWThuTzkl5OhsWTtr3plx3B31OAjanOA+EloYdIqkwsy7wGchy5rv0zAJnNBZaoHKodD9XKkUMv/PRXMaTVzuYqBtNw0cywCjmFDpDh9OH/2uVKHm7HYHEG9azWNjSgOHIhWnieJSW9NT
|1|7VxMAYCtkkfcxLDU4i9dktuD4hM=|vWs7gM52cv1zvZLddNKcOSlslOQ= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOX/mVzEsJGjGIDTByXMDQpiwHNyiN2iHWeAC79l0I0U
h1.example,h2.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
";

/// ⛔ A token of the shape the relay mints, ⛔ **with a zero MAC and a date past
/// any relay's lifetime**, so it is not a credential for anything.
pub const SYNTHETIC: &str = "ephm1.1900000000000.forward.0000000000000000000000";
/// ⛔ A second one, for a test that needs two and asserts that neither reaches
/// the output.
pub const SYNTHETIC_2: &str = "ephm1.1900000000001.reverse.1111111111111111111111";

/// Parse one of the keys above, and ⛔ panic with the line that failed so a
/// broken fixture names itself.
pub fn key(line: &str) -> PublicKey {
    parse_field(line).unwrap_or_else(|e| panic!("{line:?} should parse: {e}"))
}

/// ⛔ The `alg base64` field of an existing key, re-encoded from its own blob.
/// ⛔ Used where a test needs a `@revoked` or `@cert-authority` line and must
/// ⛔ **not** invent a base64 body.
pub fn field_of(k: &PublicKey) -> String {
    k.to_known_hosts_field()
}

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// ⛔ A `known_hosts` line carrying `key` for `host`, with a marker if asked.
pub fn line_for(marker: &str, host: &str, k: &PublicKey) -> String {
    format!("{marker}{host} {}\n", field_of(k))
}

/// ⛔ **A filesystem that is whatever the test says it is.** ⛔ `E13` and `E12`
/// both walk a chain of candidate paths and take the first that opens, and
/// ⛔ **probing a real `/dev/shm` on Windows is probing Windows** — ⛔ a test that
/// ⛔ silently measured the wrong host is the defect this repository has shipped
/// ⛔ once. ⛔ So the environment is a value.
pub struct FakeEnv {
    pub vars: Vec<(&'static str, String)>,
    /// ⛔ Path **prefixes** that answer `Ok(())` to an append, and ⛔ everything
    /// ⛔ else answers with the message `SystemEnv` uses for a missing directory,
    /// ⛔ so the chain's two failure branches are both reachable.
    pub writable: Vec<&'static str>,
    pub cwd: &'static str,
}

impl podssh_cli::security::chain::Environment for FakeEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.vars
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }
    fn current_dir(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(self.cwd)
    }
    fn try_append(&self, path: &std::path::Path) -> Result<(), String> {
        // ⛔ **Normalise the separator before matching.** MEASURED 2026-10-02,
        // this host, Git Bash on Windows: `Path::new("/home/op").join(".ssh")`
        // yields `/home/op\.ssh` — a backslash — so a fixture written with POSIX
        // separators never matches, `resolve_path` walks every candidate and
        // falls through to `None`, and the test fails for a reason that has
        // nothing to do with the chain it is testing. ⛔ The code under test is
        // correct and Linux builds this crate in the gate; ⛔ the *fixture* is
        // what has to be host-agnostic, and matching on a separator-normalised
        // string is what makes it so.
        let s = path.to_string_lossy().replace('\\', "/");
        if self.writable.iter().any(|w| s.starts_with(w)) {
            Ok(())
        } else {
            Err(format!("no such directory: {s}"))
        }
    }
}

/// ⛔ `base64`-decode a fixture constant, and panic with the value that failed
/// ⛔ so a broken fixture names itself rather than producing a wrong MAC.
pub fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_else(|e| panic!("{s:?} should be base64: {e}"))
}
