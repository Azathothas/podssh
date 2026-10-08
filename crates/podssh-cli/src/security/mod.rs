//! E12 and E13: the two credential paths.
//!
//! ⛔ **Both of these live under `podssh-cli` and nowhere else, and that is a
//! decision with a reason.** `E12`'s entry puts the token seam in
//! `crates/podssh-transport` and `E13`'s puts host keys in `podssh-core`. ⛔
//! **Neither crate is a safe home for the part that matters**: a secret wrapper
//! whose `Display` cannot print, and a trust store that refuses a wrong key,
//! are only worth having if *every* caller goes through them. A secret type
//! living in the transport would still be one `String` away in the CLI, and the
//! CLI is where a `--verbose` diagnostic gets written.
//!
//! ⛔ **This module is declared by `crates/podssh-cli/src/lib.rs` as
//! `pub mod security;`, and nothing reaches it by `#[path]` any more.** E31
//! owned that file while these modules were being written, so the first version
//! was reached as `#[path = "security/mod.rs"] mod security;` and this header
//! said so. ⛔ **The attributes came out the moment `lib.rs` named the module**,
//! which is what this paragraph promised: leaving a `#[path]` in place after it
//! stops being necessary is a second read path for the same code, and two read
//! paths drift. If a `#[path]` reappears anywhere in this crate, this is the
//! paragraph that says it should not have.
//!
//! | module | entry | holds |
//! | --- | --- | --- |
//! | [`token`] | E12 | a token that cannot be rendered, and the header it rides on |
//! | [`request`] | E12 | the only request shape a token may travel in |
//! | [`redact`] | E12 | the backstop filter, and the log line it is applied to |
//! | [`chain`] | E12 | where a cached token lives, probed rather than assumed |
//! | [`redpair`] | E12 | the reverse-path triple, and what revoking it does |
//! | [`known_hosts`] | E13 | the OpenSSH `known_hosts` parser and writer |
//! | [`fingerprint`] | E13 | SHA-256 fingerprints, and the change we refuse |
//! | [`store`] | E13 | the three verdicts, and where the file is |

pub mod chain;
pub mod fingerprint;
pub mod known_hosts;
pub mod redact;
pub mod redpair;
pub mod request;
pub mod store;
pub mod token;
