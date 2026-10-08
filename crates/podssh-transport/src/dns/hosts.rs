//! E15 — ⛔ **`/etc/hosts`, outranked by nothing and overruling nothing.**
//!
//! ⛔ **A curated entry outranks DoH**: it is an operator's decision and a DoH
//! answer must not quietly overrule it. **READ**, `dropssh` `src/dns.c:21-22`:
//! *"/etc/hosts. A cage that has one has usually curated it, and a curated answer
//! is an operator's decision that DoH must not quietly overrule."* ⛔ **And the
//! file is opened at `src/dns.c:110` with a plain `fopen`**, which is why a
//! missing file is a return of zero addresses and not a fatal error ⛔ — a cage
//! with no `/etc/hosts` is ordinary.
//!
//! ⛔ **The comment marker is stripped before the parse and not after it.
//! `src/dns.c:124-127` says why and the reason is a real defect:*
//!
//! > THE COMMENT MARKER IS STRIPPED BEFORE THE PARSE AND NOT AFTER IT.
//! > Parsing first and then dropping a "#" field would accept a line whose
//! > comment contains something that looks like a hostname, which is a hosts-file
//! > mistake that becomes a name resolution.
//!
//! ⛔ **This module strips the `#` first**, for the same reason.
//!
//! ⛔ **IPv6 lines are honoured**, which the sibling's field-count parse does not
//! do: `src/dns.c:135` reads a dotted quad with `sscanf`, so a `::1 localhost`
//! line is not an answer there. ⛔ That is recorded as a **divergence** and not
//! as a correction, because a hosts file that answers in one family only is a
//! real configuration and podssh can read it.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// ⛔ **Where the file is.** ⛔ **A field, not a constant**, because
/// `relay-hostname.md`'s plants need a hosts file that is not the machine's, and
/// a test that can only read `/etc/hosts` can only test this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsFile {
    path: PathBuf,
}

impl HostsFile {
    pub fn system() -> Self {
        Self { path: PathBuf::from("/etc/hosts") }
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// ⛔ **The answer, or an empty list.** ⛔ **An unreadable file is an empty
    /// answer and not an error**, for the reason `src/dns.c:111-113` gives: a
    /// cage may have none, and failing the whole chain over a file that is
    /// allowed to be absent would make `Hosts` the weakest stage rather than an
    /// independent one.
    pub fn lookup(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        parse(&text, host, port)
    }

    /// ⛔ **Whether the file is there.** ⛔ **And this is deliberately NOT a
    /// resolution.** `dns.md` quotes `dropssh` `src/doctor.c:174-188`, which
    /// `stat`s `/etc/resolv.conf` and then ⛔ *"resolves `example.com` at
    /// `:181-184`"* because ⛔ **"`stat` succeeding is not resolution working"**,
    /// so it exists for a doctor that wants to say ⛔ *"there is a file here"* ⛔
    /// **and must not be reported as the stage answering.**
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }
}

/// ⛔ **The parse, separated from the file so it is testable with a string.**
///
/// ⛔ **The rules, in order:** strip a `#` comment; the first field is an address
/// and the second is a canonical name; ⛔ **every remaining field is also a name
/// on the same line**, because that is what a hosts file has always meant; the
/// comparison is case-insensitive, which is what `src/dns.c:132` does with
/// `strcasecmp`.
pub fn parse(text: &str, host: &str, port: u16) -> Vec<SocketAddr> {
    let wanted = host.trim_end_matches('.').to_ascii_lowercase();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = match line.find('#') {
            Some(at) => &line[..at],
            None => line,
        };
        let mut fields = line.split_whitespace();
        let (Some(addr), Some(_first)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        for name in std::iter::once(_first).chain(fields) {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name == wanted {
                let addr = SocketAddr::new(ip, port);
                // ⛔ **No duplicates.** A name listed twice must not become two
                // dialled addresses, and the cache stores this list.
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}