//! E13: the three verdicts, and the path the store is read from.
//!
//! ⛔ **Three verdicts, no fourth**, and that is `E13`'s own wording: ⛔ *"key
//! matches a stored entry → proceed silently; key is unknown → TOFU; key
//! contradicts a stored entry → **refuse, and name both fingerprints**."*
//!
//! ⛔ **There is no `--insecure` and there is no bypass.** `E13`'s `Decision`,
//! quoting the sibling that shipped one: ⛔ *"A flag with a default is a
//! decision the user must notice to keep."* ⛔ This module has no parameter
//! that turns a [`Verdict::Refused`] into a [`Verdict::Accepted`], and ⛔ **that
//! is the structural form of the decision** ⛔ — the same argument `E03` makes
//! for TLS in `crates/podssh-ws/src/tls.rs`, where the only constructor takes a
//! bundle and builds a `WebPkiServerVerifier` whose `verify_server_cert` calls
//! `verify_server_name` unconditionally.

use std::fmt;
use std::path::{Path, PathBuf};

use super::fingerprint::PublicKey;
use super::known_hosts::{parse, Entry, HostPattern, KnownHosts};

/// What podssh decided about a presented host key.
///
/// ⛔ **The type makes the unsafe state unrepresentable, which is the point.** A
/// `bool` return would make "proceed anyway" a value a caller could compute. ⛔
/// A caller that matches on this enum has three arms to write and ⛔ the
/// `Refused` arm is the one that returns an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// ⛔ A stored entry for this host holds exactly this key. ⛔ **Silent**: the
    /// `Prove` block's control says ⛔ *"a known key with no flag. Must connect
    /// **silently** — no prompt, no stderr output. A control that passes loudly
    /// is not proving the negative."*
    Accepted { line: usize },
    /// ⛔ Nothing in the store names this host. ⛔ **Trust on first use, and it
    /// is never silent** — see [`accept_new`].
    Unknown { fingerprint: String },
    /// ⛔ **The store names this host and holds a different key.** ⛔ This is
    /// the case the entry calls ⛔ *"the attack, not the remedy"*, and it
    /// **names the file, the line, and both fingerprints.**
    Refused(Refusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub host: String,
    pub file: PathBuf,
    /// ⛔ **Every** contradicting line, not the first. ⛔ A file that disagrees
    /// with the presented key in three places is a file worth naming in full,
    /// and reporting one of the three would leave the operator to wonder what
    /// the other two were.
    pub lines: Vec<usize>,
    pub stored: Vec<String>,
    pub presented: String,
    /// ⛔ What the operator does next, printed verbatim. ⛔ `ssh-keygen -R` is
    /// named because ⛔ the entry says the operator's muscle memory has to work:
    /// ⛔ *"`ssh-keygen -R` semantics are honoured so an operator's muscle memory
    /// works."*
    pub remedy: String,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Accepted { line } => {
                write!(f, "host key matches the entry on line {line}")
            }
            Verdict::Unknown { fingerprint } => {
                write!(f, "host key is unknown; its fingerprint is {fingerprint}")
            }
            Verdict::Refused(r) => write!(f, "{r}"),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "podssh: REFUSING {}: the key presented is not the key on record.",
            self.host
        )?;
        writeln!(f, "  presented: {}", self.presented)?;
        writeln!(f, "  on record:")?;
        for (i, s) in self.stored.iter().enumerate() {
            let line = self.lines.get(i).copied().unwrap_or(0);
            writeln!(f, "    {}:{}", self.file.display(), line)?;
            writeln!(f, "      {s}")?;
        }
        writeln!(f, "  this is refused, not warned about.")?;
        writeln!(
            f,
            "  podssh will not overwrite a key on its own: an attacker who can do it \
             once would own every later connection."
        )?;
        writeln!(f, "  {}", self.remedy)?;
        write!(
            f,
            "  if the host was rebuilt, confirm the new fingerprint out of band first."
        )
    }
}

/// ⛔ **The three answers, and how each is arrived at.** ⛔ The order of the
/// checks is the security property: ⛔ **a match anywhere in the candidates wins
/// over a contradiction**, because a file may legitimately hold a rotated key
/// beside the old one, and a store that refused on any disagreement would punish
/// exactly the operator who had already pinned both. ⛔ The entry says a
/// rotated key is an **operator action** — ⛔ which is what makes two entries for
/// one host a state an operator can reach on purpose.
pub fn check(store: &KnownHosts, file: &Path, host: &str, presented: &PublicKey) -> Verdict {
    let candidates = store.candidates(host);
    let fp = presented.fingerprint().with_prefix();
    // ⛔ **The line returned is the line that MATCHED, not the first
    // candidate.** ⛔ A file may legitimately hold the same host twice ⛔ once
    // unhashed and once hashed, or once before a rotation and once after ⛔ and
    // the first version returned `candidates[0].line` for either. ⛔ MEASURED:
    // against a store where `github.com` is on line 2 unhashed and on line 4
    // hashed, presenting the line-4 key reported ⛔ *"matches the entry on line
    // 2"* ⛔ — a message naming a line that holds a **different key**, which is
    // exactly the sentence the entry requires to be true.
    // ⛔ **A `@revoked` entry is a candidate for every host and never a
    // match.** ⛔ It has to be *in* the candidate list for the refusal to name
    // it, and it must not be *matched* by the scan above — otherwise a file
    // whose only entry is the revocation hands back `Accepted`.
    //
    // ⛔ **MEASURED, and this was a live defect.** ⛔ The first version
    // matched on `e.key == presented` with no marker test, so
    // `@revoked evil.example <the presented key>` was ⛔ **accepted** — the
    // exact outcome the marker exists to prevent, and one that only a test
    // asking for it would find.
    if let Some(matched) = candidates
        .iter()
        .find(|e| e.marker != super::known_hosts::Marker::Revoked && e.key == *presented)
    {
        return Verdict::Accepted { line: matched.line };
    }
    if candidates.is_empty() {
        return Verdict::Unknown { fingerprint: fp };
    }
    Verdict::Refused(Refusal {
        host: host.to_string(),
        file: file.to_path_buf(),
        lines: candidates.iter().map(|e| e.line).collect(),
        stored: candidates
            .iter()
            .map(|e| e.key.fingerprint().with_prefix())
            .collect(),
        presented: fp,
        remedy: format!("to remove the old record: ssh-keygen -R {host} -f {}", file.display()),
    })
}

/// ⛔ **What `--accept-new` did.** ⛔ `Write` is a **separate arm from
/// `AlreadyKnown`** because `E13`'s `Prove` block names the difference: ⛔ *"a
/// connect that succeeds without persisting is a silent TOFU that re-prompts
/// forever."*
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// ⛔ Nothing to do: the store already holds this key for this host.
    AlreadyKnown { line: usize },
    /// ⛔ A new entry, and **the whole new file text** ⛔ — so the caller decides
    /// when to touch the disk, and a caller that fails to write cannot already
    /// have told the operator the key was accepted.
    Write { path: PathBuf, text: String },
}

/// ⛔ **The non-interactive way in, and it accepts an unknown key only.**
///
/// ⛔ `E13`'s Approach: ⛔ *"`--accept-new` is the only non-interactive way in,
/// and it accepts **unknown only** — never a contradiction."* ⛔ This is the
/// plant the entry calls ⛔ *"the plant that matters, because it is the one a
/// naive implementation passes."* ⛔ The decision is a [`Verdict`] and the
/// parameters are a host and a key: ⛔ there is no `bool` for a caller to set,
/// and ⛔ the `Refused` arm is a `return Err`, so ⛔ **a flag that consults
/// itself before the match check cannot be written against this signature.**
pub fn accept_new(
    store: &KnownHosts,
    file: &Path,
    host: &str,
    presented: &PublicKey,
) -> Result<AcceptOutcome, Refusal> {
    match check(store, file, host, presented) {
        Verdict::Accepted { line } => Ok(AcceptOutcome::AlreadyKnown { line }),
        Verdict::Unknown { .. } => Ok(AcceptOutcome::Write {
            path: file.to_path_buf(),
            text: accept_and_write(store, file, host, presented)?,
        }),
        // ⛔ The whole point. ⛔ `--accept-new` never converts a refusal.
        Verdict::Refused(r) => Err(r),
    }
}

/// ⛔ **The write, with the key in hand.** ⛔ **It re-runs [`check`] rather
/// than trusting a verdict the caller had in hand** ⛔ — one read path for the
/// decision and one write path, because a second decision made in the write
/// path is a second decision that can disagree with the first.
pub fn accept_and_write(
    store: &KnownHosts,
    file: &Path,
    host: &str,
    presented: &PublicKey,
) -> Result<String, Refusal> {
    if let Verdict::Refused(r) = check(store, file, host, presented) {
        return Err(r);
    }
    let line = store.entries.last().map(|e| e.line + 1).unwrap_or(1);
    let entry = Entry {
        line,
        patterns: vec![HostPattern::Plain(host.to_string())],
        marker: super::known_hosts::Marker::None,
        key: presented.clone(),
    };
    Ok(store.append(&entry))
}


/// ⛔ **The path the store is read from, resolved by probing.**
///
/// ⛔ `E13`'s Approach, in its own order: `~/.ssh/known_hosts`, then
/// `$XDG_CONFIG_HOME`/`podssh/known_hosts`, then beside the binary ⛔ resolved
/// from `/proc/self/exe` and ⛔ **not** from `argv[0]`, then `$PODSSH_KNOWN_HOSTS`.
/// ⛔ ⚠ **`UNKNOWN`**: which of those is canonical on the constrained host, and
/// whether it has a writable `$HOME` at all ⛔ — `E05`'s `open()` ⛔ *"has not
/// been run"* ⛔ on any host. ⛔ So the chain is walked and the result reported,
/// and **nothing is assumed about which entry exists.**
///
/// ⛔ `E13`'s `Decision`, quoting the sibling that got this wrong: ⛔ *"`argv[0]`
/// is whatever the operator typed, which may be a bare name found on PATH, and a
/// ProxyCommand's `argv[0]` is frequently not a path at all."* ⛔ **`podssh` is a
/// ProxyCommand**, so this is podssh's failure mode and not only the sibling's.
pub fn resolve_path(env: &dyn super::chain::Environment, exe: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = env.var("PODSSH_KNOWN_HOSTS") {
        return Some(PathBuf::from(p));
    }
    if let Some(h) = env.var("HOME") {
        let p = Path::new(&h).join(".ssh").join("known_hosts");
        if env.try_append(&p).is_ok() {
            return Some(p);
        }
    }
    if let Some(x) = env.var("XDG_CONFIG_HOME") {
        let p = Path::new(&x).join("podssh").join("known_hosts");
        if env.try_append(&p).is_ok() {
            return Some(p);
        }
    }
    if let Some(exe) = exe {
        if let Some(dir) = exe.parent() {
            let p = dir.join("known_hosts");
            if env.try_append(&p).is_ok() {
                return Some(p);
            }
        }
    }
    // ⛔ The run directory is the last resort for the same reason it is the last
    // resort for the token: ⛔ the constrained host may deny every other path.
    let p = env.current_dir().join("podssh-known-hosts");
    env.try_append(&p).ok().map(|_| p)
}

/// ⛔ **Read and parse, and ⛔ a missing file is an empty store rather than an
/// error.** ⛔ A first connection is the case the entry calls out ⛔ — *"podssh
/// cannot find anywhere to store the key… it then either refuses every first
/// connection, which makes the tool unusable"* ⛔ — and an empty store is what
/// turns that into a TOFU prompt instead of a dead end.
pub fn load(path: &Path) -> std::io::Result<KnownHosts> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KnownHosts::default()),
        Err(e) => Err(e),
    }
}
