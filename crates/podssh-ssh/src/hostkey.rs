//! Deciding whether to trust the key a server presents.
//!
//! The relay sits in the middle of every connection, so this check is what
//! makes the connection safe. A changed key is always refused, whatever
//! `StrictHostKeyChecking` says; a revoked key too. An unknown key is accepted
//! only when the policy or the user says so, and is then recorded.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key::PublicKey;

use crate::known_hosts::{self, Lookup, Recorded, Unreadable};
use crate::log::Log;
use crate::options::StrictHostKeyChecking;
use crate::prompt::{self, PromptError};

/// Everything the check needs, owned, so it can run on a blocking thread.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The name the key is filed under: `host` or `[host]:port`.
    pub name: String,
    pub strict: StrictHostKeyChecking,
    /// Read in order; new keys go into the first.
    pub user_files: Vec<PathBuf>,
    /// Why `user_files` is empty, for the note on a key that is not
    /// recorded: `HOME` is not set, or `UserKnownHostsFile` is none.
    pub no_user_file: Option<&'static str>,
    pub global_files: Vec<PathBuf>,
    pub batch_mode: bool,
    /// The key of the first connection of this run, which each later one
    /// must meet; `None` checks `known_hosts` alone.
    pub pin: Option<Pin>,
    /// `--host-key-fingerprint`: when not empty, the only keys accepted, and
    /// none is recorded (T-031). A revoked or changed key is refused first.
    pub fingerprints: Vec<String>,
}

/// The destination's host key for one run of podssh, so that each new
/// connection of the run (a copy that continues after a drop) meets the key
/// of the first or fails: `known_hosts` alone takes any key that it lists.
#[derive(Debug, Clone, Default)]
pub struct Pin(Arc<Mutex<Option<String>>>);

impl Pin {
    /// Keep `fingerprint` when nothing is kept yet; else it must be the kept
    /// one.
    pub fn admit(&self, fingerprint: &str) -> Result<(), String> {
        let mut kept = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match kept.as_deref() {
            None => {
                *kept = Some(fingerprint.to_string());
                Ok(())
            }
            Some(first) if first == fingerprint => Ok(()),
            Some(first) => Err(format!(
                "the host key changed during this run: {first} at the first connection, {fingerprint} now. \
                 Refusing to connect."
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Refused, with the message to show.
    Reject(String),
}

impl Policy {
    fn files(&self) -> Vec<PathBuf> {
        self.user_files.iter().chain(&self.global_files).cloned().collect()
    }

    /// Check `key`; may prompt (blocking), may append to the first user file.
    /// A key that passes must also meet the run's pin.
    pub fn check(&self, key: &PublicKey, log: &Log) -> Verdict {
        let verdict = self.check_known(key, log);
        match (&verdict, &self.pin) {
            (Verdict::Accept, Some(pin)) => match pin.admit(&known_hosts::fingerprint(key)) {
                Ok(()) => verdict,
                Err(why) => Verdict::Reject(why),
            },
            _ => verdict,
        }
    }

    fn check_known(&self, key: &PublicKey, log: &Log) -> Verdict {
        let kind = known_hosts::key_type(key);
        let fp = known_hosts::fingerprint(key);
        let (lookup, unreadable) = known_hosts::lookup_all(&self.files(), &self.name, key);
        for file in &unreadable {
            log.verbose(&format!("{} cannot be read: {}", file.path.display(), file.error));
        }
        // The user's files are where keys are recorded: a key that is not
        // seen there, as one of them cannot be read, is not known to be new.
        let unseen: Vec<Unreadable> =
            unreadable.into_iter().filter(|file| self.user_files.contains(&file.path)).collect();
        match lookup {
            Lookup::Revoked { path, line } => Verdict::Reject(revoked_message(&self.name, &kind, &fp, &path, line)),
            Lookup::Changed { path, line, recorded } => {
                Verdict::Reject(changed_message(&self.name, &kind, &fp, &recorded, &path, line))
            }
            // After a revoked or changed key, the fingerprints that the user
            // gave decide alone, also for a key that known_hosts holds (T-031).
            _ if !self.fingerprints.is_empty() => self.expected(&kind, &fp, log),
            Lookup::Known { path, line } => {
                log.debug(&format!("host key for '{}' found at {}:{line}", self.name, path.display()));
                Verdict::Accept
            }
            Lookup::OtherTypes(types) => self.unknown(key, &kind, &fp, Some(&types), &unseen, log),
            Lookup::Unknown => self.unknown(key, &kind, &fp, None, &unseen, log),
        }
    }

    /// A key that is neither revoked nor changed, against the fingerprints of
    /// `--host-key-fingerprint`: one of them, or a refusal, never a record.
    fn expected(&self, kind: &str, fp: &str, log: &Log) -> Verdict {
        if self.fingerprints.iter().any(|expected| expected == fp) {
            log.verbose(&format!("the {kind} host key of '{}' is {fp}, as --host-key-fingerprint names it", self.name));
            return Verdict::Accept;
        }
        Verdict::Reject(format!(
            "the {kind} host key of '{}' is {fp}, and --host-key-fingerprint names {}. Refusing to connect.",
            self.name,
            self.fingerprints.join(", ")
        ))
    }

    fn unknown(
        &self,
        key: &PublicKey,
        kind: &str,
        fp: &str,
        other: Option<&[String]>,
        unseen: &[Unreadable],
        log: &Log,
    ) -> Verdict {
        let accept_hint = "if it is the right key, connect once with -o StrictHostKeyChecking=accept-new";
        let note = unseen_note(unseen);
        match self.strict {
            StrictHostKeyChecking::Yes => Verdict::Reject(format!(
                "no {kind} host key is known for '{}' and StrictHostKeyChecking is yes.\n  \
                 The server's key fingerprint is {fp};\n  {accept_hint}.{note}",
                self.name
            )),
            // A key that is not seen cannot be called new (T-028).
            StrictHostKeyChecking::AcceptNew | StrictHostKeyChecking::No if !unseen.is_empty() => {
                Verdict::Reject(unverifiable(&self.name, kind, fp, unseen))
            }
            StrictHostKeyChecking::AcceptNew | StrictHostKeyChecking::No => self.record(key, kind, fp, log),
            StrictHostKeyChecking::Ask if self.batch_mode => Verdict::Reject(format!(
                "host key verification failed: '{}' is not a known host and BatchMode forbids asking.\n  \
                 Its {kind} key fingerprint is {fp};\n  {accept_hint}.{note}",
                self.name
            )),
            StrictHostKeyChecking::Ask => self.ask(key, kind, fp, other, &note, log),
        }
    }

    fn ask(&self, key: &PublicKey, kind: &str, fp: &str, other: Option<&[String]>, note: &str, log: &Log) -> Verdict {
        let mut question = format!(
            "The authenticity of host '{}' can't be established.\n{kind} key fingerprint is {fp}.\n",
            self.name
        );
        if let Some(types) = other {
            question.push_str(&format!(
                "Keys of other types ({}) are known for this host; this one is not.\n",
                types.join(", ")
            ));
        }
        if !note.is_empty() {
            question.push_str(note.trim_start());
            question.push('\n');
        }
        question.push_str("Are you sure you want to continue connecting (yes/no/[fingerprint])? ");
        loop {
            let answer = match prompt::ask(&question, true) {
                Ok(a) => a,
                Err(e @ (PromptError::NoTerminal | PromptError::NoAnswer)) => {
                    return Verdict::Reject(format!(
                        "'{}' is not a known host, and {e}.\n  \
                         Its {kind} key fingerprint is {fp}.\n  \
                         If that is the right key, re-run with -o StrictHostKeyChecking=accept-new.",
                        self.name
                    ))
                }
                Err(e) => return Verdict::Reject(format!("host key verification failed: {e}")),
            };
            let answer = answer.trim();
            if answer.eq_ignore_ascii_case("yes") || answer == fp {
                return self.record(key, kind, fp, log);
            }
            if answer.eq_ignore_ascii_case("no") || answer.is_empty() {
                return Verdict::Reject("host key verification failed.".into());
            }
            question = "Please type 'yes', 'no' or the fingerprint: ".to_string();
        }
    }

    /// Record an accepted key in the first user file. Another run may have
    /// recorded the host meanwhile (T-029): the same key is known then, and
    /// another key of the type is refused as changed.
    fn record(&self, key: &PublicKey, kind: &str, fp: &str, log: &Log) -> Verdict {
        let Some(path) = self.user_files.first() else {
            let why = self.no_user_file.unwrap_or("no known_hosts file is configured");
            log.info(&not_recorded(&self.name, kind, fp, &NotRecorded::NoFile(why)));
            return Verdict::Accept;
        };
        match known_hosts::append(path, &self.name, key) {
            Ok(Recorded::Written { locked }) => {
                if !locked {
                    log.verbose(&format!("{} takes no lock: the key went in without one", path.display()));
                }
                log.info(&format!("Warning: Permanently added '{}' ({kind}) to the list of known hosts.", self.name));
                Verdict::Accept
            }
            Ok(Recorded::Already { line }) => {
                log.debug(&format!("the key of '{}' was recorded meanwhile at {}:{line}", self.name, path.display()));
                Verdict::Accept
            }
            Ok(Recorded::Changed { line, recorded }) => {
                Verdict::Reject(changed_message(&self.name, kind, fp, &recorded, path, line))
            }
            Ok(Recorded::Revoked { line }) => Verdict::Reject(revoked_message(&self.name, kind, fp, path, line)),
            Err(e) => {
                log.info(&not_recorded(&self.name, kind, fp, &NotRecorded::Write { path, error: &e }));
                Verdict::Accept
            }
        }
    }
}

/// The fingerprints of `--host-key-fingerprint`, `SHA256:B64[,...]` as
/// `ssh-keygen -l` prints them (T-031): each is a digest of 32 bytes, and a
/// value that is not is refused before anything connects.
pub fn parse_fingerprints(value: &str) -> Result<Vec<String>, String> {
    use base64::Engine;
    let mut out = Vec::new();
    for item in value.split(',').map(str::trim) {
        let body = item.strip_prefix("SHA256:").ok_or_else(|| {
            format!("--host-key-fingerprint: '{item}' is not SHA256:B64, as ssh-keygen -l prints a fingerprint")
        })?;
        let body = body.trim_end_matches('=');
        match base64::engine::general_purpose::STANDARD_NO_PAD.decode(body) {
            Ok(digest) if digest.len() == 32 => out.push(format!("SHA256:{body}")),
            _ => return Err(format!("--host-key-fingerprint: '{item}' is not the base64 of a SHA-256 digest")),
        }
    }
    Ok(out)
}

fn revoked_message(name: &str, kind: &str, fp: &str, path: &Path, line: usize) -> String {
    format!(
        "the {kind} host key for '{name}' ({fp}) is marked as revoked at {}:{line}. Refusing to connect.",
        path.display()
    )
}

/// Why a key that was accepted is not recorded.
#[derive(Debug)]
pub enum NotRecorded<'a> {
    /// No user file: the words say why.
    NoFile(&'a str),
    /// The first user file could not be written.
    Write { path: &'a Path, error: &'a std::io::Error },
}

/// The note on a key that is accepted for this connection only (T-028): a
/// later run meets the same question, and cannot tell a changed key.
pub fn not_recorded(name: &str, kind: &str, fp: &str, why: &NotRecorded<'_>) -> String {
    let why = match why {
        NotRecorded::NoFile(why) => why.to_string(),
        NotRecorded::Write { path, error } => format!("{} could not be written: {error}", path.display()),
    };
    format!(
        "the {kind} key of '{name}' ({fp}) is accepted for this connection only: it was not recorded, as {why}. \
         The next run cannot tell a changed key from a new one."
    )
}

/// The refusal of a key that no readable file knows, while a user file
/// cannot be read: the key may be recorded there, or a changed one.
fn unverifiable(name: &str, kind: &str, fp: &str, unseen: &[Unreadable]) -> String {
    let files: Vec<String> = unseen.iter().map(|f| format!("{} ({})", f.path.display(), f.error)).collect();
    format!(
        "the {kind} host key for '{name}' ({fp}) cannot be verified: {} cannot be read, and a key recorded \
         there is not seen. Refusing to connect.\n  \
         Make the file readable, name a readable one with -o UserKnownHostsFile=FILE, or give the \
         key's fingerprint with --host-key-fingerprint.",
        files.join(", ")
    )
}

/// One line for each user file that cannot be read, for a refusal or the
/// question; empty when each could be read.
fn unseen_note(unseen: &[Unreadable]) -> String {
    unseen
        .iter()
        .map(|f| format!("\n  {} cannot be read ({}): a key recorded there is not seen.", f.path.display(), f.error))
        .collect()
}

fn changed_message(
    name: &str,
    kind: &str,
    fp: &str,
    recorded: &PublicKey,
    path: &std::path::Path,
    line: usize,
) -> String {
    format!(
        "the host key for '{name}' has changed.\n\
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n\
         Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n\
         The relay, or anything between you and the server, could be the one doing it.\n\
         It is also possible that the host key has just been changed.\n\
         The {kind} key sent by '{name}' is {fp}.\n\
         The key recorded at {}:{line} is {}.\n\
         If the change is expected, delete line {line} of that file and connect again.\n\
         Host key verification failed.",
        path.display(),
        known_hosts::fingerprint(recorded),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{not_recorded, parse_fingerprints, NotRecorded, Pin, Policy, Verdict};

    const A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrY8o/Gih84gTH1Xe3+dWQIj69CTwHrBaBcbYacBdYS";
    const B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFuCj635iAvbyqAVAq82WzngvdvUIT84jHdP+VKHDIxG";

    /// The three reasons of a key that is not recorded each name the cause
    /// and the risk (T-028).
    #[test]
    fn not_recorded_names_the_cause_and_the_risk() {
        let fp = "SHA256:abc";
        let home = not_recorded("h", "ED25519", fp, &NotRecorded::NoFile("HOME is not set"));
        let none = not_recorded("h", "ED25519", fp, &NotRecorded::NoFile("UserKnownHostsFile is none"));
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied");
        let path = Path::new("/ro/known_hosts");
        let write = not_recorded("h", "ED25519", fp, &NotRecorded::Write { path, error: &error });
        for (text, cause) in [
            (&home, "HOME is not set"),
            (&none, "UserKnownHostsFile is none"),
            (&write, "/ro/known_hosts could not be written: Permission denied"),
        ] {
            assert!(text.contains("accepted for this connection only"), "{text}");
            assert!(text.contains("not recorded") && text.contains(cause), "{text}");
            assert!(text.contains("cannot tell a changed key"), "{text}");
            assert!(text.contains(fp) && text.contains("'h'"), "{text}");
            assert!(!text.contains("checked again"), "{text}");
        }
    }

    /// `--host-key-fingerprint` (T-031): the named key is accepted and not
    /// recorded, under each policy; another key is refused, also under
    /// accept-new and no, and also when known_hosts holds it; a revoked or a
    /// changed key is refused first, also when it is the named one.
    #[test]
    fn pinned_fingerprint_decides_alone_and_records_nothing() {
        use crate::known_hosts::fingerprint;
        use crate::log::Log;
        use crate::options::{LogLevel, StrictHostKeyChecking};
        use russh::keys::ssh_key::PublicKey;
        let a = PublicKey::from_openssh(A).unwrap();
        let b = PublicKey::from_openssh(B).unwrap();
        let dir = std::env::temp_dir().join(format!("podssh-pinned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty");
        let policy = |file: &Path, strict| Policy {
            name: "example.org".into(),
            strict,
            user_files: vec![file.to_path_buf()],
            no_user_file: None,
            global_files: Vec::new(),
            batch_mode: true,
            pin: None,
            fingerprints: vec![fingerprint(&a)],
        };
        let log = Log::new(LogLevel::Quiet);
        for strict in [StrictHostKeyChecking::AcceptNew, StrictHostKeyChecking::No, StrictHostKeyChecking::Yes] {
            assert_eq!(policy(&empty, strict).check(&a, &log), Verdict::Accept, "{strict:?}");
            assert!(!empty.exists(), "{strict:?}: a pinned key was recorded");
            let Verdict::Reject(why) = policy(&empty, strict).check(&b, &log) else {
                panic!("{strict:?}: another key was accepted")
            };
            assert!(why.contains(&fingerprint(&b)) && why.contains(&fingerprint(&a)), "{why}");
        }
        // known_hosts holds b: the named key still decides.
        let holds_b = dir.join("holds_b");
        std::fs::write(&holds_b, format!("example.org {B}\n")).unwrap();
        assert!(matches!(policy(&holds_b, StrictHostKeyChecking::AcceptNew).check(&b, &log), Verdict::Reject(_)));
        // A changed key (b recorded, a presented, of the same type) and a
        // revoked one are refused, though a is the named key.
        let Verdict::Reject(why) = policy(&holds_b, StrictHostKeyChecking::AcceptNew).check(&a, &log) else {
            panic!("a changed key was accepted because it was named")
        };
        assert!(why.contains("has changed"), "{why}");
        let revoked = dir.join("revoked");
        std::fs::write(&revoked, format!("@revoked example.org {A}\n")).unwrap();
        let Verdict::Reject(why) = policy(&revoked, StrictHostKeyChecking::AcceptNew).check(&a, &log) else {
            panic!("a revoked key was accepted because it was named")
        };
        assert!(why.contains("revoked"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The form of the fingerprints, as `ssh-keygen -l` prints them.
    #[test]
    fn pinned_fingerprint_values_are_digests_of_32_bytes() {
        let one = "SHA256:JfDOvc6FaJOB34ANs+ou385/Kh+mMQhnUx0gHXVAfUI";
        assert_eq!(parse_fingerprints(one).unwrap(), [one]);
        assert_eq!(parse_fingerprints(&format!("{one}=")).unwrap(), [one], "padding is dropped");
        for bad in ["", "SHA256:", "SHA256:abc", "sha256:JfDOvc6FaJOB34ANs+ou385/Kh+mMQhnUx0gHXVAfUI", "MD5:aa"] {
            assert!(parse_fingerprints(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_pin_keeps_the_first_key_and_refuses_another() {
        let pin = Pin::default();
        assert_eq!(pin.admit("SHA256:first"), Ok(()));
        assert_eq!(pin.clone().admit("SHA256:first"), Ok(()), "a clone shares the pin");
        let refused = pin.admit("SHA256:other").expect_err("another key");
        assert!(refused.contains("SHA256:first") && refused.contains("SHA256:other"), "{refused}");
    }
}
