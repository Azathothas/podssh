//! Deciding whether to trust the key a server presents.
//!
//! The relay sits in the middle of every connection, so this check is what
//! makes the connection safe. A changed key is always refused, whatever
//! `StrictHostKeyChecking` says; a revoked key too. An unknown key is accepted
//! only when the policy or the user says so, and is then recorded.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key::PublicKey;

use crate::known_hosts::{self, Lookup};
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
    pub global_files: Vec<PathBuf>,
    pub batch_mode: bool,
    /// The key of the first connection of this run, which each later one
    /// must meet; `None` checks `known_hosts` alone.
    pub pin: Option<Pin>,
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
        match known_hosts::lookup(&self.files(), &self.name, key) {
            Lookup::Known { path, line } => {
                log.debug(&format!("host key for '{}' found at {}:{line}", self.name, path.display()));
                Verdict::Accept
            }
            Lookup::Revoked { path, line } => Verdict::Reject(format!(
                "the {kind} host key for '{}' ({fp}) is marked as revoked at {}:{line}. Refusing to connect.",
                self.name,
                path.display()
            )),
            Lookup::Changed { path, line, recorded } => {
                Verdict::Reject(changed_message(&self.name, &kind, &fp, &recorded, &path, line))
            }
            Lookup::OtherTypes(types) => self.unknown(key, &kind, &fp, Some(&types), log),
            Lookup::Unknown => self.unknown(key, &kind, &fp, None, log),
        }
    }

    fn unknown(&self, key: &PublicKey, kind: &str, fp: &str, other: Option<&[String]>, log: &Log) -> Verdict {
        let accept_hint = "if it is the right key, connect once with -o StrictHostKeyChecking=accept-new";
        match self.strict {
            StrictHostKeyChecking::Yes => Verdict::Reject(format!(
                "no {kind} host key is known for '{}' and StrictHostKeyChecking is yes.\n  \
                 The server's key fingerprint is {fp};\n  {accept_hint}.",
                self.name
            )),
            StrictHostKeyChecking::AcceptNew | StrictHostKeyChecking::No => {
                self.record(key, kind, log);
                Verdict::Accept
            }
            StrictHostKeyChecking::Ask if self.batch_mode => Verdict::Reject(format!(
                "host key verification failed: '{}' is not a known host and BatchMode forbids asking.\n  \
                 Its {kind} key fingerprint is {fp};\n  {accept_hint}.",
                self.name
            )),
            StrictHostKeyChecking::Ask => self.ask(key, kind, fp, other, log),
        }
    }

    fn ask(&self, key: &PublicKey, kind: &str, fp: &str, other: Option<&[String]>, log: &Log) -> Verdict {
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
                self.record(key, kind, log);
                return Verdict::Accept;
            }
            if answer.eq_ignore_ascii_case("no") || answer.is_empty() {
                return Verdict::Reject("host key verification failed.".into());
            }
            question = "Please type 'yes', 'no' or the fingerprint: ".to_string();
        }
    }

    fn record(&self, key: &PublicKey, kind: &str, log: &Log) {
        let Some(path) = self.user_files.first() else {
            log.info(&format!(
                "the {kind} key for '{}' was accepted but not recorded: no known_hosts file is configured",
                self.name
            ));
            return;
        };
        match known_hosts::append(path, &self.name, key) {
            Ok(()) => {
                log.info(&format!("Warning: Permanently added '{}' ({kind}) to the list of known hosts.", self.name))
            }
            Err(e) => log.error(&format!(
                "could not record the host key for '{}' in {}: {e}; it will be checked again next time",
                self.name,
                path.display()
            )),
        }
    }
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
    use super::Pin;

    #[test]
    fn a_pin_keeps_the_first_key_and_refuses_another() {
        let pin = Pin::default();
        assert_eq!(pin.admit("SHA256:first"), Ok(()));
        assert_eq!(pin.clone().admit("SHA256:first"), Ok(()), "a clone shares the pin");
        let refused = pin.admit("SHA256:other").expect_err("another key");
        assert!(refused.contains("SHA256:first") && refused.contains("SHA256:other"), "{refused}");
    }
}
