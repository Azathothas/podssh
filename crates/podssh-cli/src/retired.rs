//! The `PODSSH_*` names that a release stopped reading (T-634). podssh
//! refuses a flag and a keyword that it does not take, by name and with what
//! replaced it; a variable that a release stopped reading would be ignored in
//! silence, and a service whose file still sets it would start, look
//! healthy, and not do what its owner believes. So a name of [`RETIRED`]
//! that is set stops a run with 78 before anything is tried, and a service's
//! file of variables that sets it is refused with its line.
//!
//! A name that no row holds passes, set or not: refusing each unknown
//! `PODSSH_` name would punish a stray variable of a shell, and teach users
//! to unset names that nothing read. So this is never a list of allowed
//! names, and a misspelt name is still ignored. A name that a release reads
//! again loses its row in that release: the manual's tests refuse a row
//! whose name the source reads.

use std::io::Write;

use crate::exitmap::sysexits::EX_CONFIG;
use crate::tree::Parsed;

/// What took a retired name's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instead {
    /// A variable, a flag or a keyword of the settings file, as a user
    /// writes it.
    Use(&'static str),
    /// Nothing does what it did.
    Nothing,
}

/// One name that a release stopped reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retired {
    pub name: &'static str,
    /// The first release that did not read it, such as `v1.2.0`.
    pub since: &'static str,
    pub instead: Instead,
    /// Why it went, in few words.
    pub why: &'static str,
}

/// Each retired name. Empty: each `PODSSH_` name that a release read is
/// read still.
pub const RETIRED: &[Retired] = &[];

impl Retired {
    fn instead_words(&self) -> String {
        match self.instead {
            Instead::Use(what) => format!("use {what} instead"),
            Instead::Nothing => "nothing replaces it".to_string(),
        }
    }

    /// The refusal, in this order: what the name is not, what took its
    /// place, what to do, and only then why it went.
    pub fn refusal(&self) -> String {
        let (name, since, instead, why) = (self.name, self.since, self.instead_words(), self.why);
        format!("{name} is no longer read (since {since}): {instead}; remove it ({why})")
    }

    /// Its item in the manual's ENVIRONMENT.
    pub fn manual(&self) -> String {
        let (since, instead, why) = (self.since, self.instead_words(), self.why);
        format!("No longer read since {since}: {instead}; remove it. {why}.")
    }
}

/// The row of `table` named `name`.
pub fn named<'t>(table: &'t [Retired], name: &str) -> Option<&'t Retired> {
    table.iter().find(|row| row.name == name)
}

/// Each row of `table`, in its order, whose name `vars` sets to a value that
/// is not empty: an empty value is unset, as for each of podssh's variables.
pub fn set_in<'t>(table: &'t [Retired], vars: &[(String, String)]) -> Vec<&'t Retired> {
    table.iter().filter(|row| vars.iter().any(|(name, value)| name == row.name && !value.is_empty())).collect()
}

/// The variables of this process: a value that is not UTF-8 is set too.
pub fn environment() -> Vec<(String, String)> {
    let pairs = std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value)));
    pairs.map(|(name, value)| (name, value.to_string_lossy().into_owned())).collect()
}

/// The refusal of a run while `vars` sets a name of `table`: a line for each
/// on `err`, and 78; `None` lets the run go on. What only prints (help, the
/// version, the manual, a usage error) answers, so that `podssh man
/// environment` still says what replaced the name.
pub fn check(parsed: &Parsed, table: &[Retired], vars: &[(String, String)], err: &mut dyn Write) -> Option<i32> {
    if prints_only(parsed) {
        return None;
    }
    let rows = set_in(table, vars);
    if rows.is_empty() {
        return None;
    }
    for row in rows {
        // A unit's stale file is found by `journalctl -p warning` too (T-640).
        crate::journal::line(err, podssh_ssh::LogLevel::Error, &format!("podssh: {}", row.refusal()));
    }
    Some(EX_CONFIG)
}

/// A parse that only prints, and so runs whatever is set.
fn prints_only(parsed: &Parsed) -> bool {
    let shown = matches!(parsed, Parsed::Help(_) | Parsed::Version | Parsed::Man { .. });
    shown || matches!(parsed, Parsed::Usage(_) | Parsed::NoArguments(_) | Parsed::UnknownVerb(_))
}

#[cfg(test)]
pub(crate) mod tests;
