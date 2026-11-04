//! The relay settings: `--relay-host` or `PODSSH_RELAY`, and `--relay-addr`
//! with `PODSSH_RELAY_ADDR` ([`crate::pins`]). A bad flag is a usage error
//! (64). A bad variable is a configuration error (78): the command line is
//! right, and a script that reads 64 would look for the fault in its
//! arguments.

use std::io::Write;

use podssh_relay::failover::{Mode, MODE_ENV};
use podssh_relay::relay::{self, RelayList};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CONFIG;
use crate::settings::Defaults;

/// A refusal before anything is attempted, with the exit code that says
/// where the fault is: in the command line (64) or in the environment (78).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub message: String,
    pub code: i32,
}

impl Refusal {
    /// A fault in the command line.
    pub fn usage(message: impl Into<String>) -> Self {
        Refusal { message: message.into(), code: EXIT_USAGE }
    }

    /// A fault in a variable of the environment.
    pub fn config(message: impl Into<String>) -> Self {
        Refusal { message: message.into(), code: EX_CONFIG }
    }

    /// Print the message for `verb`, and give the exit code. Where stderr is
    /// the journal's stream, the journal gets it at the priority of an error
    /// too (T-640).
    pub fn report(&self, verb: &str, err: &mut dyn Write) -> i32 {
        crate::journal::line(err, podssh_ssh::LogLevel::Error, &format!("podssh {verb}: {}", self.message));
        self.code
    }
}

/// Most refusals come from the command line, so a bare message is one.
impl From<String> for Refusal {
    fn from(message: String) -> Self {
        Refusal::usage(message)
    }
}

impl From<&str> for Refusal {
    fn from(message: &str) -> Self {
        Refusal::usage(message)
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The relay hosts: `--relay-host`, else `PODSSH_RELAY` (`env`), else the
/// settings file's `RelayHost` (T-048), else the default host and its pool.
/// The message names the flag, the variable or the line that gave the bad
/// value.
pub fn relays(flag: Option<&str>, env: Option<String>) -> Result<RelayList, Refusal> {
    relays_from(flag, env, crate::settings::here())
}

/// [`relays`] with the settings given. The default list is followed by the
/// hosts of other deployments that a signed list names (T-346).
pub fn relays_from(flag: Option<&str>, env: Option<String>, file: &Defaults) -> Result<RelayList, Refusal> {
    crate::relay_deployments::install(file)?;
    let pool = ranked(podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST), file);
    // select_relays reads the variable only when there is no flag, and an
    // empty variable as no variable.
    let from_env = flag.is_none() && env.as_deref().is_some_and(|v| !v.trim().is_empty());
    if let (None, false, Some(value)) = (flag, from_env, &file.relay_host) {
        file.check()?;
        return relay::select_relays(Some(&value.text), None, &pool)
            .map_err(|why| Refusal::config(format!("{}: RelayHost {}: {why}", value.at, value.text)));
    }
    let list = relay::select_relays(flag, env, &pool).map_err(|why| {
        if from_env {
            Refusal::config(format!("{}: {why}", relay::RELAY_ENV))
        } else {
            Refusal::usage(format!("--relay-host: {why}"))
        }
    })?;
    Ok(crate::relay_deployments::joined(list))
}

/// The pool in the order that this host measured (T-607): by the rank of
/// `relay rank` when one holds for this egress, else by the times of the
/// races; as `/relays.json` gave it with `RelayRank no` or
/// `PODSSH_RELAY_RANK=no`, which `open` reads too. `RelayRank auto` asks
/// for a rank in a session's background too (T-608).
fn ranked(pool: Vec<String>, file: &Defaults) -> Vec<String> {
    podssh_relay::rank_list::set_by_settings(rank_on(file));
    podssh_relay::rank_auto::set_by_settings(rank_auto(file));
    if !podssh_relay::rank_list::enabled() {
        return pool;
    }
    let egress = podssh_relay::rank_list::egress_for(relay::DEFAULT_RELAY_HOST);
    let kept = podssh_relay::rank::load();
    podssh_relay::rank_list::alternates(pool, kept.as_ref(), &egress, crate::pairs::now_ms())
}

/// Whether the settings file leaves the rank on: all but `RelayRank no`.
fn rank_on(file: &Defaults) -> bool {
    file.relay_rank.as_ref().is_none_or(|value| yes_or_no(&value.text) != Some(false))
}

/// Whether the settings file asks for a rank in the background:
/// `RelayRank auto` alone, never by default (Q89).
fn rank_auto(file: &Defaults) -> bool {
    file.relay_rank.as_ref().is_some_and(|value| value.text.trim().eq_ignore_ascii_case("auto"))
}

/// How the relay hosts are tried (T-220): `--relay-failover`, else
/// `PODSSH_RELAY_FAILOVER` (`env`), else the settings file's
/// `RelayFailover` (T-048), else `staggered`.
pub fn failover(flag: Option<&str>, env: Option<String>) -> Result<Mode, Refusal> {
    failover_from(flag, env, crate::settings::here())
}

/// [`failover`] with the settings given.
pub fn failover_from(flag: Option<&str>, env: Option<String>, file: &Defaults) -> Result<Mode, Refusal> {
    let env_set = env.as_deref().is_some_and(|v| !v.trim().is_empty());
    match (flag, env_set, &file.relay_failover) {
        (Some(word), ..) => Mode::parse(word)
            .ok_or_else(|| Refusal::usage(format!("--relay-failover: {word:?} is not a mode: give {}", Mode::NAMES))),
        (None, false, Some(value)) => Mode::parse(&value.text).ok_or_else(|| {
            Refusal::config(format!("{}: RelayFailover {:?} is not a mode: give {}", value.at, value.text, Mode::NAMES))
        }),
        _ => Mode::from_env(env).map_err(Refusal::config),
    }
}

/// [`failover`] with no flag: the variable of the process.
pub fn failover_of_env() -> Result<Mode, Refusal> {
    failover(None, std::env::var(MODE_ENV).ok())
}

/// `no`: when each relay host failed, podssh tries the direct road no more
/// (T-363).
pub const DIRECT_ENV: &str = "PODSSH_DIRECT";

/// Whether the direct road follows the relay hosts: [`DIRECT_ENV`], else the
/// settings file's `Direct`, else yes. A bad variable is 78; the file's
/// value was checked as the file was read.
pub fn direct_from(env: Option<String>, file: &Defaults) -> Result<bool, Refusal> {
    match (env.as_deref().filter(|v| !v.trim().is_empty()), &file.direct) {
        (Some(word), _) => yes_or_no(word).ok_or_else(|| Refusal::config(format!("{DIRECT_ENV}={word}: yes or no"))),
        (None, Some(value)) => Ok(yes_or_no(&value.text).unwrap_or(true)),
        (None, None) => Ok(true),
    }
}

/// `yes`, `on`, `true` or `1`; `no`, `off`, `false` or `0`; else none.
pub fn yes_or_no(word: &str) -> Option<bool> {
    match word.trim().to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" | "1" => Some(true),
        "no" | "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podssh_direct_turns_the_fallback_off_and_beats_the_file() {
        let file = |text: &str| crate::settings::parse(&format!("Direct {text}\n"), "settings", None).unwrap();
        assert_eq!(direct_from(None, &Defaults::default()), Ok(true), "on by default");
        assert_eq!(direct_from(Some("no".into()), &Defaults::default()), Ok(false));
        assert_eq!(direct_from(None, &file("no")), Ok(false), "the file's key");
        assert_eq!(direct_from(Some("yes".into()), &file("no")), Ok(true), "the variable wins");
        assert_eq!(direct_from(Some(" ".into()), &file("no")), Ok(false), "an empty variable is none");
        let bad = direct_from(Some("maybe".into()), &Defaults::default()).unwrap_err();
        assert_eq!(bad.code, EX_CONFIG);
        assert!(bad.message.contains("PODSSH_DIRECT=maybe"), "{bad}");
        assert!(crate::settings::parse("Direct maybe\n", "settings", None).is_err(), "the file checks its value");
    }

    #[test]
    fn relay_rank_no_turns_the_rank_off_and_nothing_else_does() {
        let file = |text: &str| crate::settings::parse(&format!("RelayRank {text}\n"), "settings", None).unwrap();
        assert!(rank_on(&Defaults::default()), "on by default");
        assert!(!rank_on(&file("no")));
        assert!(rank_on(&file("yes")));
        assert!(crate::settings::parse("RelayRank maybe\n", "settings", None).is_err(), "the file checks its value");
        // auto (T-608): the rank on, and a rank in the background asked;
        // nothing else asks for one.
        assert!(rank_on(&file("auto")) && rank_auto(&file("Auto")));
        assert!(!rank_auto(&file("yes")) && !rank_auto(&file("no")) && !rank_auto(&Defaults::default()));
    }

    #[test]
    fn a_bad_variable_is_78_and_a_bad_flag_64() {
        let bad = relays_from(None, Some("bad host!".into()), &Defaults::default()).unwrap_err();
        assert_eq!(bad.code, EX_CONFIG);
        assert!(bad.message.starts_with("PODSSH_RELAY: "), "{bad}");
        let bad = relays_from(Some("bad host!"), Some("good.example".into()), &Defaults::default()).unwrap_err();
        assert_eq!(bad.code, EXIT_USAGE);
        assert!(bad.message.starts_with("--relay-host: "), "{bad}");
        // The flag wins, so a bad variable beside a good flag is not read.
        assert!(relays_from(Some("good.example"), Some("bad host!".into()), &Defaults::default()).is_ok());
        // An empty variable is no variable.
        assert!(relays_from(None, Some("  ".into()), &Defaults::default()).is_ok());
    }

    /// A refusal's line on `err` is as it was before the journal's copy
    /// (T-640): one line, the verb, the message, and its code.
    #[test]
    fn a_refusal_reports_its_line_as_before() {
        let mut err = Vec::new();
        assert_eq!(Refusal::config("PODSSH_NET: a relative path").report("net", &mut err), EX_CONFIG);
        assert_eq!(err, b"podssh net: PODSSH_NET: a relative path\n");
    }
}
