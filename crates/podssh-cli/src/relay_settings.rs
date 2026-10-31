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

    /// Print the message for `verb`, and give the exit code.
    pub fn report(&self, verb: &str, err: &mut dyn Write) -> i32 {
        let _ = writeln!(err, "podssh {verb}: {}", self.message);
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

/// [`relays`] with the settings given.
pub fn relays_from(flag: Option<&str>, env: Option<String>, file: &Defaults) -> Result<RelayList, Refusal> {
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    // select_relays reads the variable only when there is no flag, and an
    // empty variable as no variable.
    let from_env = flag.is_none() && env.as_deref().is_some_and(|v| !v.trim().is_empty());
    if let (None, false, Some(value)) = (flag, from_env, &file.relay_host) {
        file.check()?;
        return relay::select_relays(Some(&value.text), None, &pool)
            .map_err(|why| Refusal::config(format!("{}: RelayHost {}: {why}", value.at, value.text)));
    }
    relay::select_relays(flag, env, &pool).map_err(|why| {
        if from_env {
            Refusal::config(format!("{}: {why}", relay::RELAY_ENV))
        } else {
            Refusal::usage(format!("--relay-host: {why}"))
        }
    })
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
}
