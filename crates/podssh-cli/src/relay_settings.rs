//! The relay settings: `--relay-host` or `PODSSH_RELAY`, and `--relay-addr`
//! with `PODSSH_RELAY_ADDR` ([`crate::pins`]). A bad flag is a usage error
//! (64). A bad variable is a configuration error (78): the command line is
//! right, and a script that reads 64 would look for the fault in its
//! arguments.

use std::io::Write;

use podssh_relay::relay::{self, RelayList};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CONFIG;

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
/// default host and its pool. The message names the flag or the variable
/// that gave the bad value.
pub fn relays(flag: Option<&str>, env: Option<String>) -> Result<RelayList, Refusal> {
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    // select_relays reads the variable only when there is no flag, and an
    // empty variable as no variable.
    let from_env = flag.is_none() && env.as_deref().is_some_and(|v| !v.trim().is_empty());
    relay::select_relays(flag, env, &pool).map_err(|why| {
        if from_env {
            Refusal::config(format!("{}: {why}", relay::RELAY_ENV))
        } else {
            Refusal::usage(format!("--relay-host: {why}"))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_variable_is_78_and_a_bad_flag_64() {
        let bad = relays(None, Some("bad host!".into())).unwrap_err();
        assert_eq!(bad.code, EX_CONFIG);
        assert!(bad.message.starts_with("PODSSH_RELAY: "), "{bad}");
        let bad = relays(Some("bad host!"), Some("good.example".into())).unwrap_err();
        assert_eq!(bad.code, EXIT_USAGE);
        assert!(bad.message.starts_with("--relay-host: "), "{bad}");
        // The flag wins, so a bad variable beside a good flag is not read.
        assert!(relays(Some("good.example"), Some("bad host!".into())).is_ok());
        // An empty variable is no variable.
        assert!(relays(None, Some("  ".into())).is_ok());
    }
}
