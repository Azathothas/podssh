//! Connection sharing on the command line (T-039): `-M`, `-S`, `-O`,
//! `ControlMaster`, `ControlPath` and `ControlPersist`, read as OpenSSH
//! 10.3p1 reads them, and the start of a run that uses them: an `-O`
//! request, a run through a master that answers on the socket, or a run
//! that becomes the master. The protocol is `podssh_ssh::mux`. A socket
//! passes descriptors (SCM_RIGHTS), which Windows has not.

use std::path::PathBuf;

use super::args::SshArgs;
use super::options::Settings;

/// `ControlMaster`, and `-M` (`-MM` asks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    No,
    Yes,
    Ask,
    Auto,
    AutoAsk,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Mode> {
        Some(match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Mode::No,
            "yes" | "true" => Mode::Yes,
            "ask" => Mode::Ask,
            "auto" => Mode::Auto,
            "autoask" => Mode::AutoAsk,
            _ => return None,
        })
    }

    /// As OpenSSH's `-G` prints it.
    pub fn shown(self) -> &'static str {
        match self {
            Mode::No => "false",
            Mode::Yes => "true",
            Mode::Ask => "ask",
            Mode::Auto => "auto",
            Mode::AutoAsk => "autoask",
        }
    }
}

/// `ControlPersist`: how long a `-N` master stays with no client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Persist {
    #[default]
    No,
    /// `yes`, or `0`, as OpenSSH reads 0.
    Forever,
    Seconds(u64),
}

impl Persist {
    /// `yes`, `no`, or a time: seconds, or OpenSSH's units (`10m`, `1h30m`).
    pub fn parse(value: &str) -> Option<Persist> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Some(Persist::No),
            "yes" | "true" => Some(Persist::Forever),
            time => match seconds(time)? {
                0 => Some(Persist::Forever),
                n => Some(Persist::Seconds(n)),
            },
        }
    }

    pub fn shown(self) -> String {
        match self {
            Persist::No => "no".into(),
            Persist::Forever => "yes".into(),
            Persist::Seconds(n) => n.to_string(),
        }
    }
}

/// OpenSSH's time format (sshd_config(5), TIME FORMATS): numbers, each with
/// a unit of s, m, h, d or w, or none for seconds, added up.
fn seconds(time: &str) -> Option<u64> {
    if time.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    let mut number = String::new();
    for c in time.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        total = total.checked_add(number.parse::<u64>().ok()?.checked_mul(unit)?)?;
        number.clear();
    }
    if !number.is_empty() {
        total = total.checked_add(number.parse().ok()?)?;
    }
    Some(total)
}

/// A request of `-O`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Forward,
    Cancel,
    Exit,
    Stop,
    Proxy,
}

impl Command {
    fn parse(value: &str) -> Option<Command> {
        Some(match value {
            "check" => Command::Check,
            "forward" => Command::Forward,
            "cancel" => Command::Cancel,
            "exit" => Command::Exit,
            "stop" => Command::Stop,
            "proxy" => Command::Proxy,
            _ => return None,
        })
    }
}

/// The connection sharing of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    /// The socket, its tokens expanded; `None` for none or `none`.
    pub path: Option<PathBuf>,
    pub persist: Persist,
    pub command: Option<Command>,
}

/// The `%`, `${NAME}` and `~` expansion of a path.
type Expand<'a> = &'a dyn Fn(&str, &str) -> Result<PathBuf, String>;

/// Read `-M`, `-S`, `-O` and the keywords: the flags win, as in OpenSSH.
pub fn plan(args: &SshArgs, settings: &Settings, expand: Expand) -> Result<Plan, String> {
    let mode = match args.control_master {
        0 => settings.control_master.unwrap_or_default(),
        1 => Mode::Yes,
        _ => Mode::Ask,
    };
    let path = match (&args.control_path, &settings.control_path) {
        (Some(p), _) if p == "none" => None,
        (Some(p), _) => Some(expand("-S ", p)?),
        (None, Some(p)) if p.eq_ignore_ascii_case("none") => None,
        (None, Some(p)) => Some(expand("-o ControlPath=", p)?),
        (None, None) => None,
    };
    let command = match &args.control_command {
        Some(c) => Some(Command::parse(c).ok_or_else(|| format!("-O {c}: Invalid multiplex command."))?),
        None => None,
    };
    let given = args.control_master > 0 || args.control_path.is_some() || command.is_some();
    if cfg!(windows) && given {
        return Err("connection sharing (-M, -S, -O) passes descriptors between processes, which Windows cannot; \
                    each run is one connection there"
            .into());
    }
    Ok(Plan { mode, path, persist: settings.control_persist.unwrap_or_default(), command })
}

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
#[path = "control_unix.rs"]
mod unix;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_persist_reads_openssh_times() {
        assert_eq!(Persist::parse("no"), Some(Persist::No));
        assert_eq!(Persist::parse("yes"), Some(Persist::Forever));
        assert_eq!(Persist::parse("0"), Some(Persist::Forever));
        assert_eq!(Persist::parse("600"), Some(Persist::Seconds(600)));
        assert_eq!(Persist::parse("10m"), Some(Persist::Seconds(600)));
        assert_eq!(Persist::parse("1h30m"), Some(Persist::Seconds(5400)));
        assert_eq!(Persist::parse("1w2d3h4m5s"), Some(Persist::Seconds(604_800 + 172_800 + 10_800 + 240 + 5)));
        assert_eq!(Persist::parse("10x"), None);
        assert_eq!(Persist::parse(""), None);
        assert_eq!(Persist::Seconds(600).shown(), "600");
    }

    #[test]
    fn control_master_reads_each_value() {
        for (value, mode, shown) in [
            ("yes", Mode::Yes, "true"),
            ("no", Mode::No, "false"),
            ("ask", Mode::Ask, "ask"),
            ("auto", Mode::Auto, "auto"),
            ("AutoAsk", Mode::AutoAsk, "autoask"),
        ] {
            assert_eq!(Mode::parse(value), Some(mode), "{value}");
            assert_eq!(mode.shown(), shown);
        }
        assert_eq!(Mode::parse("maybe"), None);
    }
}
