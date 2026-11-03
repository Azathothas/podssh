//! The command line of `podssh job` (T-193, T-197): the words and the flags
//! as parsed, and the action that they ask for, or why they are refused
//! (64) before anything connects.

use std::time::Duration;

use clap::ArgMatches;

use crate::ssh::args::SshArgs;

/// The subcommands, in the order of the manual.
pub const SUBCOMMANDS: &[&str] = &["start", "submit", "list", "log", "wait", "fetch", "stop"];
/// The hex digits of an ID.
pub const ID_LEN: usize = 8;
/// The most jobs of the queue that `--slots` lets run at once.
pub const MOST_SLOTS: u32 = 64;

/// `job`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobArgs {
    pub subcommand: Option<String>,
    /// The host; for `submit`, a list of hosts too.
    pub host: Option<String>,
    /// The words after the host: an ID and a directory, or the command
    /// after `--`.
    pub words: Vec<String>,
    /// Whether `--` came on the command line: a command must follow it, so
    /// that no word of it is read as a flag of podssh.
    pub dashed: bool,
    /// `--slots N` of `submit`, `--timeout D` of `wait`, `--files GLOB` of
    /// `fetch` and `--json` of `list`, as typed (T-197).
    pub slots: Option<String>,
    pub timeout: Option<String>,
    pub files: Option<String>,
    pub json: bool,
    /// `--no-tmux` of `start` and `submit` (T-481): the job runs under
    /// nohup, for a host where tmux cannot be installed.
    pub no_tmux: bool,
    /// `--follow`, `--from-end` and `--jsonl` of `log` (T-485).
    pub follow: bool,
    pub from_end: bool,
    pub jsonl: bool,
    /// The connection flags, read as `ssh` reads them: `job`'s rows share
    /// their ids. The destination is the host.
    pub ssh: SshArgs,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl JobArgs {
    /// Read the values out of `job`'s matches; `dashed` when the command
    /// line held `--`.
    pub fn from_matches(m: &ArgMatches, dashed: bool, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| m.try_get_one::<String>(id).ok().flatten().cloned();
        let flag = |id: &str| m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        let words = m.try_get_many::<String>("words").ok().flatten().map(|v| v.cloned().collect()).unwrap_or_default();
        JobArgs {
            subcommand: one("subcommand"),
            host: one("host"),
            words,
            dashed,
            slots: one("slots"),
            timeout: one("timeout"),
            files: one("files"),
            json: flag("json"),
            no_tmux: flag("no-tmux"),
            follow: flag("follow"),
            from_end: flag("from-end"),
            jsonl: flag("jsonl"),
            ssh: SshArgs::from_matches(m),
            refused,
        }
    }
}

/// What a command line of `job` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start the command now: its words joined with spaces, as OpenSSH
    /// joins them, for sh on the host; `plain` with `--no-tmux` (T-481).
    Start {
        command: String,
        plain: bool,
    },
    /// Queue the command (T-197); `slots`, the jobs of the queue that may
    /// run at once, when `--slots` gives it.
    Submit {
        command: String,
        slots: Option<u32>,
        plain: bool,
    },
    List {
        json: bool,
    },
    Log(String),
    /// `log --follow` (T-485): the output as it comes, from the start or,
    /// with `--from-end`, from its size now; `jsonl`, one object for each
    /// line; `timeout` at most.
    Follow {
        id: String,
        from_end: bool,
        jsonl: bool,
        timeout: Option<Duration>,
    },
    /// Wait for the end of the job, `timeout` at most (T-197).
    Wait {
        id: String,
        timeout: Option<Duration>,
    },
    /// Copy the job's output, and the files of `files`, into `dir`, else
    /// `./podssh-job-ID` (T-197).
    Fetch {
        id: String,
        dir: Option<String>,
        files: Option<String>,
    },
    Stop(String),
}

/// An ID as `start` and `submit` printed it: 8 hex digits, in either case.
pub fn id(text: &str) -> Result<String, String> {
    if text.len() == ID_LEN && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(format!("{text}: an ID is the {ID_LEN} hex digits that podssh job start or submit printed"))
    }
}

/// A new ID: 8 random hex digits.
pub fn new_id() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// The time now, in milliseconds since 1970, which orders the jobs.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The value of `--slots`: 1 to [`MOST_SLOTS`].
pub fn slots(text: &str) -> Result<u32, String> {
    match text.trim().parse::<u32>() {
        Ok(n) if (1..=MOST_SLOTS).contains(&n) => Ok(n),
        _ => Err(format!("--slots {text}: give the jobs that may run at once, 1 to {MOST_SLOTS}")),
    }
}

/// The pattern of `--files`: the words of a shell's pattern, each under the
/// home directory of the host, so that each file that it names has a place
/// under the local directory.
pub fn files(text: &str) -> Result<String, String> {
    let outside = text.split_whitespace().any(|w| w.starts_with('/') || w.split('/').any(|c| c == ".."));
    if text.trim().is_empty() || outside || text.contains(['\n', '\0']) {
        return Err(format!(
            "--files {text}: give a pattern of files under the home directory of the host, such as 'build/*.log'"
        ));
    }
    Ok(text.to_string())
}

/// The command of `start` and `submit`: the words after `--`.
fn command(sub: &str, words: &[String], dashed: bool) -> Result<String, String> {
    if words.is_empty() {
        return Err(format!("give the command after --: podssh job {sub} HOST -- COMMAND"));
    }
    if !dashed {
        return Err(format!(
            "give the command after --, so that no word of it is read as a flag: podssh job {sub} HOST -- COMMAND"
        ));
    }
    let command = words.join(" ");
    if command.contains(['\n', '\0']) {
        return Err("the command holds a newline or a NUL, which no word of a far shell can carry".into());
    }
    Ok(command)
}

/// The value of `--timeout`, of `wait` and of `log --follow`.
fn timeout(args: &JobArgs) -> Result<Option<Duration>, String> {
    // The parser's words name podssh already; the report names the verb.
    let parse = |raw: &str| crate::non_interactive::parse_duration("--timeout", raw);
    args.timeout.as_deref().map(parse).transpose().map_err(|r| r.message.trim_start_matches("podssh: ").to_string())
}

/// The action of `args`, or why the command line is refused (64).
pub fn action(args: &JobArgs) -> Result<Action, String> {
    let Some(sub) = args.subcommand.as_deref() else {
        return Err(format!("give what to do and the host: podssh job {} HOST", SUBCOMMANDS.join("|")));
    };
    if !SUBCOMMANDS.contains(&sub) {
        return Err(format!("{sub} is not a command of podssh job: give {}", SUBCOMMANDS.join(", ")));
    }
    if args.host.is_none() {
        return Err(format!("give the host: podssh job {sub} HOST"));
    }
    // Each flag of some subcommands is refused with another, as a typo.
    for (given, flag, only) in [
        (args.slots.is_some(), "--slots", &["submit"][..]),
        (args.timeout.is_some(), "--timeout", &["wait", "log --follow"][..]),
        (args.files.is_some(), "--files", &["fetch"][..]),
        (args.json, "--json", &["list"][..]),
        (args.no_tmux, "--no-tmux", &["start", "submit"][..]),
        (args.follow, "--follow", &["log"][..]),
        (args.from_end, "--from-end", &["log --follow"][..]),
        (args.jsonl, "--jsonl", &["log --follow"][..]),
    ] {
        // `log --follow` is `log` with the flag.
        let fits = |one: &&str| *one == sub || (*one == "log --follow" && sub == "log" && args.follow);
        if given && !only.iter().any(fits) {
            let with = if sub == "log" && only.contains(&"log --follow") { "log without --follow" } else { sub };
            return Err(format!("{flag} goes with podssh job {}, not with {with}", only.join(" or ")));
        }
    }
    let (words, plain) = (args.words.as_slice(), args.no_tmux);
    match (sub, words) {
        ("start", _) => Ok(Action::Start { command: command(sub, words, args.dashed)?, plain }),
        ("submit", _) => {
            let slots = args.slots.as_deref().map(slots).transpose()?;
            Ok(Action::Submit { command: command(sub, words, args.dashed)?, slots, plain })
        }
        ("list", []) => Ok(Action::List { json: args.json }),
        ("list", [extra, ..]) => Err(format!("list takes no word after the host: {extra}")),
        ("log", [one]) if args.follow => {
            Ok(Action::Follow { id: id(one)?, from_end: args.from_end, jsonl: args.jsonl, timeout: timeout(args)? })
        }
        ("log", [one]) => Ok(Action::Log(id(one)?)),
        ("stop", [one]) => Ok(Action::Stop(id(one)?)),
        ("wait", [one]) => Ok(Action::Wait { id: id(one)?, timeout: timeout(args)? }),
        ("fetch", [one, rest @ ..]) if rest.len() <= 1 => {
            let files = args.files.as_deref().map(files).transpose()?;
            Ok(Action::Fetch { id: id(one)?, dir: rest.first().cloned(), files })
        }
        ("fetch", _) => Err("give one ID, and a directory or none: podssh job fetch HOST ID [DIR]".into()),
        _ => Err(format!("give one ID: podssh job {sub} HOST ID")),
    }
}
