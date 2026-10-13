//! `podssh session` (T-186): a session that outlives each call of an agent.
//! `start` runs `serve` in the background: a podssh of its own that holds
//! one SSH session with a remote pty, on the road and the SSH client of
//! `podssh ssh`, and answers requests on a socket of this user's alone.
//! `send` types into the session, `wait` waits until its output stops or
//! shows a text, `capture` reads its screen, `stop` ends it, and `list`
//! names each one.
//!
//! **A listener that the user asks for** (the operator's ruling of
//! 2026-10-08, Q1). `start` and `serve` listen through the listener of
//! `podssh pipe`: `PODSSH_LISTEN=no` refuses them before any bind (78), and
//! the bind is the probe (77 where the host refuses it). The socket is mode
//! 0600 in a directory of mode 0700 of the cache, or on Windows a socket or
//! a named pipe of this user; a client of another user is closed. No TCP:
//! a request types into a shell, and a TCP peer's user cannot be read.
//!
//! **No credential crosses the socket.** The daemon logs in with what
//! `podssh ssh` would use; a request carries text to type, and an answer the
//! screen. A password to type goes through `send` with no TEXT, from stdin,
//! so that no command line holds it.

mod client;
mod daemon;
mod model;
mod place;
mod start;
mod wire;

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::io::Write;
use std::time::Duration;

use clap::ArgMatches;

use crate::exitmap::sysexits::EX_SOFTWARE;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;

/// The longest name of a session.
pub const NAME_MAX: usize = 32;
/// `--timeout` when it is not given: of `start`, and of `wait`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// `--idle` of a `wait` that names neither `--idle` nor `--match`.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(2);
/// The most that one `send` types: its line stays within the protocol's.
pub const SEND_MAX: usize = 512 * 1024;

const SUBCOMMANDS: &str = "start, send, wait, capture, stop, list or serve";

/// `session`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionArgs {
    pub subcommand: Option<String>,
    pub name: Option<String>,
    /// The connection flags, read as `ssh` reads them. For `start` and
    /// `serve` the destination is the host and the command its command; for
    /// `send` the two hold the words of the text.
    pub ssh: SshArgs,
    pub socket: Option<String>,
    pub timeout: Option<String>,
    pub idle: Option<String>,
    /// `--match TEXT`.
    pub matching: Option<String>,
    pub no_enter: bool,
    pub raw: bool,
    pub detach: bool,
    /// The words after the verb, as typed: `start` gives them to `serve`.
    pub argv: Vec<OsString>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl SessionArgs {
    /// Read the values out of `session`'s matches; `rest` is the command
    /// line after the verb.
    pub fn from_matches(m: &ArgMatches, rest: &[OsString], refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| m.get_one::<String>(id).cloned();
        let flag = |id: &str| m.get_flag(id);
        SessionArgs {
            subcommand: one("subcommand"),
            name: one("name"),
            ssh: SshArgs::from_matches(m),
            socket: one("socket"),
            timeout: one("timeout"),
            idle: one("idle"),
            matching: one("match"),
            no_enter: flag("no-enter"),
            raw: flag("raw"),
            detach: flag("detach"),
            argv: rest.to_vec(),
            refused,
        }
    }

    /// The name, checked before anything runs.
    fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
}

/// What the command line asks for, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    Start,
    Serve,
    List,
    /// `send` with no TEXT: the text comes from stdin.
    SendStdin,
    Request(wire::Op),
}

/// Run `podssh session`; the process exit code.
pub fn run(args: &SessionArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let ask = match check(args) {
        Ok(ask) => ask,
        Err(refusal) => return refusal.report("session", err),
    };
    match ask {
        Ask::Start => start::run(args, out, err),
        Ask::Serve => daemon::run(args, out, err),
        Ask::List => client::list(out, err),
        Ask::SendStdin => match client::stdin_text() {
            Ok(text) => client::request(args, wire::Op::Send(text), out, err),
            Err(refusal) => refusal.report("session", err),
        },
        Ask::Request(op) => client::request(args, op, out, err),
    }
}

/// A runtime for one run, or the line that says why there is none.
fn runtime(err: &mut dyn Write) -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => Some(runtime),
        Err(e) => {
            let _ = writeln!(err, "podssh session: could not start the async runtime: {e}");
            None
        }
    }
}

/// The exit code of a run that could not start its runtime.
const NO_RUNTIME: i32 = EX_SOFTWARE;

/// The usage errors of `podssh session`, before anything runs: what the
/// command line asks for.
fn check(args: &SessionArgs) -> Result<Ask, Refusal> {
    let sub = args.subcommand.as_deref().ok_or_else(|| format!("give a subcommand: {SUBCOMMANDS}"))?;
    if !matches!(sub, "start" | "serve" | "send" | "wait" | "capture" | "stop" | "list") {
        return Err(format!("no subcommand {sub:?}: {SUBCOMMANDS}").into());
    }
    // start gives serve the words after its own, so the subcommand comes
    // first, as in podssh session start NAME HOST.
    if args.argv.first().and_then(|w| w.to_str()) != Some(sub) {
        return Err(format!("the subcommand comes first: podssh session {sub} ...").into());
    }
    for (given, flag, takes) in [
        (args.idle.is_some(), "--idle", &["wait"][..]),
        (args.matching.is_some(), "--match", &["wait"][..]),
        (args.timeout.is_some(), "--timeout", &["start", "serve", "wait"][..]),
        (args.no_enter, "--no-enter", &["send"][..]),
        (args.raw, "--raw", &["capture"][..]),
        (args.detach, "--detach", &["serve"][..]),
        (args.socket.is_some(), "--socket", &["start", "serve", "send", "wait", "capture", "stop"][..]),
        (connection_flags(&args.ssh), "a connection flag", &["start", "serve"][..]),
    ] {
        if given && !takes.contains(&sub) {
            return Err(format!("{flag} is for {}", takes.join(" and ")).into());
        }
    }
    if sub == "list" {
        if args.name.is_some() || args.ssh.destination.is_some() {
            return Err("list takes no name: it names each session".into());
        }
        return Ok(Ask::List);
    }
    let name = args.name.as_deref().ok_or_else(|| format!("give the session's name: podssh session {sub} NAME"))?;
    check_name(name)?;
    if let Some(text) = &args.timeout {
        duration("--timeout", text)?;
    }
    let words = text_words(&args.ssh);
    match sub {
        "start" | "serve" => {
            if args.ssh.destination.is_none() {
                return Err(format!("give the host: podssh session {sub} NAME [OPTIONS] HOST [COMMAND]").into());
            }
            Ok(if sub == "start" { Ask::Start } else { Ask::Serve })
        }
        "send" => match words {
            None => Ok(Ask::SendStdin),
            Some(text) => {
                let mut bytes = text_bytes(&text)?;
                if !args.no_enter {
                    bytes.push(b'\r');
                }
                if bytes.len() > SEND_MAX {
                    return Err(format!("send types {SEND_MAX} bytes at most at once").into());
                }
                Ok(Ask::Request(wire::Op::Send(bytes)))
            }
        },
        _ if words.is_some() => Err(format!("{sub} takes only the session's name").into()),
        "wait" => {
            let idle = args.idle.as_deref().map(|t| duration("--idle", t)).transpose()?;
            let text = args.matching.as_ref().map(|t| t.as_bytes().to_vec());
            if text.as_ref().is_some_and(Vec::is_empty) {
                return Err("--match takes a text that is not empty".into());
            }
            let idle = idle.or(if text.is_none() { Some(DEFAULT_IDLE) } else { None });
            let timeout = args.timeout.as_deref().map(|t| duration("--timeout", t)).transpose()?;
            Ok(Ask::Request(wire::Op::Wait(wire::Wait { idle, text, timeout: timeout.unwrap_or(DEFAULT_TIMEOUT) })))
        }
        "capture" => Ok(Ask::Request(wire::Op::Capture { raw: args.raw })),
        _ => Ok(Ask::Request(wire::Op::Stop)),
    }
}

/// Whether a flag of the connection was given: each field of `SshArgs`
/// but the positionals, `-v` and `-q`, which each subcommand takes.
fn connection_flags(ssh: &SshArgs) -> bool {
    let mut given = ssh.clone();
    given.destination = None;
    given.command.clear();
    given.verbose = 0;
    given.quiet = 0;
    given != SshArgs::default()
}

/// The words of `send`'s text, joined with spaces as `ssh` joins a
/// command's; `None` when there is none.
fn text_words(ssh: &SshArgs) -> Option<String> {
    let first = ssh.destination.clone()?;
    Some(std::iter::once(first).chain(ssh.command.iter().cloned()).collect::<Vec<_>>().join(" "))
}

/// A session's name: letters, digits, `_` and `-`, not first a `-`, 1 to
/// [`NAME_MAX`]; it names the socket's file, so nothing else is taken.
pub fn check_name(name: &str) -> Result<(), String> {
    let fits = !name.is_empty()
        && name.len() <= NAME_MAX
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if fits {
        Ok(())
    } else {
        Err(format!("{name:?}: a session's name has letters, digits, _ and -, not first a -, {NAME_MAX} at most"))
    }
}

/// A duration of the command line, `2s`, `500ms` or `10m`: more than zero.
fn duration(flag: &str, text: &str) -> Result<Duration, String> {
    crate::non_interactive::parse_duration(flag, text)
        .map_err(|r| r.message.trim_start_matches("podssh: ").replace('\n', " "))
}

/// The bytes of `send`'s TEXT: `\r`, `\n`, `\t`, `\e` (ESC), `\xNN` and `\\`
/// give the bytes that they name, so that a key with no letter can be sent
/// (`\x03` is Ctrl-C). Each other `\` is refused: a text with a path of
/// Windows writes each `\` twice.
pub fn text_bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        if b != b'\\' {
            out.push(b);
            continue;
        }
        let (&c, tail) = rest.split_first().ok_or("the text ends with a \\: write \\\\ for one")?;
        rest = tail;
        match c {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'e' => out.push(0x1b),
            b'\\' => out.push(b'\\'),
            b'x' => match rest.get(..2) {
                Some(&[high, low]) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                    out.push((nibble(high) << 4) | nibble(low));
                    rest = &rest[2..];
                }
                _ => return Err("\\x takes two hex digits, as \\x03 for Ctrl-C".into()),
            },
            other => {
                return Err(format!(
                    "\\{} is no escape of send: \\r, \\n, \\t, \\e, \\xNN and \\\\ are",
                    char::from(other).escape_default()
                ))
            }
        }
    }
    Ok(out)
}

/// The value of one hex digit, checked by the caller.
fn nibble(digit: u8) -> u8 {
    char::from(digit).to_digit(16).map_or(0, |n| n as u8)
}
