//! `podssh sftp`: the command line of OpenSSH's sftp (T-139). Commands from
//! a batch (`-b FILE`, `-b -` for stdin) or, on a terminal, at a prompt, over
//! one SFTP session; a destination that names a file is fetched at once. A
//! file goes as `podssh cp` copies it: under a temporary name, verified by
//! its digest, then renamed.
//!
//! **Exit codes are the sysexits of `cp`**: 64 a usage error (OpenSSH gives
//! 1, and a script that tests for "not zero" works with both), and the code
//! of the first command that fails a batch.
//!
//! **`--result-file FILE`** (T-486): at the end, on each path, one JSON
//! object in FILE, as `cp`'s, with the commands run and failed and the
//! command that ended the batch ([`result`]).

mod commands;
mod listing;
mod result;
mod run;

use std::io::{BufRead, Write};
use std::sync::Arc;

use clap::ArgMatches;
use podssh_ssh::outcome::Scope;
use podssh_ssh::Log;

use crate::cp::link;
use crate::cp::operand::{self, Operand, Remote};
use crate::exitmap::Fault;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env};
use result::Tally;
use run::{Flow, State};

/// `sftp`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SftpArgs {
    /// `[user@]host[:path]`, `sftp://[user@]host[:port][/path]`, or a node of
    /// a pair, `node://[user@]NAME[/ROUTE][:path]` (T-296).
    pub destination: Option<String>,
    /// The connection flags, read as `ssh` reads them.
    pub ssh: SshArgs,
    /// `-b FILE`; `-` is stdin.
    pub batch: Option<String>,
    /// `-s NAME`, the subsystem.
    pub subsystem: Option<String>,
    /// `-B BYTES`, `-R COUNT` and each `-X NAME=VALUE`: the size of each
    /// read or write, and the requests in flight (T-140).
    pub buffer: Option<String>,
    pub requests: Option<String>,
    pub sftp_options: Vec<String>,
    /// `-l KBITS`: the bandwidth (T-145).
    pub limit: Option<String>,
    /// `-p`: each get and put keeps the times (T-146).
    pub preserve: bool,
    /// `-r`: each get and put of a directory copies it (T-298).
    pub recursive: bool,
}

impl SftpArgs {
    /// Read the values out of `sftp`'s matches.
    pub fn from_matches(m: &ArgMatches) -> Self {
        let one = |id: &str| {
            if m.try_contains_id(id).unwrap_or(false) {
                m.get_one::<String>(id).cloned()
            } else {
                None
            }
        };
        SftpArgs {
            destination: one("destination"),
            ssh: SshArgs::from_matches(m),
            batch: one("batch-file"),
            subsystem: one("subsystem-name"),
            buffer: one("buffer-size"),
            requests: one("requests"),
            limit: one("limit"),
            preserve: m.try_get_one::<bool>("preserve").ok().flatten().copied().unwrap_or(false),
            recursive: m.try_get_one::<bool>("recursive").ok().flatten().copied().unwrap_or(false),
            sftp_options: if m.try_contains_id("sftp-option").unwrap_or(false) {
                m.get_many::<String>("sftp-option").map(|v| v.cloned().collect()).unwrap_or_default()
            } else {
                Vec::new()
            },
        }
    }
}

/// The server and the path of a destination. With no `:`, the whole is
/// `[user@]host`, never a local file; `node://` names a node (T-296).
fn destination(text: &str) -> Result<Remote, String> {
    match operand::parse(text, false)? {
        Operand::Remote(remote) => Ok(remote),
        Operand::Local(_) => {
            let (user, host) = match text.rfind('@') {
                Some(i) => (Some(&text[..i]), &text[i + 1..]),
                None => (None, text),
            };
            let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
            if host.is_empty() || host.contains(['/', '\\']) || user == Some("") {
                return Err(format!("{text:?} names no host"));
            }
            Ok(Remote {
                user: user.map(str::to_string),
                host: host.to_string(),
                port: None,
                path: String::new(),
                node: false,
            })
        }
    }
}

/// The lines of a batch: a file, or stdin for `-`.
fn read_batch(path: &str) -> std::io::Result<Vec<String>> {
    if path == "-" {
        std::io::stdin().lock().lines().collect()
    } else {
        std::fs::read_to_string(path).map(|text| text.lines().map(str::to_string).collect())
    }
}

/// Run `podssh sftp`; the process exit code. `deadline` is `--timeout`, or
/// `PODSSH_TIMEOUT`: a bound of the whole run, never required (T-508).
/// With `--result-file FILE`, the run's record goes to FILE at its end, on
/// each path (T-486).
pub fn run_sftp(
    args: &SftpArgs,
    deadline: Option<std::time::Duration>,
    tty: crate::pager::Tty,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let file = args.ssh.result_file.as_deref();
    if crate::ssh::result::dash("sftp", file, err) {
        return Fault::Usage.code();
    }
    let (started, scope, mut tally) = (std::time::Instant::now(), Scope::new(), Tally::default());
    let code = sftp_run(args, deadline, tty, out, err, &scope, &mut tally);
    if let Some(path) = file {
        let object = result::object(code, started.elapsed(), &scope.record(), &tally);
        crate::ssh::result::write("sftp", path, &object, err);
    }
    code
}

/// A refusal before anything connects: said, kept for the record, and 64.
fn refuse(err: &mut dyn Write, why: &str, tally: &mut Tally) -> i32 {
    let _ = writeln!(err, "podssh sftp: {why}.\n  Nothing has been attempted.");
    tally.did.error = Some(why.to_string());
    Fault::Usage.code()
}

/// A refusal of the settings or the destination, kept for the record.
fn refused(refusal: &Refusal, err: &mut dyn Write, tally: &mut Tally) -> i32 {
    tally.did.error = Some(refusal.message.clone());
    refusal.report("sftp", err)
}

/// [`run_sftp`], its connection in `scope`, what it did in `tally`.
fn sftp_run(
    args: &SftpArgs,
    deadline: Option<std::time::Duration>,
    tty: crate::pager::Tty,
    out: &mut dyn Write,
    err: &mut dyn Write,
    scope: &Scope,
    tally: &mut Tally,
) -> i32 {
    let Some(text) = &args.destination else {
        let why =
            "give a destination: [user@]host[:path], sftp://[user@]host[:port][/path] or node://[user@]NAME[:path]";
        return refuse(err, why, tally);
    };
    let server = match destination(text) {
        Ok(server) => server,
        Err(why) => return refuse(err, &why, tally),
    };
    let pipe = match crate::cp::pipe::pipeline(args.buffer.as_deref(), args.requests.as_deref(), &args.sftp_options) {
        Ok(pipe) => pipe,
        Err(why) => return refuse(err, &why, tally),
    };
    let mut shape = crate::cp::pipe::Shape { pipe, ..Default::default() };
    shape.keep.times = args.preserve;
    match args.limit.as_deref().map(|text| crate::cp::rate::parse("-l", text)).transpose() {
        Ok(limit) => crate::cp::rate::set(limit),
        Err(why) => return refuse(err, &why, tally),
    }
    // With no terminal the commands come from -b; a destination with a path
    // can still name one file to fetch.
    if args.batch.is_none() && !tty.stdin && server.path.is_empty() {
        return refuse(err, "with no terminal, give the commands with -b FILE, or -b - for stdin", tally);
    }
    let script = match args.batch.as_deref().map(read_batch).transpose() {
        Ok(script) => script,
        Err(e) => {
            let why = format!("the batch file {}: {e}", args.batch.as_deref().unwrap_or("-"));
            let _ = writeln!(err, "podssh sftp: {why}");
            // The command line named a batch that cannot be read.
            (tally.did.failure, tally.did.error) = (Some("usage"), Some(why));
            return Fault::NoInput.code();
        }
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refused(&refusal, err, tally);
    }
    // The session to a node ends with its link (T-612); resolve checks that
    // a node is named.
    crate::no_resume::ask(args.ssh.no_resume);
    let mut ssh = args.ssh.clone();
    ssh.destination = Some(server.destination());
    if let Some(port) = server.port {
        ssh.port = Some(port.to_string());
    }
    let mut resolved = match resolve::resolve_or_refuse(&ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refused(&refusal, err, tally),
    };
    resolved.options.host_key_pin = Some(podssh_ssh::hostkey::Pin::default());
    resolved.options.remembered = Some(podssh_ssh::remember::Remembered::default());
    // sftp-server uses no agent (T-036): no agent channel is ever accepted.
    resolved.options.forward_agent = podssh_ssh::Agent::Off;
    let log = Arc::new(Log::new(resolved.options.log_level));
    // No plain line in a pipe, as OpenSSH's sftp writes none (T-472).
    crate::cp::gauge::init(false, resolved.options.log_level == podssh_ssh::LogLevel::Quiet, false);
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let why = format!("could not start the async runtime: {e}");
            log.error(&why);
            (tally.did.failure, tally.did.error) = (Some("session"), Some(why));
            return Fault::SessionFault.code();
        }
    };
    let subsystem = args.subsystem.as_deref().unwrap_or("sftp");
    let work = Work { subsystem, shape, recursive: args.recursive, script, interactive: tty.stdin };
    // The session's connection writes the run's own record (T-486).
    let ran = scope.run(session(&resolved, &server, work, &log, out, tally));
    // The bound covers the login and each command, as cp's covers its copy;
    // a carrier that the session's connection took ends after it (T-595).
    let ended = runtime.block_on(crate::ssh::transport::settled(async {
        match deadline {
            Some(limit) => tokio::time::timeout(limit, ran).await.map_err(|_| limit),
            None => Ok(ran.await),
        }
    }));
    runtime.shutdown_background();
    ended.unwrap_or_else(|limit| {
        let why = format!("the --timeout of {} s passed", limit.as_secs());
        log.error(&why);
        (tally.did.failure, tally.did.error) = (Some("timeout"), Some(why));
        Fault::TimedOut.code()
    })
}

/// What the session runs: the subsystem, the shape of each copy, `sftp
/// -r`, and the batch, or the prompt when stdin is a terminal.
struct Work<'a> {
    subsystem: &'a str,
    shape: crate::cp::pipe::Shape,
    recursive: bool,
    script: Option<Vec<String>>,
    interactive: bool,
}

/// The SFTP session: the destination's path first, then the batch or the
/// prompt; what its commands did, in `tally`.
async fn session(
    resolved: &crate::ssh::resolve::Resolved,
    server: &Remote,
    work: Work<'_>,
    log: &Arc<Log>,
    out: &mut dyn Write,
    tally: &mut Tally,
) -> i32 {
    let Work { subsystem, shape, recursive, script, interactive } = work;
    let link = match link::open_sftp(resolved, log, subsystem).await {
        Ok(link) => link,
        Err(f) => {
            log.error(&f.message);
            tally.ended_by(&f, None);
            return f.fault.code();
        }
    };
    let code: Result<i32, crate::cp::transfer::Failed> = async {
        let mut state = State::new(&link, log, shape, recursive).await?;
        // A path that names a file is fetched at once; a directory is where
        // the commands start.
        if !server.path.is_empty() {
            let path = state.there(&server.path);
            if state.is_dir(&path).await? {
                state.run(&commands::Command::Cd(Some(path)), out).await?;
            } else {
                let get = commands::Command::Get { remote: path, local: None, preserve: false, recursive: false };
                // The fetch is the one command of the run.
                tally.run += 1;
                state.run(&get, out).await?;
                return Ok(0);
            }
        }
        Ok(match script {
            Some(lines) => batch(&mut state, &lines, log, out, tally).await,
            None if interactive => prompt(&mut state, log, out, tally).await,
            None => {
                let why = "with no terminal, give the commands with -b FILE, or -b - for stdin";
                log.error(why);
                (tally.did.failure, tally.did.error) = (Some("usage"), Some(why.to_string()));
                Fault::Usage.code()
            }
        })
    }
    .await;
    link.close().await;
    match code {
        Ok(code) => code,
        Err(failed) => {
            log.error(&failed.message);
            tally.ended_by(&failed, None);
            failed.fault.code()
        }
    }
}

/// Each line of a batch, echoed unless `@`; the first error ends it unless
/// its line starts with `-`. Each command is counted, and the one that ends
/// the batch named, as the user wrote it (T-486).
async fn batch(state: &mut State<'_>, lines: &[String], log: &Log, out: &mut dyn Write, tally: &mut Tally) -> i32 {
    for text in lines {
        let line = match commands::parse_line(text) {
            Ok(Some(line)) => line,
            Ok(None) => continue,
            Err(why) => {
                log.error(&why);
                (tally.run, tally.failed) = (tally.run + 1, tally.failed + 1);
                tally.failed_command = Some(text.trim().to_string());
                (tally.did.failure, tally.did.error) = (Some("usage"), Some(why));
                return Fault::Usage.code();
            }
        };
        if line.echo {
            let _ = writeln!(out, "sftp> {}", text.trim().trim_start_matches(['-', '@']));
        }
        tally.run += 1;
        match state.run(&line.command, out).await {
            Ok(Flow::Bye) => return 0,
            Ok(Flow::Next) => {}
            Err(failed) if line.keep_going => {
                log.error(&failed.message);
                tally.failed += 1;
            }
            Err(failed) => {
                log.error(&failed.message);
                tally.failed += 1;
                tally.ended_by(&failed, Some(text));
                return failed.fault.code();
            }
        }
    }
    0
}

/// The prompt: each line that the user types, until `bye` or the end of
/// input. An error is said, and the prompt goes on; each command is
/// counted.
async fn prompt(state: &mut State<'_>, log: &Log, out: &mut dyn Write, tally: &mut Tally) -> i32 {
    loop {
        let _ = write!(out, "sftp> ");
        let _ = out.flush();
        // Off the runtime's thread, so the connection's keepalives go on
        // while the user types.
        let read = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).map(|n| (n, line))
        })
        .await;
        let line = match read {
            Ok(Ok((0, _))) | Ok(Err(_)) | Err(_) => {
                let _ = writeln!(out);
                return 0;
            }
            Ok(Ok((_, line))) => line,
        };
        match commands::parse_line(&line) {
            Ok(Some(parsed)) => {
                tally.run += 1;
                match state.run(&parsed.command, out).await {
                    Ok(Flow::Bye) => return 0,
                    Ok(Flow::Next) => {}
                    Err(failed) => {
                        log.error(&failed.message);
                        tally.failed += 1;
                    }
                }
            }
            Ok(None) => {}
            Err(why) => {
                log.error(&why);
                (tally.run, tally.failed) = (tally.run + 1, tally.failed + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_a_host_with_or_without_a_path() {
        let at = |user: Option<&str>, host: &str, port: Option<u16>, path: &str| {
            Ok(Remote { user: user.map(str::to_string), host: host.into(), port, path: path.into(), node: false })
        };
        assert_eq!(destination("host"), at(None, "host", None, ""));
        assert_eq!(destination("u@host"), at(Some("u"), "host", None, ""));
        assert_eq!(destination("u@host:dir/f"), at(Some("u"), "host", None, "dir/f"));
        assert_eq!(destination("sftp://u@host:2222/x"), at(Some("u"), "host", Some(2222), "x"));
        assert_eq!(destination("[::1]"), at(None, "::1", None, ""));
        // A node of a pair, and the path after the first : (T-296).
        let node = destination("node://u@lab/ssh:dir").expect("a node");
        assert_eq!((node.node, node.host.as_str(), node.path.as_str()), (true, "lab/ssh", "dir"));
        assert_eq!(node.destination(), "node://u@lab/ssh");
        for bad in ["", "@host", "/tmp/x", "./x"] {
            assert!(destination(bad).is_err(), "{bad:?}");
        }
    }
}
