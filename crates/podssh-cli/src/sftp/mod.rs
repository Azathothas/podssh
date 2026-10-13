//! `podssh sftp`: the command line of OpenSSH's sftp (T-139). Commands from
//! a batch (`-b FILE`, `-b -` for stdin) or, on a terminal, at a prompt, over
//! one SFTP session; a destination that names a file is fetched at once. A
//! file goes as `podssh cp` copies it: under a temporary name, verified by
//! its digest, then renamed.
//!
//! **Exit codes are the sysexits of `cp`**: 64 a usage error (OpenSSH gives
//! 1, and a script that tests for "not zero" works with both), and the code
//! of the first command that fails a batch.

mod commands;
mod run;

use std::io::{BufRead, Write};
use std::sync::Arc;

use clap::ArgMatches;
use podssh_ssh::Log;

use crate::cp::link;
use crate::cp::operand::{self, Operand, Remote};
use crate::exitmap::Fault;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env};
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

/// Run `podssh sftp`; the process exit code.
pub fn run_sftp(args: &SftpArgs, tty: crate::pager::Tty, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let refuse = |err: &mut dyn Write, why: &str| {
        let _ = writeln!(err, "podssh sftp: {why}.\n  Nothing has been attempted.");
        Fault::Usage.code()
    };
    let Some(text) = &args.destination else {
        return refuse(
            err,
            "give a destination: [user@]host[:path], sftp://[user@]host[:port][/path] or node://[user@]NAME[:path]",
        );
    };
    let server = match destination(text) {
        Ok(server) => server,
        Err(why) => return refuse(err, &why),
    };
    let pipe = match crate::cp::pipe::pipeline(args.buffer.as_deref(), args.requests.as_deref(), &args.sftp_options) {
        Ok(pipe) => pipe,
        Err(why) => return refuse(err, &why),
    };
    let mut shape = crate::cp::pipe::Shape { pipe, ..Default::default() };
    shape.keep.times = args.preserve;
    match args.limit.as_deref().map(|text| crate::cp::rate::parse("-l", text)).transpose() {
        Ok(limit) => crate::cp::rate::set(limit),
        Err(why) => return refuse(err, &why),
    }
    // With no terminal the commands come from -b; a destination with a path
    // can still name one file to fetch.
    if args.batch.is_none() && !tty.stdin && server.path.is_empty() {
        return refuse(err, "with no terminal, give the commands with -b FILE, or -b - for stdin");
    }
    let script = match args.batch.as_deref().map(read_batch).transpose() {
        Ok(script) => script,
        Err(e) => {
            let _ = writeln!(err, "podssh sftp: the batch file {}: {e}", args.batch.as_deref().unwrap_or("-"));
            return Fault::NoInput.code();
        }
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("sftp", err);
    }
    let mut ssh = args.ssh.clone();
    ssh.destination = Some(server.destination());
    if let Some(port) = server.port {
        ssh.port = Some(port.to_string());
    }
    let mut resolved = match resolve::resolve_or_refuse(&ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("sftp", err),
    };
    resolved.options.host_key_pin = Some(podssh_ssh::hostkey::Pin::default());
    resolved.options.remembered = Some(podssh_ssh::remember::Remembered::default());
    // sftp-server uses no agent (T-036): no agent channel is ever accepted.
    resolved.options.forward_agent = podssh_ssh::Agent::Off;
    let log = Arc::new(Log::new(resolved.options.log_level));
    crate::cp::gauge::init(false, resolved.options.log_level == podssh_ssh::LogLevel::Quiet);
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return Fault::SessionFault.code();
        }
    };
    let subsystem = args.subsystem.as_deref().unwrap_or("sftp");
    let code = runtime.block_on(session(&resolved, &server, subsystem, shape, script, tty.stdin, &log, out));
    runtime.shutdown_background();
    code
}

/// The SFTP session: the destination's path first, then the batch or the
/// prompt.
#[allow(clippy::too_many_arguments)]
async fn session(
    resolved: &crate::ssh::resolve::Resolved,
    server: &Remote,
    subsystem: &str,
    shape: crate::cp::pipe::Shape,
    script: Option<Vec<String>>,
    interactive: bool,
    log: &Arc<Log>,
    out: &mut dyn Write,
) -> i32 {
    let link = match link::open_sftp(resolved, log, subsystem).await {
        Ok(link) => link,
        Err(f) => {
            log.error(&f.message);
            return f.fault.code();
        }
    };
    let code: Result<i32, crate::cp::transfer::Failed> = async {
        let mut state = State::new(&link, log, shape).await?;
        // A path that names a file is fetched at once; a directory is where
        // the commands start.
        if !server.path.is_empty() {
            let path = state.there(&server.path);
            if state.is_dir(&path).await? {
                state.run(&commands::Command::Cd(Some(path)), out).await?;
            } else {
                state.run(&commands::Command::Get { remote: path, local: None, preserve: false }, out).await?;
                return Ok(0);
            }
        }
        Ok(match script {
            Some(lines) => batch(&mut state, &lines, log, out).await,
            None if interactive => prompt(&mut state, log, out).await,
            None => {
                log.error("with no terminal, give the commands with -b FILE, or -b - for stdin");
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
            failed.fault.code()
        }
    }
}

/// Each line of a batch, echoed unless `@`; the first error ends it unless
/// its line starts with `-`.
async fn batch(state: &mut State<'_>, lines: &[String], log: &Log, out: &mut dyn Write) -> i32 {
    for text in lines {
        let line = match commands::parse_line(text) {
            Ok(Some(line)) => line,
            Ok(None) => continue,
            Err(why) => {
                log.error(&why);
                return Fault::Usage.code();
            }
        };
        if line.echo {
            let _ = writeln!(out, "sftp> {}", text.trim().trim_start_matches(['-', '@']));
        }
        match state.run(&line.command, out).await {
            Ok(Flow::Bye) => return 0,
            Ok(Flow::Next) => {}
            Err(failed) if line.keep_going => log.error(&failed.message),
            Err(failed) => {
                log.error(&failed.message);
                return failed.fault.code();
            }
        }
    }
    0
}

/// The prompt: each line that the user types, until `bye` or the end of
/// input. An error is said, and the prompt goes on.
async fn prompt(state: &mut State<'_>, log: &Log, out: &mut dyn Write) -> i32 {
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
            Ok(Some(parsed)) => match state.run(&parsed.command, out).await {
                Ok(Flow::Bye) => return 0,
                Ok(Flow::Next) => {}
                Err(failed) => log.error(&failed.message),
            },
            Ok(None) => {}
            Err(why) => log.error(&why),
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
