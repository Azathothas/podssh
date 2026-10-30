//! `podssh node NAME TARGET... --install` and `--uninstall` (T-121): the
//! node as a service that this user may make with no privilege, found by a
//! probe at run time: a user unit of systemd when `systemctl --user`
//! answers, else an `@reboot` line of the crontab when `crontab -l`
//! answers; on Windows a task at logon (`schtasks`), never a Windows
//! service, which needs an administrator. With none of them, the command to
//! run at login is printed, and the exit is 69. The service runs this
//! binary by its absolute path, with the node's own arguments and
//! `--env-file`: the variables that the node reads (the proxy, the relay,
//! the places of podssh's files) go into a private file beside the pair, so
//! that no token is on a command line or in a unit file, and the pair's
//! tokens stay in the pair's own file. `--uninstall` removes what
//! `--install` wrote, and nothing else.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

mod env;
mod text;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;

/// The bound on each program that a probe or an install runs.
const PROGRAM_LIMIT: Duration = Duration::from_secs(10);

/// What a service runs: this binary by its absolute path, and its words.
pub(crate) struct Spec {
    pub name: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
}

/// What one way of making a service came to.
pub(crate) enum Made {
    /// The service is made: what was made, in lines.
    Done(Vec<String>),
    /// This way is not there: why, for the line that names each way tried.
    Absent(String),
    /// This way is there, and failed.
    Failed(Refusal),
}

/// `podssh node`: the variables of `--env-file` first, then the node, or
/// its install or uninstall.
pub fn dispatch(args: &NodeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Some(file) = &args.env_file {
        if args.install || args.uninstall {
            let why = "--env-file is the file that --install writes for the service: give it to the node alone";
            return Refusal::usage(why).report("node", err);
        }
        if let Err(refusal) = env::apply(Path::new(file)) {
            return refusal.report("node", err);
        }
    }
    match (args.install, args.uninstall) {
        (true, true) => Refusal::usage("--install and --uninstall: give one").report("node", err),
        (true, false) => match prepare(args) {
            Ok((spec, notes)) => install(&spec, &notes, out, err),
            Err(refusal) => refusal.report("node", err),
        },
        (false, true) => uninstall(args, err),
        (false, false) => crate::node::run_node(args, err),
    }
}

/// The label of `--install` or `--uninstall`, checked.
fn label(args: &NodeArgs, flag: &str) -> Result<String, Refusal> {
    let name = args.name.clone().ok_or_else(|| Refusal::usage(format!("{flag} needs NAME, the label of a pair")))?;
    crate::pairs::check_label(&name)?;
    Ok(name)
}

/// The service's command and the notes on what it carries. The file of the
/// node's variables is written here.
fn prepare(args: &NodeArgs) -> Result<(Spec, Vec<String>), Refusal> {
    let name = label(args, "--install")?;
    let refused = [
        (args.temporary.is_some(), "--temporary", "the node of podssh ssh --upgrade ends with its last session"),
        (
            args.ephemeral_key,
            "--ephemeral-key",
            "each start of the service would bring a new key, which an operator that pinned the node's key refuses",
        ),
        (args.iroh_ephemeral, "--iroh-ephemeral", "each start of the service would bring a new key and a new ticket"),
    ];
    if let Some((_, flag, why)) = refused.iter().find(|(given, ..)| *given) {
        return Err(Refusal::usage(format!("--install with {flag}: {why}")));
    }
    let mut notes = Vec::new();
    // A pair that is missing or has expired makes a service that fails at
    // each start: it is read now.
    let pair = match (&args.pair_file, args.iroh) {
        (_, true) => None,
        (Some(file), false) => Some(crate::pairs::from_file(file)?),
        (None, false) => Some(crate::pairs::stored(&name)?),
    };
    if let Some(pair) = pair {
        notes.push(format!(
            "the pair expires at {}: then the node exits with 77, and the service stays down until a new pair \
             (podssh relay pair {name}) and podssh node {name} --install again",
            crate::pairs::utc(pair.expires_ms)
        ));
    }
    let exe = std::env::current_exe()
        .and_then(std::path::absolute)
        .map_err(|e| Refusal::config(format!("the path of this podssh is not known: {e}")))?;
    let (body, left) = env::body();
    for variable in left {
        notes.push(format!("{variable} is set and is not carried: a service keeps no token of the environment"));
    }
    let env_file = podssh_relay::cache::store_file(&env::file_name(&name), body.as_bytes())
        .map_err(|e| Refusal::config(format!("the file of the node's variables: {e}")))?;
    notes.push(format!(
        "its variables are in {}, a private file (a proxy's password too, when its URL has one)",
        env_file.display()
    ));
    let words = text::service_args(args, &name, &env_file)?;
    Ok((Spec { name, exe, args: words }, notes))
}

/// The ways of this system, in the order of the probe.
#[cfg(unix)]
const WAYS: &[fn(&Spec) -> Made] = &[unix::systemd, unix::cron];
#[cfg(windows)]
const WAYS: &[fn(&Spec) -> Made] = &[windows::schtasks];
#[cfg(not(any(unix, windows)))]
const WAYS: &[fn(&Spec) -> Made] = &[];

/// Make the service by the first way that is there; with none, the command
/// to run at login, and 69.
fn install(spec: &Spec, notes: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let name = &spec.name;
    let mut absent = Vec::new();
    for way in WAYS {
        match way(spec) {
            Made::Done(lines) => {
                for line in lines.iter().chain(notes) {
                    let _ = writeln!(err, "podssh node: {name}: {line}");
                }
                let _ = writeln!(err, "podssh node: {name}: podssh node {name} --uninstall removes it");
                return 0;
            }
            Made::Absent(why) => absent.push(why),
            Made::Failed(refusal) => return refusal.report("node", err),
        }
    }
    let _ = writeln!(
        err,
        "podssh node: {name}: no service of this user can be made here ({}); run this at login:",
        absent.join("; ")
    );
    let _ = writeln!(out, "{}", text::login_line(spec));
    for note in notes {
        let _ = writeln!(err, "podssh node: {name}: {note}");
    }
    let _ = writeln!(err, "podssh node: {name}: podssh node {name} --uninstall removes the file of its variables");
    EX_UNAVAILABLE
}

/// Remove what `--install` wrote for NAME, wherever it is: each way, and the
/// file of the node's variables. Nothing to remove is no failure.
fn uninstall(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    let name = match label(args, "--uninstall") {
        Ok(name) => name,
        Err(refusal) => return refusal.report("node", err),
    };
    #[cfg(unix)]
    let mut removed = unix::remove(&name);
    #[cfg(windows)]
    let mut removed = windows::remove(&name);
    #[cfg(not(any(unix, windows)))]
    let mut removed: Vec<String> = Vec::new();
    if let Some(path) = env::remove(&name) {
        removed.push(format!("removed the file of its variables, {}", path.display()));
    }
    if removed.is_empty() {
        let _ = writeln!(err, "podssh node: {name}: nothing that --install writes is here");
    }
    for line in removed {
        let _ = writeln!(err, "podssh node: {name}: {line}");
    }
    0
}

/// Run `cmd`, with no stdin, within [`PROGRAM_LIMIT`]: its output, or why
/// it did not run or end.
pub(crate) fn run(cmd: &mut Command) -> Result<Output, String> {
    let shown = format!("{:?}", cmd.get_program());
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{shown}: {e}"))?;
    // Read as the program writes, so that a long answer cannot hold it.
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = reader(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let stderr = reader(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let deadline = Instant::now() + PROGRAM_LIMIT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{shown} did not end within {} s", PROGRAM_LIMIT.as_secs()));
            }
            Err(e) => return Err(format!("{shown}: {e}")),
        }
    };
    Ok(Output { status, stdout: stdout.join().unwrap_or_default(), stderr: stderr.join().unwrap_or_default() })
}

/// The first line of a program's complaint, for a message.
pub(crate) fn said(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no message");
    format!("{} ({})", podssh_ws::text::one_line(line), output.status)
}
