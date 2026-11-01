//! `podssh node NAME TARGET... --install` and `--uninstall` (T-121), and
//! `podssh ssh --install NAME -N -R ... --persist` (T-393, `ssh`): the run
//! as a service that this user may make with no privilege, found by a probe
//! at run time: a user unit of systemd when `systemctl --user` answers, else
//! a LaunchAgent when `launchctl` has this user's login session, else two
//! lines of the crontab (one at boot, one each 5 minutes) when `crontab -l`
//! answers; on Windows a task at logon (`schtasks`), never a Windows service,
//! which needs an administrator. With none of them, the command to run at
//! login is printed, and the exit is 69. Each way starts the run again
//! whenever it ends, with no limit of starts: a tunnel that stays down locks
//! its server out. The service runs this binary by its absolute path, with
//! the run's own arguments and `--env-file`: the variables that the run
//! reads (the proxy, the relay, the places of podssh's files) go into a
//! private file beside the pair, so that no token is on a command line or in
//! a unit file, and the pair's tokens stay in the pair's own file. A run with
//! `--env-file` holds a lock beside that file (`lock`), so that a second
//! start of the same service ends at once. `--uninstall` removes what
//! `--install` wrote, and nothing else.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

mod env;
#[cfg(unix)]
mod launchd;
pub(crate) mod lock;
pub(crate) mod ssh;
mod text;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;

/// The bound on each program that a probe or an install runs.
const PROGRAM_LIMIT: Duration = Duration::from_secs(10);

/// Which command a service runs: a node, or a tunnel of `podssh ssh`. The
/// names of its files and units come from it, so that a node and a tunnel
/// of the same NAME are two services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Node,
    Ssh,
}

impl Kind {
    pub fn verb(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Ssh => "ssh",
        }
    }

    /// How a person makes it again, after `podssh `.
    pub fn install_words(self, name: &str) -> String {
        match self {
            Kind::Node => format!("node {name} --install"),
            Kind::Ssh => format!("ssh --install {name}"),
        }
    }

    /// How a person removes it, after `podssh `.
    pub fn uninstall_words(self, name: &str) -> String {
        match self {
            Kind::Node => format!("node {name} --uninstall"),
            Kind::Ssh => format!("ssh --uninstall {name}"),
        }
    }

    /// `VERB-NAME`: the stem of the service's files, units and tasks.
    pub fn stem(self, name: &str) -> String {
        format!("{}-{name}", self.verb())
    }
}

/// What a service runs: this binary by its absolute path, and its words.
pub(crate) struct Spec {
    pub kind: Kind,
    pub name: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
    /// The directory that the run starts in, for the relative paths among
    /// the words that it keeps as typed (`podssh ssh`); none for a node,
    /// whose files are absolute already.
    pub dir: Option<PathBuf>,
    /// The file of `--env-file`, beside which a LaunchAgent's log goes.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub env_file: PathBuf,
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

/// One way of making a service, and how to remove what it made.
struct Way {
    make: fn(&Spec) -> Made,
    remove: fn(Kind, &str) -> Vec<String>,
}

/// The ways of this system, in the order of the probe.
#[cfg(unix)]
const WAYS: &[Way] = &[
    Way { make: unix::systemd, remove: unix::remove_systemd },
    Way { make: launchd::launchd, remove: launchd::remove },
    Way { make: unix::cron, remove: unix::remove_cron },
];
#[cfg(windows)]
const WAYS: &[Way] = &[Way { make: windows::schtasks, remove: windows::remove }];
#[cfg(not(any(unix, windows)))]
const WAYS: &[Way] = &[];

/// `podssh node`: the variables of `--env-file` and the lock of its service
/// first, then the node, or its install or uninstall.
pub fn dispatch(args: &NodeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Some(file) = &args.env_file {
        if args.install || args.uninstall {
            let why = "--env-file is the file that --install writes for the service: give it to the node alone";
            return Refusal::usage(why).report("node", err);
        }
        if let Err(refusal) = env::apply(Path::new(file)) {
            return refusal.report("node", err);
        }
        // The parent of --detach holds nothing: its child takes the lock.
        if !args.detach || crate::detach::is_child() {
            if let Some(code) = lock::enter("node", Some(file), err) {
                return code;
            }
        }
    }
    if args.detach && (args.install || args.uninstall || args.temporary.is_some()) {
        let why = "--detach sends this run into the background: it goes with no --install, --uninstall or --temporary";
        return Refusal::usage(why).report("node", err);
    }
    match (args.install, args.uninstall) {
        (true, true) => Refusal::usage("--install and --uninstall: give one").report("node", err),
        (true, false) => match prepare(args) {
            Ok((spec, notes)) => install(&spec, &notes, out, err),
            Err(refusal) => refusal.report("node", err),
        },
        (false, true) => match label(args, "--uninstall") {
            Ok(name) => uninstall(Kind::Node, &name, err),
            Err(refusal) => refusal.report("node", err),
        },
        (false, false) => crate::node::run_node(args, err),
    }
}

/// The label of `--install` or `--uninstall`, checked.
fn label(args: &NodeArgs, flag: &str) -> Result<String, Refusal> {
    let name = args.name.clone().ok_or_else(|| Refusal::usage(format!("{flag} needs NAME, the label of a pair")))?;
    crate::pairs::check_label(&name)?;
    Ok(name)
}

/// This binary by its absolute path, as a service starts in another
/// directory.
pub(crate) fn this_binary() -> Result<PathBuf, Refusal> {
    std::env::current_exe()
        .and_then(std::path::absolute)
        .map_err(|e| Refusal::config(format!("the path of this podssh is not known: {e}")))
}

/// The private file of the variables of `kind`'s service NAME, written now,
/// and the notes on what it carries.
pub(crate) fn env_file(kind: Kind, name: &str, notes: &mut Vec<String>) -> Result<PathBuf, Refusal> {
    let (body, left) = env::body();
    for variable in left {
        notes.push(format!("{variable} is set and is not carried: a service keeps no token of the environment"));
    }
    let file = podssh_relay::cache::store_file(&env::file_name(kind, name), body.as_bytes())
        .map_err(|e| Refusal::config(format!("the file of the service's variables: {e}")))?;
    notes.push(format!(
        "its variables are in {}, a private file (a proxy's password too, when its URL has one)",
        file.display()
    ));
    Ok(file)
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
    // The iroh road and the DERP road serve with no pair (T-379).
    let pair = match (&args.pair_file, args.iroh || args.derp) {
        (_, true) => None,
        (Some(file), false) => Some(crate::pairs::from_file(file)?),
        (None, false) => Some(crate::pairs::stored(&name)?),
    };
    if let Some(pair) = pair {
        notes.push(format!(
            "the pair expires at {}: then the node exits with 77, and the service starts it again, in vain until \
             a new pair (podssh relay pair {name}), which its next start takes",
            crate::pairs::utc(pair.expires_ms)
        ));
    }
    let exe = this_binary()?;
    let env_file = env_file(Kind::Node, &name, &mut notes)?;
    let words = text::service_args(args, &name, &env_file)?;
    Ok((Spec { kind: Kind::Node, name, exe, args: words, dir: None, env_file }, notes))
}

/// Make the service by the first way that is there, and remove what another
/// way made for it before, which would start a second copy; with none, the
/// command to run at login, and 69.
pub(crate) fn install(spec: &Spec, notes: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (verb, name) = (spec.kind.verb(), &spec.name);
    let mut absent = Vec::new();
    for (at, way) in WAYS.iter().enumerate() {
        match (way.make)(spec) {
            Made::Done(lines) => {
                let others = WAYS.iter().enumerate().filter(|(other, _)| *other != at);
                let earlier: Vec<String> = others
                    .flat_map(|(_, other)| (other.remove)(spec.kind, name))
                    .map(|line| format!("an earlier --install of another way: {line}"))
                    .collect();
                for line in lines.iter().chain(&earlier).chain(notes) {
                    let _ = writeln!(err, "podssh {verb}: {name}: {line}");
                }
                let _ = writeln!(err, "podssh {verb}: {name}: podssh {} removes it", spec.kind.uninstall_words(name));
                return 0;
            }
            Made::Absent(why) => absent.push(why),
            Made::Failed(refusal) => return refusal.report(verb, err),
        }
    }
    let _ = writeln!(
        err,
        "podssh {verb}: {name}: no service of this user can be made here ({}); run this at login:",
        absent.join("; ")
    );
    let _ = writeln!(out, "{}", text::login_line(spec));
    for note in notes {
        let _ = writeln!(err, "podssh {verb}: {name}: {note}");
    }
    let removes = spec.kind.uninstall_words(name);
    let _ = writeln!(err, "podssh {verb}: {name}: podssh {removes} removes the file of its variables");
    EX_UNAVAILABLE
}

/// Remove what `--install` wrote for `kind`'s NAME, wherever it is: each
/// way, and the files of its variables and its lock. Nothing to remove is
/// no failure.
pub(crate) fn uninstall(kind: Kind, name: &str, err: &mut dyn Write) -> i32 {
    let verb = kind.verb();
    let mut removed: Vec<String> = WAYS.iter().flat_map(|way| (way.remove)(kind, name)).collect();
    if let Some(path) = env::remove(kind, name) {
        removed.push(format!("removed the file of its variables, {}", path.display()));
    }
    if removed.is_empty() {
        let _ = writeln!(err, "podssh {verb}: {name}: nothing that --install writes is here");
    }
    for line in removed {
        let _ = writeln!(err, "podssh {verb}: {name}: {line}");
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
