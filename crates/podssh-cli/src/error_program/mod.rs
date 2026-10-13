//! `PODSSH_ERROR_PROGRAM` (T-195): when podssh itself fails, it hands a
//! report of the failure to a program that the user names, as one JSON
//! object on the program's stdin ([`report`]): a script that files a ticket,
//! or a tool that asks an AI. podssh calls no AI service and no network
//! address for this; the program decides what to do with the report.
//!
//! **Only a failure of podssh.** A run that exits 0 starts nothing, and
//! neither does a status that podssh passes on, of a remote command or of a
//! child: the code path that gives such a status says so
//! ([`not_a_failure`]), so that a remote `exit 255` is never read as
//! podssh's own 255. A stop that the user asked for is no failure either.
//!
//! **The program runs as `SSH_ASKPASS` runs**: by its name, with no shell
//! and no argument. Its stdout and stderr go to podssh's stderr, as stdout
//! is data. It has [`LIMIT`], then it is stopped; its status is ignored,
//! and podssh's exit code stays the run's.

pub mod report;

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The variable that names the program.
pub const ENV: &str = "PODSSH_ERROR_PROGRAM";
/// How long the program may run before podssh stops it.
pub const LIMIT: Duration = Duration::from_secs(30);
/// The bytes of a line of stderr that are kept; [`podssh_ssh::said`] cuts
/// it shorter.
const LINE_CAP: usize = 4096;

/// Set by a code path whose exit code is no failure of podssh.
static NOT_A_FAILURE: AtomicBool = AtomicBool::new(false);

/// The exit code of this run passes on the status of a remote command or of
/// a child (`exec:`, an editor), which is no failure of podssh.
pub fn not_a_failure() {
    NOT_A_FAILURE.store(true, Ordering::Relaxed);
}

/// Whether a run that exits with `code` is a failure of podssh: not 0, not
/// a status that it passes on, and not 130 or 143, which podssh gives after
/// the user's SIGINT or SIGTERM once it has put the terminal back.
pub fn failed(code: i32, passed_on: bool) -> bool {
    code != 0 && !passed_on && !matches!(code, 130 | 143)
}

/// The program of a run, when the user named one.
#[derive(Debug)]
pub struct Hook {
    program: OsString,
    /// The command, as its canonical name: never the command line.
    verb: Option<&'static str>,
}

impl Hook {
    /// The program of [`ENV`] for a run whose first word is `first`; none
    /// when the variable is not set or empty. podssh then keeps its last
    /// messages for the report.
    pub fn from_env(first: Option<&OsStr>) -> Option<Hook> {
        let program = std::env::var_os(ENV).filter(|p| !p.is_empty())?;
        podssh_ssh::said::start();
        NOT_A_FAILURE.store(false, Ordering::Relaxed);
        let verb = first.and_then(OsStr::to_str).and_then(crate::flags::canonical_name);
        Some(Hook { program, verb })
    }

    /// After the run, which exits with `code`: the report to the program
    /// when podssh itself failed, else nothing.
    pub fn after(&self, code: i32, err: &mut dyn Write) {
        if !failed(code, NOT_A_FAILURE.load(Ordering::Relaxed)) {
            return;
        }
        let object = report::object(self.verb, code, &podssh_ssh::said::lines());
        let mut bytes = object.to_string().into_bytes();
        bytes.push(b'\n');
        start(&self.program, &bytes, err);
    }
}

/// Start `program` with `report` on its stdin. A podssh that the program
/// runs starts no program of its own, and the program gets none of
/// podssh's credentials through its environment; the proxy variables stay,
/// as the program may need the proxy itself.
fn start(program: &OsStr, report: &[u8], err: &mut dyn Write) {
    let mut command = Command::new(program);
    command.env_remove(ENV);
    for name in report::CREDENTIALS {
        command.env_remove(name);
    }
    give(command, report, LIMIT, err);
}

/// Run `command` with `report` on its stdin and its output on stderr, and
/// wait `limit` at most; then stop it. Each problem is one line on `err`.
pub fn give(mut command: Command, report: &[u8], limit: Duration, err: &mut dyn Write) {
    let shown = command.get_program().to_string_lossy().into_owned();
    command.stdin(Stdio::piped()).stdout(Stdio::from(std::io::stderr())).stderr(Stdio::inherit());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = writeln!(err, "podssh: {ENV} {shown} did not start: {e}");
            return;
        }
    };
    // From a thread: a program that reads no input must not hold podssh at
    // a full pipe, and its end closes the pipe for one that reads to it.
    if let Some(mut stdin) = child.stdin.take() {
        let report = report.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&report);
        });
    }
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let secs = limit.as_secs();
                let _ = writeln!(err, "podssh: {ENV} {shown} did not end within {secs} s, and was stopped");
                return;
            }
            Err(e) => {
                let _ = writeln!(err, "podssh: {ENV} {shown}: {e}");
                return;
            }
        }
    }
}

/// The stderr of the command line, with each whole line of it kept as one
/// of podssh's messages for the report.
pub struct Tee<'a> {
    inner: &'a mut dyn Write,
    line: Vec<u8>,
}

impl<'a> Tee<'a> {
    pub fn new(inner: &'a mut dyn Write) -> Self {
        Tee { inner, line: Vec::new() }
    }

    /// Keep a last line that came with no line break.
    pub fn finish(&mut self) {
        if !self.line.is_empty() {
            podssh_ssh::said::keep(&String::from_utf8_lossy(&self.line));
            self.line.clear();
        }
    }
}

impl Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        for &byte in &buf[..n] {
            if byte == b'\n' {
                podssh_ssh::said::keep(&String::from_utf8_lossy(&self.line));
                self.line.clear();
            } else if self.line.len() < LINE_CAP {
                self.line.push(byte);
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
