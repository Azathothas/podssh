//! `LocalCommand` (T-191): a command that runs here after the login and
//! before the request, as OpenSSH runs it with `PermitLocalCommand yes`:
//! `SHELL -c LINE`, waited for, its exit status said with `-v` and changing
//! nothing. The user names the program, in the option or in ssh_config, and
//! the caller chooses the shell before anything connects.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::log::Log;
use crate::options::Options;
use crate::retry::{self, Phase};

/// The command of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommand {
    /// The command line, its `%` tokens expanded.
    pub line: String,
    /// The shell that runs it; `None` until the caller chose one, and with
    /// none it does not run.
    pub shell: Option<PathBuf>,
    /// Its stdout goes to stderr: stdout carries the stream of `-W`.
    pub to_stderr: bool,
}

/// Run the LocalCommand of `opts`, if it has one, and wait for its end.
pub async fn run(opts: &Options, log: &Log) {
    let Some(local) = &opts.local_command else { return };
    let Some(shell) = &local.shell else {
        log.verbose("LocalCommand: no shell was chosen for it, so it does not run");
        return;
    };
    // A try after a drop of the relay would run it twice (T-025).
    retry::reached(Phase::Requested);
    spawn(shell, local, log).await;
}

/// `shell -c LINE`, with no input, until it ends.
async fn spawn(shell: &Path, local: &LocalCommand, log: &Log) {
    log.verbose(&format!("LocalCommand: {} -c {}", shell.display(), local.line));
    let mut command = tokio::process::Command::new(shell);
    // Its input is not the session's: the session reads stdin next.
    command.arg("-c").arg(&local.line).stdin(Stdio::null());
    if local.to_stderr {
        command.stdout(std::io::stderr());
    }
    match command.status().await {
        Ok(status) if status.success() => {}
        Ok(status) => log.verbose(&format!("LocalCommand ended with {status}")),
        Err(e) => log.error(&format!("LocalCommand: {} could not run: {e}", shell.display())),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::options::LogLevel;

    /// The shell runs the line, with no input; a failure changes nothing.
    #[tokio::test]
    async fn the_shell_runs_the_line() {
        let dir = std::env::temp_dir().join(format!("podssh-local-command-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ran");
        let line = format!("read x; printf '%s' \"${{x:-none}}\" > {}", file.display());
        let local = LocalCommand { line, shell: Some(PathBuf::from("/bin/sh")), to_stderr: true };
        spawn(Path::new("/bin/sh"), &local, &Log::new(LogLevel::Quiet)).await;
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "none");
        let failing = LocalCommand { line: "exit 3".into(), ..local };
        spawn(Path::new("/bin/sh"), &failing, &Log::new(LogLevel::Quiet)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
