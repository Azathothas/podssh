//! `LocalCommand` and `PermitLocalCommand` (T-191), as OpenSSH 10.3p1 reads
//! them: with `PermitLocalCommand yes`, the command runs here after the
//! login, with the user's shell (`SHELL -c LINE`), and its `%` tokens are
//! those of `RemoteCommand` and `%T`, the tunnel device, which is `NONE`.
//! The user names the program, as with `SSH_ASKPASS`. The shell is chosen
//! before anything connects: `SHELL`, else `/bin/sh` when it is there, else
//! a refusal (78). Only `podssh ssh` runs it; the other commands that log
//! in, as OpenSSH's `scp` and `sftp`, run none.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use podssh_ssh::local_command::LocalCommand;
use podssh_ssh::Options;

use super::tokens::Tokens;
use crate::relay_settings::Refusal;

/// The variable that names the shell of `LocalCommand`.
pub const SHELL_ENV: &str = "SHELL";
/// The shell when `SHELL` names none.
const FALLBACK: &str = "/bin/sh";

/// The LocalCommand of a run, its tokens expanded: none unless
/// `PermitLocalCommand` is yes, as in OpenSSH. With `stream`, stdout
/// carries the stream of `-W`, and the command's stdout goes to stderr.
pub(super) fn plan(
    given: Option<&str>,
    permit: Option<bool>,
    tokens: &Tokens,
    stream: bool,
) -> Result<Option<LocalCommand>, String> {
    let (Some(line), Some(true)) = (given, permit) else { return Ok(None) };
    let line = tokens.local_command(line)?;
    Ok(Some(LocalCommand { line, shell: None, to_stderr: stream }))
}

/// Choose the shell of the LocalCommand of `options`, if it has one,
/// before anything connects.
pub fn shell(options: &mut Options) -> Result<(), Refusal> {
    let Some(local) = options.local_command.as_mut() else { return Ok(()) };
    local.shell = Some(choose(std::env::var_os(SHELL_ENV), Path::new(FALLBACK))?);
    Ok(())
}

/// `shell` when it names one, else `fallback` when it is a file there.
pub fn choose(shell: Option<OsString>, fallback: &Path) -> Result<PathBuf, Refusal> {
    if let Some(shell) = shell.filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(shell));
    }
    if fallback.is_file() {
        return Ok(fallback.to_path_buf());
    }
    Err(Refusal::config(format!(
        "LocalCommand needs a shell: {SHELL_ENV} is not set, and {} is not here; set {SHELL_ENV}, or leave \
         PermitLocalCommand at no",
        fallback.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens() -> Tokens {
        Tokens { host: "db.example.org".into(), original: "db".into(), port: 2222, ..Tokens::default() }
    }

    /// The plant of the entry: with no PermitLocalCommand, the command
    /// would run.
    #[test]
    fn the_command_runs_only_with_permit_local_command_yes() {
        let given = Some("touch /tmp/lc-%h");
        assert_eq!(plan(given, None, &tokens(), false), Ok(None));
        assert_eq!(plan(given, Some(false), &tokens(), false), Ok(None));
        assert_eq!(plan(None, Some(true), &tokens(), false), Ok(None));
        let local = plan(given, Some(true), &tokens(), false).unwrap().expect("a command");
        assert_eq!((local.line.as_str(), local.shell, local.to_stderr), ("touch /tmp/lc-db.example.org", None, false));
    }

    #[test]
    fn the_tokens_and_t_are_expanded_and_w_sends_stdout_to_stderr() {
        let local = plan(Some("echo %n:%p %T %%"), Some(true), &tokens(), true).unwrap().expect("a command");
        assert_eq!(local.line, "echo db:2222 NONE %");
        assert!(local.to_stderr);
        assert!(plan(Some("echo %Q"), Some(true), &tokens(), false).unwrap_err().contains("%Q"));
    }

    #[test]
    fn the_shell_is_shell_else_bin_sh_else_78() {
        let here = std::env::current_exe().unwrap();
        let none = Path::new("/no/such/shell/here");
        assert_eq!(choose(Some("/bin/zsh".into()), none), Ok(PathBuf::from("/bin/zsh")));
        assert_eq!(choose(Some(OsString::new()), &here), Ok(here.clone()), "an empty SHELL is none");
        assert_eq!(choose(None, &here), Ok(here));
        let refused = choose(None, none).unwrap_err();
        assert_eq!(refused.code, crate::exitmap::sysexits::EX_CONFIG);
        assert!(refused.message.contains("SHELL is not set"), "{}", refused.message);
    }
}
