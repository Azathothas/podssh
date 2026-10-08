//! Asking the user something: on the controlling terminal, or through
//! `SSH_ASKPASS`, chosen the way OpenSSH chooses (ssh(1), ENVIRONMENT):
//!
//! - `SSH_ASKPASS_REQUIRE=force`: the askpass program, always;
//! - `SSH_ASKPASS_REQUIRE=prefer`: the askpass program when it is allowed
//!   (a `DISPLAY` or `WAYLAND_DISPLAY` is set), else the terminal;
//! - `SSH_ASKPASS_REQUIRE=never`: the terminal only;
//! - unset: the terminal, and the askpass program only when there is no
//!   terminal and it is allowed.
//!
//! When neither works the answer is [`PromptError::NoTerminal`], and the caller
//! turns that into a refusal that names a remedy. Nothing ever blocks waiting
//! for input that cannot arrive.

use std::ffi::OsString;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    /// No controlling terminal, and no askpass program allowed to stand in.
    NoTerminal,
    /// The user cancelled: Ctrl-C or Ctrl-D at a prompt, or the askpass
    /// program exited non-zero.
    Cancelled,
    /// The askpass program could not be run.
    Failed(String),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptError::NoTerminal => f.write_str("there is no terminal to ask on (and no SSH_ASKPASS)"),
            PromptError::Cancelled => f.write_str("cancelled"),
            PromptError::Failed(why) => write!(f, "SSH_ASKPASS failed: {why}"),
        }
    }
}

/// Ask `prompt`, echoing the answer or not.
pub fn ask(prompt: &str, echo: bool) -> Result<Zeroizing<String>, PromptError> {
    let askpass = std::env::var_os("SSH_ASKPASS").filter(|v| !v.is_empty());
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().to_ascii_lowercase();
    let display = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
    let (allowed, preferred) = match require.as_str() {
        "force" => (askpass.is_some(), true),
        "prefer" => (askpass.is_some() && display, true),
        "never" => (false, false),
        _ => (askpass.is_some() && display, false),
    };
    if let (true, true, Some(program)) = (allowed, preferred, askpass.as_ref()) {
        return run_askpass(program, prompt);
    }
    match crate::terminal::read_line(prompt, echo) {
        Ok(answer) => Ok(answer),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(PromptError::Cancelled),
        Err(_) => match (allowed, askpass.as_ref()) {
            (true, Some(program)) => run_askpass(program, prompt),
            _ => Err(PromptError::NoTerminal),
        },
    }
}

/// Whether [`ask`] could reach anyone, without asking: used to skip a method
/// rather than start it and fail halfway.
pub fn can_ask() -> bool {
    let askpass = std::env::var_os("SSH_ASKPASS").is_some_and(|v| !v.is_empty());
    let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default().to_ascii_lowercase();
    if askpass && require == "force" {
        return true;
    }
    let display = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
    controlling_terminal_exists() || (askpass && display && require != "never")
}

#[cfg(unix)]
fn controlling_terminal_exists() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok()
}

#[cfg(windows)]
fn controlling_terminal_exists() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("CONIN$").is_ok()
}

/// Run the askpass program with the prompt as its argument; its first line of
/// output is the answer.
fn run_askpass(program: &OsString, prompt: &str) -> Result<Zeroizing<String>, PromptError> {
    let output = Command::new(program)
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| PromptError::Failed(format!("{}: {e}", program.to_string_lossy())))?;
    let stdout = Zeroizing::new(output.stdout);
    if !output.status.success() {
        return Err(PromptError::Cancelled);
    }
    let text = String::from_utf8_lossy(&stdout);
    let first = text.split('\n').next().unwrap_or_default().trim_end_matches('\r');
    Ok(Zeroizing::new(first.to_string()))
}
