//! The sudo and su of the test's server (T-032): a command of either,
//! until it starts.

/// A command of sudo (with its prompt) or of su (with none), until it starts.
pub(super) struct Elevated {
    pub(super) prompt: Option<String>,
    pub(super) started: String,
    pub(super) line: Vec<u8>,
}

/// The prompt of `sudo -S -k -p PROMPT -- sh -c '...'` (none for `su -c`),
/// and the marker that the command prints as it starts.
pub(super) fn elevation(command: &str) -> Option<(Option<String>, String)> {
    let started = command.split("printf %s ").nth(1)?.split_whitespace().next()?.to_string();
    if let Some(rest) = command.strip_prefix("sudo -S -k -p ") {
        Some((Some(rest.split_whitespace().next()?.to_string()), started))
    } else {
        command.starts_with("su -c ").then_some((None, started))
    }
}
