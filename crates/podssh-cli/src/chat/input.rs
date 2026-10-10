//! What a line of the user means: a message, or a command on files. A line
//! that starts with `//` is a message that starts with `/`.

use std::path::PathBuf;

/// One line of the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    Say(String),
    /// `/file PATH`: offer a file.
    Offer(PathBuf),
    /// `/accept ID [PATH]`: take a file, into PATH (a directory or a new
    /// file's path), else into the working directory.
    Accept {
        id: u64,
        to: Option<PathBuf>,
    },
    /// `/decline ID`.
    Decline(u64),
    /// `/quit`: end the conversation.
    Quit,
    /// An empty line: nothing.
    Nothing,
}

/// The words of the commands, for the user's help.
pub const HELP: &str =
    "/file PATH offers a file; /accept ID [PATH] takes one; /decline ID refuses it; /quit ends; // starts a message with /";

/// The act of `line`; `Err` names what is wrong with a command.
pub fn parse(line: &str) -> Result<Act, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return Ok(Act::Nothing);
    }
    if let Some(rest) = line.strip_prefix("//") {
        return Ok(Act::Say(format!("/{rest}")));
    }
    let Some(command) = line.strip_prefix('/') else { return Ok(Act::Say(line.to_string())) };
    let mut words = command.splitn(2, char::is_whitespace);
    let verb = words.next().unwrap_or_default();
    let rest = words.next().unwrap_or_default().trim();
    let id = |text: &str| text.parse::<u64>().map_err(|_| format!("/{verb} needs the number of a file, not {text:?}"));
    match verb {
        "file" if !rest.is_empty() => Ok(Act::Offer(PathBuf::from(rest))),
        "accept" if !rest.is_empty() => {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let number = id(parts.next().unwrap_or_default())?;
            let to = parts.next().map(str::trim).filter(|p| !p.is_empty()).map(PathBuf::from);
            Ok(Act::Accept { id: number, to })
        }
        "decline" if !rest.is_empty() => Ok(Act::Decline(id(rest)?)),
        "quit" => Ok(Act::Quit),
        _ => Err(format!("{line:?} is no command: {HELP}")),
    }
}
