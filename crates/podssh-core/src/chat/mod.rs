//! Chat between two podssh ends (T-099), with no I/O: the records that go
//! over the end-to-end channel of the roads (T-088), and the state of one
//! conversation. The caller carries the bytes, reads the user's lines, and
//! writes the files that the user accepted; nothing here touches a file,
//! and nothing that arrives is run.

pub mod record;
pub mod session;

pub use record::{DecodeError, Decoder, Record};
pub use session::{Event, ProtocolError, Refused, Session};

/// A file's offered name as a name that can be written in a directory: its
/// last part, with no control character, not `.` or `..`, and not empty.
/// `None` when nothing of it is left: the user then gives a path.
pub fn safe_name(offered: &str) -> Option<String> {
    let last = offered.rsplit(['/', '\\']).next().unwrap_or_default();
    let name: String = last.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim().trim_end_matches(['.', ' ']);
    let reserved = matches!(name, "" | "." | "..") || name.contains(':');
    (!reserved && name.len() <= record::MAX_NAME).then(|| name.to_string())
}
