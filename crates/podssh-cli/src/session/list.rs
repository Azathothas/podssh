//! `podssh session list` (T-186, T-506): a line for each session of the
//! cache's directories, its name, its state and its host, with a tab
//! between them; with `--json`, one object. A script that reads stdout must
//! tell "none" from a list that could not be made, so:
//!
//! - with nothing to list, stdout stays empty and one line on stderr says
//!   so and names the directories read (none with `-q`);
//! - a session whose podssh takes the connection and gives no answer within
//!   its wait is a line of the list, with the state `no-answer`, and why on
//!   stderr: it is there, busy or stuck, and a script that counts the lines
//!   counts it;
//! - a socket that nobody serves is no session (its podssh ended, as in a
//!   crash), and the next `start` of its name takes its place;
//! - a directory that is there and cannot be read is a line on stderr with
//!   its error, and a field of the JSON.
//!
//! The exit is 0 in each case: the list is what was found.

use std::io::Write;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::client::{self, text};
use super::place::{self, Found};
use super::wire::{self, Op};
use super::SessionArgs;

/// How long `list` waits for each session.
pub const LIST_WAIT: Duration = Duration::from_secs(2);
/// The state of a session that did not answer within [`LIST_WAIT`].
pub const NO_ANSWER: &str = "no-answer";

/// One line of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub state: String,
    pub host: String,
    pub socket: String,
}

/// What the question of one session gave.
enum Asked {
    Answer(Map<String, Value>),
    /// Nobody serves the socket.
    Unserved,
    /// It took the connection, or refused it, and gave no answer: why.
    Failed(String),
}

/// Run `podssh session list`; the exit code.
pub fn list(args: &SessionArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let quiet = args.ssh.quiet > 0;
    let found = place::all();
    let mut listed = Vec::new();
    if !found.sessions.is_empty() {
        let Some(runtime) = super::runtime(err) else { return super::NO_RUNTIME };
        for (name, socket) in &found.sessions {
            let line = wire::request(name, &Op::Info);
            let (state, host) = match runtime.block_on(ask(socket, &line)) {
                Asked::Unserved => continue,
                Asked::Answer(fields) => (state_of(&fields), text(&fields, "host").to_string()),
                Asked::Failed(why) => {
                    if !quiet {
                        let _ = writeln!(err, "podssh session: {name}: {why}");
                    }
                    (NO_ANSWER.to_string(), String::new())
                }
            };
            listed.push(Listed { name: name.clone(), state, host, socket: socket.clone() });
        }
        runtime.shutdown_background();
    }
    if !quiet {
        for (dir, why) in &found.unreadable {
            let _ = writeln!(err, "podssh session: {dir}: {why}; its sessions are not listed");
        }
    }
    if args.json {
        let _ = writeln!(out, "{}", json_of(&listed, &found));
        return 0;
    }
    for l in &listed {
        let _ = writeln!(out, "{}\t{}\t{}", l.name, l.state, l.host);
    }
    if listed.is_empty() && !quiet {
        let _ = writeln!(err, "{}", none_line(&found));
    }
    0
}

/// Ask the session at `socket` for its state: a socket that refuses the
/// connect because nobody listens is none, any other failure an answer
/// that did not come.
async fn ask(socket: &str, line: &str) -> Asked {
    let end = match crate::pipe::unix::connect(socket).await {
        Ok(end) => end,
        Err(e) if client::unserved(&e) => return Asked::Unserved,
        Err(e) => return Asked::Failed(format!("{socket}: {e}")),
    };
    match client::exchange(socket, end, line, LIST_WAIT).await {
        Ok(fields) => Asked::Answer(fields),
        Err((_, why)) => Asked::Failed(why),
    }
}

/// `running`, or `ended STATUS` once its command ended.
fn state_of(fields: &Map<String, Value>) -> String {
    match fields.get("status").and_then(Value::as_i64) {
        Some(status) => format!("ended {status}"),
        None => text(fields, "state").to_string(),
    }
}

/// The line of an empty list: which directories were read, or why none.
pub fn none_line(found: &Found) -> String {
    if found.looked.is_empty() {
        return format!(
            "podssh session: no session runs: {} is none, so no directory of sessions is read \
             (a session of --socket is not listed)",
            podssh_relay::cache::DIR_ENV
        );
    }
    if !found.read.is_empty() {
        return format!("podssh session: no session runs (the directories read: {})", found.read.join(", "));
    }
    if found.unreadable.is_empty() {
        return format!(
            "podssh session: no session runs: no directory of sessions is there yet (the first: {})",
            found.looked[0]
        );
    }
    "podssh session: no session is known: no directory of sessions could be read".to_string()
}

/// The list as one object: each session (`[]` for none), the directories
/// read, and those that could not be read, with why.
pub fn json_of(listed: &[Listed], found: &Found) -> Value {
    let sessions: Vec<Value> = listed
        .iter()
        .map(|l| json!({ "name": l.name, "state": l.state, "host": l.host, "socket": l.socket }))
        .collect();
    let unreadable: Vec<Value> =
        found.unreadable.iter().map(|(dir, why)| json!({ "dir": dir, "error": why })).collect();
    json!({ "sessions": sessions, "read": found.read, "unreadable": unreadable })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(looked: &[&str], read: &[&str], unreadable: &[(&str, &str)]) -> Found {
        Found {
            sessions: Vec::new(),
            looked: looked.iter().map(|s| s.to_string()).collect(),
            read: read.iter().map(|s| s.to_string()).collect(),
            unreadable: unreadable.iter().map(|(d, w)| (d.to_string(), w.to_string())).collect(),
        }
    }

    /// The line of an empty list says which directories were read, or why
    /// none was.
    #[test]
    fn an_empty_list_says_what_was_read() {
        let line = none_line(&found(&["/c/sessions", "/t/sessions"], &["/c/sessions"], &[]));
        assert_eq!(line, "podssh session: no session runs (the directories read: /c/sessions)");
        let line = none_line(&found(&["/c/sessions"], &[], &[]));
        assert!(line.contains("no directory of sessions is there yet (the first: /c/sessions)"), "{line}");
        let line = none_line(&found(&["/c/sessions"], &[], &[("/c/sessions", "Permission denied")]));
        assert!(line.contains("no session is known: no directory of sessions could be read"), "{line}");
        assert!(none_line(&found(&[], &[], &[])).contains("PODSSH_CACHE_DIR is none"));
    }

    /// A directory that is not there holds none; one that cannot be read
    /// (here a file, which no user lists, root too) is named with its
    /// error; a socket's file of a session's name is a session.
    #[test]
    fn a_look_names_each_directory_read_and_each_that_was_not() {
        let base = std::env::temp_dir().join(format!("podssh-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (good, file, missing) = (base.join("good"), base.join("file"), base.join("missing"));
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(good.join("w.sock"), b"").unwrap();
        std::fs::write(good.join("not a name.sock"), b"").unwrap();
        std::fs::write(&file, b"").unwrap();
        let found = place::all_in(&[good.clone(), file.clone(), missing]);
        assert_eq!(found.sessions, [("w".to_string(), good.join("w.sock").display().to_string())]);
        assert_eq!(found.read, [good.display().to_string()]);
        assert_eq!(found.unreadable.len(), 1, "{found:?}");
        assert_eq!(found.unreadable[0].0, file.display().to_string());
        assert_eq!(found.looked.len(), 3);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The JSON of an empty list is `[]`, with the directories read.
    #[test]
    fn the_json_of_a_list_holds_each_session_and_the_directories() {
        let empty = json_of(&[], &found(&["/c/sessions"], &["/c/sessions"], &[("/t/sessions", "denied")]));
        assert_eq!(empty["sessions"], json!([]));
        assert_eq!(empty["read"], json!(["/c/sessions"]));
        assert_eq!(empty["unreadable"], json!([{ "dir": "/t/sessions", "error": "denied" }]));
        let one = Listed { name: "w".into(), state: NO_ANSWER.into(), host: String::new(), socket: "/c/w.sock".into() };
        let doc = json_of(&[one], &found(&["/c"], &["/c"], &[]));
        assert_eq!(doc["sessions"][0]["state"], "no-answer");
        assert_eq!(doc["sessions"][0]["socket"], "/c/w.sock");
    }
}
