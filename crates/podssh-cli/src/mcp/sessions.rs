//! The sessions of `podssh mcp` (T-488), behind `--allow-session`: a shell
//! with a pty on an allowed host that outlives each call, as `podssh
//! session` keeps one. `session_start`, `session_send`, `session_wait`,
//! `session_capture` and `session_stop` are each a child of `podssh
//! session`; the start carries the options that `ssh_exec` forces. A
//! session's daemon outlives its call, and would outlive the server: the
//! server drives only the sessions that it started, never the user's own,
//! and stops each of them as it ends, so that none stays on the host with no
//! owner. The text to type goes on the child's stdin, never on its command
//! line.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::allow::Allow;
use super::child::{Outcome, Plan, Ran};
use super::tools::{
    boolean, destination, forced, known, limit, limit_property, object_needing, streams, string, Settings,
};

/// The limit of a call when it names none.
const LIMIT: u64 = 60;
/// What a call of `session_wait` has past the wait's own limit.
const WAIT_MARGIN: u64 = 30;
/// What a start has past its wait for the session to be ready.
const START_MARGIN: u64 = 10;
/// The most bytes of a screen, or of the raw output, kept.
const SCREEN_CAP: usize = 1 << 20;
/// How long the stop of each session may take as the server ends.
const STOP_LIMIT: Duration = Duration::from_secs(10);
/// The exits of `session wait` when its limit passed first, and of a
/// session that is not there.
const NOT_YET: i32 = 75;
const NO_SESSION: i32 = 69;

/// The sessions that this server started, by name.
#[derive(Debug, Clone, Default)]
pub struct Started(Arc<Mutex<BTreeSet<String>>>);

impl Started {
    fn lock(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take `name` for a start; refused when this server holds one of it.
    fn reserve(&self, name: &str) -> Result<(), String> {
        match self.lock().insert(name.to_string()) {
            true => Ok(()),
            false => Err(format!("session {name}: this server started one of that name; session_stop ends it")),
        }
    }

    fn holds(&self, name: &str) -> bool {
        self.lock().contains(name)
    }

    fn forget(&self, name: &str) {
        self.lock().remove(name);
    }

    /// The names, in order.
    pub fn names(&self) -> Vec<String> {
        self.lock().iter().cloned().collect()
    }
}

/// The tools, when a host is allowed and `--allow-session` given.
#[rustfmt::skip]
pub fn list(allow: &Allow) -> Vec<Value> {
    let hosts = allow.shown();
    let name = json!({ "type": "string", "description": "the session's name: letters, digits, _ and -, 32 at most" });
    let changes = json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true });
    let reads = json!({ "readOnlyHint": true, "openWorldHint": true });
    let tool = |tool: &str, title: &str, description: String, properties: Value, required: &[&str], notes: &Value| {
        json!({ "name": tool, "title": title, "description": description,
            "inputSchema": object_needing(properties, required), "annotations": notes })
    };
    vec![
        tool("session_start", "Start a shell that outlives the call",
            format!("podssh session start on an allowed host ({hosts}): a shell, or command, with a pty, held by a \
                podssh of this host until session_stop, or until this server ends, which stops it."),
            json!({ "name": name, "destination": { "type": "string", "description": format!("[user@]host, a host that matches {hosts}") },
                "command": { "type": "string", "description": "the command to run in place of the login shell" },
                "timeout_seconds": limit_property(LIMIT) }),
            &["name", "destination"], &changes),
        tool("session_send", "Type into a session",
            "podssh session send: type text into a session that this server started, then Enter unless enter is \
                false; \\r is Enter, \\u0003 is Ctrl-C.".into(),
            json!({ "name": name, "text": { "type": "string" }, "enter": { "type": "boolean" } }),
            &["name", "text"], &changes),
        tool("session_wait", "Wait until a session's output stops or shows a text",
            "podssh session wait: until the output has stopped for idle_seconds (default 2) or match comes, counted \
                from the last send, at most wait_seconds (default 60); ended_by says which, or limit.".into(),
            json!({ "name": name, "match": { "type": "string", "minLength": 1 },
                "idle_seconds": { "type": "integer", "minimum": 1, "maximum": 600 },
                "wait_seconds": { "type": "integer", "minimum": 1, "maximum": super::tools::SSH_LIMIT_MAX } }),
            &["name"], &reads),
        tool("session_capture", "Read a session's screen",
            "podssh session capture: the session's screen as text, or with raw the last 64 KiB of its output as it \
                came.".into(),
            json!({ "name": name, "raw": { "type": "boolean" } }), &["name"], &reads),
        tool("session_stop", "Stop a session",
            "podssh session stop: end a session that this server started, and its shell.".into(),
            json!({ "name": name }), &["name"], &changes),
    ]
}

/// The child of a call of a session; `None` for another tool.
pub fn plan(settings: &Settings, tool: &str, arguments: &Map<String, Value>) -> Option<Result<Plan, String>> {
    let names: &[&str] = match tool {
        "session_start" => &["name", "destination", "command", "timeout_seconds"],
        "session_send" => &["name", "text", "enter"],
        "session_wait" => &["name", "match", "idle_seconds", "wait_seconds"],
        "session_capture" => &["name", "raw"],
        "session_stop" => &["name"],
        _ => return None,
    };
    Some(known(arguments, names).and_then(|()| plan_of(settings, tool, arguments)))
}

fn plan_of(settings: &Settings, tool: &str, arguments: &Map<String, Value>) -> Result<Plan, String> {
    if !settings.allow_session {
        return Err("sessions are off: podssh mcp was started with no --allow-session".into());
    }
    let name = string(arguments, "name")?.ok_or("name: required, the session's name")?;
    crate::session::check_name(&name)?;
    let words = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
    if tool == "session_start" {
        let destination = destination(settings, arguments)?;
        let seconds = limit(arguments, LIMIT)?;
        let mut argv = words(&["session", "start", &name]);
        argv.extend(forced(settings));
        argv.extend(words(&["--timeout", &format!("{seconds}s"), "--", &destination]));
        if let Some(command) = string(arguments, "command")?.filter(|c| !c.is_empty()) {
            if command.contains('\0') {
                return Err("command: a NUL character".into());
            }
            argv.push(command.into());
        }
        // Last, once each check passed: a refused call holds no name.
        settings.started.reserve(&name)?;
        let limit = Duration::from_secs(seconds + START_MARGIN);
        return Ok(Plan { argv, stdin: Vec::new(), limit, cap: SCREEN_CAP });
    }
    if !settings.started.holds(&name) {
        return Err(format!("session {name}: not one that this server started; session_start starts one"));
    }
    let mut plan = Plan { argv: Vec::new(), stdin: Vec::new(), limit: Duration::from_secs(LIMIT), cap: SCREEN_CAP };
    match tool {
        "session_send" => {
            let mut text = string(arguments, "text")?.ok_or("text: required, what to type")?.into_bytes();
            if boolean(arguments, "enter")?.unwrap_or(true) {
                text.push(b'\r');
            }
            if text.len() > crate::session::SEND_MAX {
                return Err(format!("text: {} bytes types at most at once", crate::session::SEND_MAX));
            }
            plan.argv = words(&["session", "send", &name]);
            plan.stdin = text;
        }
        "session_wait" => {
            let mut argv = words(&["session", "wait", &name]);
            if let Some(idle) = whole(arguments, "idle_seconds", 600)? {
                argv.extend(words(&["--idle", &format!("{idle}s")]));
            }
            if let Some(text) = string(arguments, "match")? {
                if text.is_empty() || text.contains('\0') {
                    return Err("match: a text, not empty, with no NUL".into());
                }
                argv.push(format!("--match={text}").into());
            }
            let wait = whole(arguments, "wait_seconds", super::tools::SSH_LIMIT_MAX)?.unwrap_or(LIMIT);
            argv.extend(words(&["--timeout", &format!("{wait}s")]));
            plan.argv = argv;
            plan.limit = Duration::from_secs(wait + WAIT_MARGIN);
        }
        "session_capture" => {
            plan.argv = words(&["session", "capture", &name]);
            if boolean(arguments, "raw")?.unwrap_or(false) {
                plan.argv.push("--raw".into());
            }
        }
        _ => plan.argv = words(&["session", "stop", &name]),
    }
    Ok(plan)
}

/// A whole number of a call, from 1 to `high`.
fn whole(arguments: &Map<String, Value>, name: &str, high: u64) -> Result<Option<u64>, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=high).contains(n))
            .map(Some)
            .ok_or(format!("{name}: a whole number from 1 to {high}")),
    }
}

/// After a call of a session: a start that failed frees its name, and a
/// stop forgets it; a start that the client cancelled, or that passed its
/// limit, may have started, and stays to be stopped at the end.
pub fn settle(settings: &Settings, tool: &str, arguments: &Map<String, Value>, outcome: &Outcome) {
    let Some(name) = arguments.get("name").and_then(Value::as_str) else { return };
    let exit = match outcome {
        Outcome::Ran(ran) if !ran.timed_out => ran.exit,
        Outcome::NotStarted(_) => None,
        _ => return,
    };
    match tool {
        "session_start" if exit != Some(0) => settings.started.forget(name),
        "session_stop" if matches!(exit, Some(0) | Some(NO_SESSION)) => settings.started.forget(name),
        _ => {}
    }
}

/// The stop of each session that this server started, as it ends.
pub fn stops(settings: &Settings) -> Vec<Plan> {
    let stop = |name: &str| ["session", "stop", name].map(OsString::from).to_vec();
    let names = settings.started.names();
    names.iter().map(|name| Plan { argv: stop(name), stdin: Vec::new(), limit: STOP_LIMIT, cap: 64 << 10 }).collect()
}

/// The result of a call of a session; `None` for another tool.
pub fn shape(tool: &str, ran: &Ran) -> Option<(Value, bool)> {
    let mut value = streams(ran);
    let out = String::from_utf8_lossy(&ran.stdout.bytes).trim().to_string();
    let failed = match tool {
        "session_start" => {
            value.insert("socket".into(), if ran.exit == Some(0) { json!(out) } else { Value::Null });
            ran.exit != Some(0)
        }
        "session_wait" => {
            let ended_by = match ran.exit {
                Some(0) => json!(out),
                Some(NOT_YET) => json!("limit"),
                _ => Value::Null,
            };
            value.insert("ended_by".into(), ended_by);
            !matches!(ran.exit, Some(0) | Some(NOT_YET))
        }
        "session_send" | "session_capture" | "session_stop" => ran.exit != Some(0),
        _ => return None,
    };
    Some((Value::Object(value), failed || ran.timed_out))
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
