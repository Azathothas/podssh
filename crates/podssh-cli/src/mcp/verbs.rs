//! The tools of `podssh health` and `podssh job` (T-488): each a child of
//! its verb, on a host that `--allow-host` lets in, with the options that
//! `ssh_exec` forces, so that no tool reaches a host, or runs a command
//! there, where `ssh_exec` could not. A job outlives its call: `job_wait`
//! waits under the call's limit, and gives the job's state when it has not
//! ended, as a result and not an error, for the agent to call it again.

use std::ffi::OsString;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::allow::Allow;
use super::child::{text, Captured, Plan, Ran};
use super::tools::{
    destination, forced, known, limit, limit_property, object_needing, streams, string, Settings, OWN_CAP,
};

/// The limit of a call of these tools when it names none.
const LIMIT: u64 = 60;
/// The hex digits of a job's ID, as `podssh job` makes it.
const JOB_ID: usize = 8;
/// The bytes of a log in one call when it names none, and the most.
const LOG_DEFAULT: u64 = 256 << 10;
const LOG_MAX: u64 = 1 << 20;
/// The furthest offset into a log: the child's output is kept up to the
/// offset and the bytes of the call, as `job log` has no offset of its own.
const LOG_FURTHEST: u64 = 31 << 20;
/// What a call of `job_wait` has past the wait's own limit: the login and the
/// answer.
const WAIT_MARGIN: u64 = 30;
/// The exit of `job wait` when the job had not ended within its limit.
const NOT_ENDED: i32 = 75;

/// The tools, when a host is allowed: a table, one tool to a call.
#[rustfmt::skip]
pub fn list(allow: &Allow) -> Vec<Value> {
    let hosts = allow.shown();
    let dest = json!({ "type": "string", "description": format!("[user@]host, a host that matches {hosts}") });
    let id = json!({ "type": "string", "description": "the job's ID, 8 hex digits, as job_start gave it" });
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": true });
    let changes =
        json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true });
    let tool = |name: &str, title: &str, description: String, properties: Value, required: &[&str], notes: &Value| {
        json!({ "name": name, "title": title, "description": description,
            "inputSchema": object_needing(properties, required), "annotations": notes })
    };
    vec![
        tool("health", "The far host's load, memory, disks and processes",
            format!("podssh health --json on an allowed host ({hosts}): its load, CPUs, memory, uptime, network, \
                disks and processes, read over one exec that only reads, as one JSON object."),
            json!({ "destination": dest, "timeout_seconds": limit_property(LIMIT) }), &["destination"], &read_only),
        tool("job_start", "Start a job that outlives the call",
            format!("podssh job start on an allowed host ({hosts}): the command runs in the host's tmux, and goes \
                on after the call; the result's id names it for job_log, job_wait and job_stop."),
            json!({ "destination": dest, "timeout_seconds": limit_property(LIMIT),
                "command": { "type": "string", "minLength": 1, "description": "the command line, for sh on the host" } }),
            &["destination", "command"], &changes),
        tool("job_list", "The jobs of a host",
            "podssh job list --json: each job of the host with its id, state, status, start and command.".into(),
            json!({ "destination": dest, "timeout_seconds": limit_property(LIMIT) }), &["destination"], &read_only),
        tool("job_log", "A part of a job's output",
            "podssh job log: the job's output, from offset, at most max_bytes (256 KiB by default, 1 MiB at most); \
                more says that bytes come after, from next_offset.".into(),
            json!({ "destination": dest, "id": id, "timeout_seconds": limit_property(LIMIT),
                "offset": { "type": "integer", "minimum": 0, "maximum": LOG_FURTHEST },
                "max_bytes": { "type": "integer", "minimum": 1, "maximum": LOG_MAX } }),
            &["destination", "id"], &read_only),
        tool("job_wait", "Wait for a job to end",
            "podssh job wait: until the job ends, at most wait_seconds (default 30); ended says whether it did, \
                and exit is then its status. A job that runs on is a result: call job_wait again.".into(),
            json!({ "destination": dest, "id": id,
                "wait_seconds": { "type": "integer", "minimum": 1, "maximum": super::tools::SSH_LIMIT_MAX } }),
            &["destination", "id"], &read_only),
        tool("job_stop", "Stop a job",
            "podssh job stop: end the job's tmux session of that exact name, and remove the job.".into(),
            json!({ "destination": dest, "id": id, "timeout_seconds": limit_property(LIMIT) }),
            &["destination", "id"], &changes),
    ]
}

/// The child of a call of one of these tools; `None` for another tool.
pub fn plan(settings: &Settings, name: &str, arguments: &Map<String, Value>) -> Option<Result<Plan, String>> {
    let names: &[&str] = match name {
        "health" | "job_list" => &["destination", "timeout_seconds"],
        "job_start" => &["destination", "command", "timeout_seconds"],
        "job_log" => &["destination", "id", "offset", "max_bytes", "timeout_seconds"],
        "job_wait" => &["destination", "id", "wait_seconds"],
        "job_stop" => &["destination", "id", "timeout_seconds"],
        _ => return None,
    };
    Some(known(arguments, names).and_then(|()| plan_of(settings, name, arguments)))
}

fn plan_of(settings: &Settings, name: &str, arguments: &Map<String, Value>) -> Result<Plan, String> {
    let destination = destination(settings, arguments)?;
    // job_wait's limit follows its wait, and it takes no timeout_seconds.
    let mut seconds = limit(arguments, LIMIT)?;
    let words = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
    let verb = if name == "health" { "health" } else { "job" };
    let mut argv = words(&[verb]);
    argv.extend(forced(settings));
    let mut cap = OWN_CAP;
    match name {
        "health" => argv.extend(words(&["--json", "--", &destination])),
        "job_list" => argv.extend(words(&["list", "--json", &destination])),
        "job_start" => {
            let command = string(arguments, "command")?.filter(|c| !c.is_empty()).ok_or("command: required")?;
            if command.contains('\0') {
                return Err("command: a NUL character".into());
            }
            argv.extend(words(&["start", &destination, "--", &command]));
        }
        "job_wait" => {
            let wait = whole(arguments, "wait_seconds", 1, super::tools::SSH_LIMIT_MAX)?.unwrap_or(30);
            argv.extend(words(&["wait", "--timeout", &format!("{wait}s"), &destination, &job_id(arguments)?]));
            seconds = wait + WAIT_MARGIN;
        }
        "job_log" => {
            let (offset, most) = log_window(arguments)?;
            cap = (offset + most) as usize;
            argv.extend(words(&["log", &destination, &job_id(arguments)?]));
        }
        _ => argv.extend(words(&["stop", &destination, &job_id(arguments)?])),
    }
    Ok(Plan { argv, stdin: Vec::new(), limit: Duration::from_secs(seconds), cap })
}

/// The `id` of a call: 8 hex digits, so that it is never a flag or a path.
fn job_id(arguments: &Map<String, Value>) -> Result<String, String> {
    let id = string(arguments, "id")?.ok_or("id: required, the job's ID")?;
    if id.len() != JOB_ID || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("id {id:?}: a job's ID is {JOB_ID} hex digits"));
    }
    Ok(id)
}

/// A whole number of a call, from `low` to `high`.
fn whole(arguments: &Map<String, Value>, name: &str, low: u64, high: u64) -> Result<Option<u64>, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|n| (low..=high).contains(n))
            .map(Some)
            .ok_or(format!("{name}: a whole number from {low} to {high}")),
    }
}

/// The window of a log: its offset, and the most bytes from it.
fn log_window(arguments: &Map<String, Value>) -> Result<(u64, u64), String> {
    let offset = whole(arguments, "offset", 0, LOG_FURTHEST)?.unwrap_or(0);
    let most = whole(arguments, "max_bytes", 1, LOG_MAX)?.unwrap_or(LOG_DEFAULT);
    Ok((offset, most))
}

/// The result of a call of a tool of `job` but `job_list`, whose result is
/// its own JSON; `None` for another tool. `failed` is the tool's, not the
/// job's: a job's status, or a job that runs on, is a result.
pub fn shape(name: &str, arguments: &Map<String, Value>, ran: &Ran) -> Option<(Value, bool)> {
    let mut value = streams(ran);
    let ended_badly = ran.timed_out || ran.exit.is_none();
    let failed = match name {
        "job_start" => {
            let out = String::from_utf8_lossy(&ran.stdout.bytes);
            let id = out.trim();
            let good = ran.exit == Some(0) && id.len() == JOB_ID && id.bytes().all(|b| b.is_ascii_hexdigit());
            value.insert("id".into(), if good { json!(id) } else { Value::Null });
            !good || ended_badly
        }
        "job_wait" => {
            let ended = ran.exit.is_some_and(|code| code != NOT_ENDED);
            value.insert("ended".into(), json!(ended && !ended_badly));
            ended_badly
        }
        "job_log" => {
            let (offset, most) = log_window(arguments).unwrap_or((0, LOG_DEFAULT));
            let bytes = &ran.stdout.bytes;
            let start = (offset as usize).min(bytes.len());
            let end = (start + most as usize).min(bytes.len());
            let more = end < bytes.len() || ran.stdout.truncated;
            let part = Captured { bytes: bytes[start..end].to_vec(), truncated: more };
            let (stdout, encoding) = text(&part);
            value.insert("stdout".into(), json!(stdout));
            value.insert("stdout_encoding".into(), json!(encoding));
            value.insert("offset".into(), json!(start));
            value.insert("next_offset".into(), json!(end));
            value.insert("more".into(), json!(more));
            ran.exit != Some(0) || ended_badly
        }
        "job_stop" => ran.exit != Some(0) || ended_badly,
        _ => return None,
    };
    Some((Value::Object(value), failed))
}

#[cfg(test)]
#[path = "verbs_tests.rs"]
mod tests;
