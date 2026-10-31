//! The tools of `podssh mcp`: `ssh_exec`, `status`, `doctor` and `man`. A
//! call becomes the command line of a child (`Plan`), and the child's end
//! becomes the call's result: its JSON in `structuredContent`, and the same
//! JSON as text, for a client of a revision that has no structured result.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::allow::Allow;
use super::child::{text, Captured, Plan, Ran};

/// The most bytes kept of each stream of `ssh_exec`.
pub const SSH_CAP: usize = 1 << 20;
/// The limit of `ssh_exec` when the call names none, and the most it may name.
const SSH_LIMIT: u64 = 60;
const SSH_LIMIT_MAX: u64 = 3600;
/// The bounds of the other tools, whose output is podssh's own.
const OWN_CAP: usize = 8 << 20;

/// What each call of a run shares.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub allow: Allow,
    /// `-F FILE` for each session.
    pub config: Option<String>,
    /// `--direct` for each session.
    pub direct: bool,
    /// A private directory for the result files of the sessions.
    pub scratch: PathBuf,
}

/// The tools, in the same order on each call: `ssh_exec` first, when a host
/// is allowed.
pub fn list(settings: &Settings) -> Vec<Value> {
    let mut tools = Vec::new();
    if !settings.allow.is_empty() {
        tools.push(ssh_exec(&settings.allow));
    }
    tools.push(json!({
        "name": "status",
        "title": "The state of this host",
        "description": "podssh status: one JSON object with the relays and where they came from, the relay token, the \
             proxy, the terminal, and, with a destination, whether known_hosts holds its host key. Reads no network.",
        "inputSchema": object(json!({
            "destination": { "type": "string", "description": "[user@]host whose host key is looked up; an allowed host" },
        })),
        "annotations": { "readOnlyHint": true, "openWorldHint": false },
    }));
    tools.push(json!({
        "name": "doctor",
        "title": "Check this host and the relay",
        "description": "podssh doctor --json: what this host allows (outbound TLS, DNS, a proxy) and whether the relay \
             works, with ok, FAIL or ???? for each check, as one JSON object.",
        "inputSchema": object(json!({
            "full": { "type": "boolean", "description": "also log in to github.com through the relay, with a key made for the check, and, with no proxy set, make a QUIC handshake with the quick tunnel's edge" },
        })),
        "annotations": { "readOnlyHint": true, "openWorldHint": true },
    }));
    tools.push(json!({
        "name": "man",
        "title": "The manual of podssh",
        "description": "podssh man --json: the commands, flags, ssh_config keywords, variables, files and exit codes \
             of this build as JSON, or one section of them.",
        "inputSchema": object(json!({
            "section": { "type": "string", "description": "a command (ssh, cp, ...), or environment, files, relay-facts, exit-status, examples or see-also" },
        })),
        "annotations": { "readOnlyHint": true, "openWorldHint": false },
    }));
    tools
}

fn ssh_exec(allow: &Allow) -> Value {
    json!({
        "name": "ssh_exec",
        "title": "Run a command over SSH",
        "description": format!(
            "Run one command on an allowed host with podssh ssh, with no terminal, no prompt and no forwarding; \
             the result has podssh's exit code, the command's status or signal, its stdout and stderr (at most \
             1 MiB each; output that is not UTF-8 comes as base64), and whether the limit passed. A host whose key \
             known_hosts does not hold is refused unless host_key_fingerprint names it. Allowed hosts: {}.",
            allow.shown()
        ),
        "inputSchema": object_needing(json!({
            "destination": { "type": "string", "description": format!("[user@]host, a host that matches {}", allow.shown()) },
            "command": { "type": "string", "minLength": 1, "description": "the command line that the remote user's shell runs" },
            "stdin": { "type": "string", "description": "text for the command's stdin; with none, it reads end of input at once" },
            "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": SSH_LIMIT_MAX,
                "description": format!("the limit of the call; past it the session ends (default {SSH_LIMIT})") },
            "host_key_fingerprint": { "type": "string", "description": "SHA256:... of the host key, as ssh-keygen -l prints it; another key is refused" },
        }), &["destination", "command"]),
        "outputSchema": {
            "type": "object",
            "properties": {
                "exit": { "type": ["integer", "null"], "description": "podssh's exit code: the status, 128 + a signal, or 255 when podssh failed" },
                "status": { "type": ["integer", "null"] },
                "signal": { "type": ["object", "null"] },
                "end": { "type": ["string", "null"] },
                "failure": { "type": ["string", "null"] },
                "stdout": { "type": "string" },
                "stdout_encoding": { "enum": ["utf-8", "base64"] },
                "stderr": { "type": "string" },
                "stderr_encoding": { "enum": ["utf-8", "base64"] },
                "truncated": { "type": "boolean" },
                "timed_out": { "type": "boolean" },
                "duration_ms": { "type": "integer" },
            },
            "required": ["exit", "status", "signal", "end", "failure", "stdout", "stdout_encoding", "stderr",
                "stderr_encoding", "truncated", "timed_out", "duration_ms"],
        },
        "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true },
    })
}

/// An object schema of `properties`, of which `required` are needed, and no
/// other property.
fn object(properties: Value) -> Value {
    object_needing(properties, &[])
}

fn object_needing(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false })
}

/// The child of a call of `name` with `arguments`: its plan, and the result
/// file of a session. An argument that is wrong is the call's error, which
/// the agent can read and correct.
pub fn plan(settings: &Settings, name: &str, arguments: &Map<String, Value>, file: &str) -> Result<Plan, String> {
    let words = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
    match name {
        "ssh_exec" => ssh_plan(settings, arguments, file),
        "status" => {
            known(arguments, &["destination"])?;
            let mut argv = words(&["status"]);
            if let Some(destination) = string(arguments, "destination")? {
                settings.allow.check(&destination)?;
                argv.extend(words(&["--", &destination]));
            }
            Ok(Plan { argv, stdin: Vec::new(), limit: Duration::from_secs(60), cap: OWN_CAP })
        }
        "doctor" => {
            known(arguments, &["full"])?;
            let mut argv = words(&["doctor", "--json"]);
            match arguments.get("full") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => argv.push("--full".into()),
                Some(_) => return Err("full: expected true or false".into()),
            }
            Ok(Plan { argv, stdin: Vec::new(), limit: Duration::from_secs(180), cap: OWN_CAP })
        }
        "man" => {
            known(arguments, &["section"])?;
            let mut argv = words(&["man", "--json"]);
            if let Some(section) = string(arguments, "section")? {
                // A word that starts with a letter: never a flag of man.
                let word = section.len() <= 32 && section.starts_with(|c: char| c.is_ascii_lowercase());
                if !word || !section.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                    return Err(format!("section {section:?}: a command or a section name, as ssh or exit-status"));
                }
                argv.push(section.into());
            }
            Ok(Plan { argv, stdin: Vec::new(), limit: Duration::from_secs(30), cap: OWN_CAP })
        }
        other => Err(format!("no tool {other}")),
    }
}

fn ssh_plan(settings: &Settings, arguments: &Map<String, Value>, file: &str) -> Result<Plan, String> {
    known(arguments, &["destination", "command", "stdin", "timeout_seconds", "host_key_fingerprint"])?;
    let destination = string(arguments, "destination")?.ok_or("destination: required, [user@]host")?;
    settings.allow.check(&destination)?;
    let command = string(arguments, "command")?.filter(|c| !c.is_empty()).ok_or("command: required, not empty")?;
    if command.contains('\0') {
        return Err("command: a NUL character".into());
    }
    let stdin = string(arguments, "stdin")?.unwrap_or_default();
    let limit = match arguments.get("timeout_seconds") {
        None | Some(Value::Null) => SSH_LIMIT,
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=SSH_LIMIT_MAX).contains(n))
            .ok_or(format!("timeout_seconds: a whole number from 1 to {SSH_LIMIT_MAX}"))?,
    };
    // No prompt, no unknown host key, no forwarding of any kind, no shared
    // connection: the first value of a keyword holds, so these come before
    // what the user's file says.
    let mut argv: Vec<OsString> = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
        .into_iter()
        .chain(["-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none"])
        .chain(["-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-T", "-e", "none"])
        .map(OsString::from)
        .collect();
    if let Some(config) = &settings.config {
        argv.extend([OsString::from("-F"), config.into()]);
    }
    if settings.direct {
        argv.push("--direct".into());
    }
    if let Some(fingerprint) = string(arguments, "host_key_fingerprint")? {
        argv.push(format!("--host-key-fingerprint={fingerprint}").into());
    }
    argv.extend(["--result-file", file, "--", &destination, &command].map(OsString::from));
    Ok(Plan { argv, stdin: stdin.into_bytes(), limit: Duration::from_secs(limit), cap: SSH_CAP })
}

/// Refuse an argument that the tool does not have: a misspelt one would be
/// ignored, and its call would do something else than asked.
fn known(arguments: &Map<String, Value>, names: &[&str]) -> Result<(), String> {
    match arguments.keys().find(|k| !names.contains(&k.as_str())) {
        Some(other) => Err(format!("{other}: not an argument of this tool; it takes {}", names.join(", "))),
        None => Ok(()),
    }
}

fn string(arguments: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{name}: expected a string")),
    }
}

/// The result of a call that ran: `structuredContent`, and whether the tool
/// failed (not the command: its status is in the result).
pub fn shape(name: &str, ran: &Ran, result_file: Option<Value>) -> (Value, bool) {
    if name == "ssh_exec" {
        let r = result_file.unwrap_or(Value::Null);
        let field = |key: &str| r.get(key).cloned().unwrap_or(Value::Null);
        let (stdout, stdout_encoding) = text(&ran.stdout);
        let (stderr, stderr_encoding) = text(&ran.stderr);
        // No result file: podssh did not say how the run ended.
        let failed = ran.timed_out || ran.exit.is_none() || r.is_null() || !field("failure").is_null();
        let value = json!({
            "exit": ran.exit,
            "status": field("status"),
            "signal": field("signal"),
            "end": field("end"),
            "failure": field("failure"),
            "stdout": stdout,
            "stdout_encoding": stdout_encoding,
            "stderr": stderr,
            "stderr_encoding": stderr_encoding,
            "truncated": ran.stdout.truncated || ran.stderr.truncated,
            "timed_out": ran.timed_out,
            "duration_ms": ran.duration.as_millis() as u64,
        });
        return (value, failed);
    }
    // podssh's own JSON, as the command wrote it; its words on stderr when
    // it wrote none.
    let own = serde_json::from_slice::<Value>(&ran.stdout.bytes).ok().filter(|_| !ran.stdout.truncated);
    match own {
        Some(value) if value.is_object() => (value, ran.timed_out || ran.exit.is_none()),
        _ => {
            let words = |c: &Captured| String::from_utf8_lossy(&c.bytes).into_owned();
            (json!({ "exit": ran.exit, "timed_out": ran.timed_out, "stderr": words(&ran.stderr) }), true)
        }
    }
}

/// A tool's result: the JSON as text and as `structuredContent`.
pub fn result(structured: Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": structured.to_string() }],
        "structuredContent": structured,
        "isError": is_error,
    })
}

/// The result of a call that could not run: words for the agent.
pub fn refusal(why: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": why }], "isError": true })
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
