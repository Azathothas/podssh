//! The copies of `podssh mcp` (T-488): `cp_put` and `cp_get`, each a child
//! of `podssh cp` with the options that `ssh_exec` forces, between a path
//! that `--allow-dir` holds (`dirs`) and a path of a host that
//! `--allow-host` lets in; `cp` checks the digest of each file. `cp_put`
//! also takes the bytes of a small file in the call, which go through a file
//! of the server's private directory, so that no local path is needed. A
//! tree is copied as `cp -r` copies it: a link as a link, never what it
//! names.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::child::{Plan, Ran};
use super::dirs::operand;
use super::tools::{
    boolean, destination, forced, known, limit, limit_property, object_needing, streams, string, Settings, OWN_CAP,
};

/// The limit of a copy when the call names none.
const LIMIT: u64 = 300;
/// The most bytes of `content`, once decoded.
pub const CONTENT_MAX: usize = 1 << 20;
/// The longest path of the host that a call names.
const PATH_MAX: usize = 4096;

/// The two tools, when a host and a directory are allowed.
#[rustfmt::skip]
pub fn list(settings: &Settings) -> Vec<Value> {
    let (hosts, dirs) = (settings.allow.shown(), settings.dirs.shown());
    let dest = json!({ "type": "string", "description": format!("[user@]host, a host that matches {hosts}") });
    let path = json!({ "type": "string", "minLength": 1, "description": "the path on the host, as podssh cp takes it after host:" });
    let local = json!({ "type": "string", "minLength": 1,
        "description": format!("a path of this host in {dirs} (--allow-dir), a relative one under the first; links are followed and held inside") });
    let recursive = json!({ "type": "boolean", "description": "a directory and what it holds, as cp -r: a link goes as a link" });
    let notes = json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": true });
    vec![
        json!({ "name": "cp_put", "title": "Copy a file to a host",
            "description": format!("podssh cp from this host to an allowed host ({hosts}): local_path, a file or with \
                recursive a tree of {dirs}, or content, the bytes of one file in base64 (1 MiB at most); each file's \
                SHA-256 is checked at both ends. The result has podssh cp's exit and its events."),
            "inputSchema": object_needing(json!({ "destination": dest, "path": path, "local_path": local,
                "content": { "type": "string", "description": "the file's bytes in base64, in place of local_path; path names the file" },
                "recursive": recursive, "timeout_seconds": limit_property(LIMIT) }), &["destination", "path"]),
            "annotations": notes }),
        json!({ "name": "cp_get", "title": "Copy a file from a host",
            "description": format!("podssh cp from an allowed host ({hosts}) into {dirs}: a file, or with recursive a \
                tree into a new path; each file's SHA-256 is checked at both ends. The result has \
                podssh cp's exit and its events."),
            "inputSchema": object_needing(json!({ "destination": dest, "path": path, "local_path": local,
                "recursive": recursive, "timeout_seconds": limit_property(LIMIT) }), &["destination", "path", "local_path"]),
            "annotations": notes }),
    ]
}

/// The child of a call of a copy; `None` for another tool. `file` names the
/// call's result file, beside which `content` is written, and which the
/// server removes after the call.
pub fn plan(
    settings: &Settings,
    name: &str,
    arguments: &Map<String, Value>,
    file: &str,
) -> Option<Result<Plan, String>> {
    let names: &[&str] = match name {
        "cp_put" => &["destination", "path", "local_path", "content", "recursive", "timeout_seconds"],
        "cp_get" => &["destination", "path", "local_path", "recursive", "timeout_seconds"],
        _ => return None,
    };
    Some(known(arguments, names).and_then(|()| plan_of(settings, name, arguments, file)))
}

fn plan_of(settings: &Settings, name: &str, arguments: &Map<String, Value>, file: &str) -> Result<Plan, String> {
    // The gate of the local side first: with no --allow-dir, no copy runs.
    if settings.dirs.is_empty() {
        return Err("no directory is allowed: podssh mcp was started with no --allow-dir".into());
    }
    let destination = destination(settings, arguments)?;
    let path = far_path(arguments)?;
    let recursive = boolean(arguments, "recursive")?.unwrap_or(false);
    let seconds = limit(arguments, LIMIT)?;
    let far = format!("{destination}:{path}");
    let local = string(arguments, "local_path")?;
    let (source, target) = match name {
        "cp_put" => {
            let here = match (local, string(arguments, "content")?) {
                (Some(local), None) => settings.dirs.source(&local)?,
                (None, Some(content)) if !recursive => content_file(&content, &path, file)?,
                (None, Some(_)) => return Err("content is one file: recursive takes local_path".into()),
                _ => return Err("local_path or content: give one".into()),
            };
            (operand(&here), far)
        }
        _ => {
            let local = local.ok_or("local_path: required, where the copy goes")?;
            (far, operand(&settings.dirs.target(&local, recursive)?))
        }
    };
    let mut argv: Vec<OsString> = Vec::from(["cp", "--jsonl", "--timeout"].map(OsString::from));
    argv.push(format!("{seconds}s").into());
    argv.extend(forced(settings));
    if recursive {
        argv.push("-r".into());
    }
    argv.extend(["--", source.as_str(), target.as_str()].map(OsString::from));
    // A few seconds past cp's own --timeout, so that cp says why it ended.
    Ok(Plan { argv, stdin: Vec::new(), limit: Duration::from_secs(seconds + 5), cap: OWN_CAP })
}

/// The `path` of the host: not empty, one line, no NUL.
fn far_path(arguments: &Map<String, Value>) -> Result<String, String> {
    let path = string(arguments, "path")?.filter(|p| !p.is_empty()).ok_or("path: required, the path on the host")?;
    if path.len() > PATH_MAX || path.chars().any(char::is_control) {
        return Err(format!("path: one line of {PATH_MAX} bytes at most, with no control character"));
    }
    Ok(path)
}

/// The bytes of `content`, in a file of the server's private directory that
/// has the name of the far path's last part, so that the copy gives the far
/// file its name: its path.
fn content_file(content: &str, far: &str, file: &str) -> Result<PathBuf, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|e| format!("content: not base64: {e}"))?;
    if bytes.len() > CONTENT_MAX {
        return Err(format!("content: {} bytes; a call carries {CONTENT_MAX} at most", bytes.len()));
    }
    let name = far.rsplit('/').next().filter(|n| !n.is_empty() && *n != "." && *n != "..");
    let name = name.ok_or("path: name the file that content becomes, not a directory")?;
    let dir = content_dir(file);
    podssh_relay::cache::private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let at = dir.join(name);
    let mut out = podssh_relay::cache::create_new_private(&at).map_err(|e| format!("{}: {e}", at.display()))?;
    out.write_all(&bytes).map_err(|e| format!("{}: {e}", at.display()))?;
    Ok(at)
}

/// The directory of the call's `content`, beside its result file.
pub fn content_dir(file: &str) -> PathBuf {
    Path::new(file).with_extension("d")
}

/// The result of a copy: cp's exit and streams, and each line of its
/// `--jsonl` as an event; `None` for another tool.
pub fn shape(name: &str, ran: &Ran) -> Option<(Value, bool)> {
    if !matches!(name, "cp_put" | "cp_get") {
        return None;
    }
    let mut value = streams(ran);
    let events: Vec<Value> = String::from_utf8_lossy(&ran.stdout.bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(Value::is_object)
        .collect();
    value.insert("events".into(), Value::Array(events));
    let failed = ran.timed_out || ran.exit != Some(0);
    Some((Value::Object(value), failed))
}

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;
