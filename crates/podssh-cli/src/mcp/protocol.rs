//! The messages of `podssh mcp`: JSON-RPC 2.0, one message on each line, as
//! the Model Context Protocol's stdio transport has them. Two eras are
//! served, as the revision 2026-07-28 lets a server do: a request that names
//! its protocol version in `_meta` is answered by itself, with no state
//! (2026-07-28); a client of an earlier revision opens with `initialize`,
//! whose version holds for the rest of the process (2025-11-25 and before).

use serde_json::{json, Map, Value};

/// The revisions of per-request metadata.
pub const MODERN: &[&str] = &["2026-07-28"];
/// The revisions of the `initialize` handshake, the latest first.
pub const LEGACY: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const UNSUPPORTED_VERSION: i64 = -32022;

/// How long a client may keep the list of tools and the answer of
/// `server/discover`: they do not change while the server runs.
const TTL_MS: u64 = 3_600_000;

/// What the server says of itself to an agent.
pub const INSTRUCTIONS: &str = "podssh runs commands on the hosts that its user allowed, over SSH: call ssh_exec \
     with a destination [user@]host and a command. No call asks for a password or a passphrase, and a host whose \
     key is not known is refused unless the call names its fingerprint: such a call fails, and its result says why. \
     status, doctor and man describe this host, its path to the relay, and podssh.";

/// The era of the process: the revision that `initialize` chose, if one did.
#[derive(Debug, Default)]
pub struct Era {
    legacy: Option<&'static str>,
}

/// How a request is answered: the shapes of a revision of the handshake, or
/// those of 2026-07-28 (`resultType`, and the server in `_meta`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Legacy,
    Modern,
}

/// What a line asks of the server.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Write this message.
    Reply(Value),
    /// Run the tool `name` with `arguments`, and answer `id` with its result.
    Call { id: Value, kind: Kind, name: String, arguments: Map<String, Value> },
    /// Stop the call of this request.
    Cancel(Value),
    /// Nothing to write.
    Nothing,
}

/// The server's name and version.
pub fn server_info() -> Value {
    json!({ "name": "podssh", "version": env!("CARGO_PKG_VERSION") })
}

/// One line of input, against the tools that this server offers.
pub fn handle(line: &[u8], era: &mut Era, tools: &[Value]) -> Action {
    let message: Value = match std::str::from_utf8(line).ok().and_then(|text| serde_json::from_str(text).ok()) {
        Some(message) => message,
        None => return Action::Reply(error(&Value::Null, PARSE_ERROR, "Parse error: not one JSON value in UTF-8")),
    };
    let Some(object) = message.as_object() else {
        let why = if message.is_array() { "a batch: send one message on each line" } else { "not an object" };
        return Action::Reply(error(&Value::Null, INVALID_REQUEST, &format!("Invalid Request: {why}")));
    };
    let id = object.get("id");
    let valid_id = id.map(|id| id.is_string() || id.is_i64() || id.is_u64());
    let reply_id = if valid_id == Some(true) { id.cloned().unwrap_or(Value::Null) } else { Value::Null };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Action::Reply(error(&reply_id, INVALID_REQUEST, "Invalid Request: jsonrpc must be \"2.0\""));
    }
    let Some(method) = object.get("method") else {
        // A response of the client: this server sends no request.
        return Action::Nothing;
    };
    let Some(method) = method.as_str() else {
        return Action::Reply(error(&reply_id, INVALID_REQUEST, "Invalid Request: the method is not a string"));
    };
    match valid_id {
        None => notification(method, object.get("params")),
        Some(false) => {
            Action::Reply(error(&Value::Null, INVALID_REQUEST, "Invalid Request: the id is not a string or an integer"))
        }
        Some(true) => match object.get("params") {
            None | Some(Value::Null) => request(reply_id, method, &Map::new(), era, tools),
            Some(Value::Object(params)) => request(reply_id, method, params, era, tools),
            Some(_) => Action::Reply(error(&reply_id, INVALID_PARAMS, "Invalid params: not an object")),
        },
    }
}

/// A notification gets no answer; one that cancels a request stops its call.
fn notification(method: &str, params: Option<&Value>) -> Action {
    match (method, params.and_then(|p| p.get("requestId"))) {
        ("notifications/cancelled", Some(id)) => Action::Cancel(id.clone()),
        _ => Action::Nothing,
    }
}

fn request(id: Value, method: &str, params: &Map<String, Value>, era: &mut Era, tools: &[Value]) -> Action {
    if method == "initialize" {
        let asked = params.get("protocolVersion").and_then(Value::as_str);
        let Some(asked) = asked else {
            return Action::Reply(error(&id, INVALID_PARAMS, "Invalid params: initialize names no protocolVersion"));
        };
        // The version asked, when this server has it; else its latest.
        let version = LEGACY.iter().copied().find(|v| *v == asked).unwrap_or(LEGACY[0]);
        era.legacy = Some(version);
        let result = json!({
            "protocolVersion": version,
            "capabilities": capabilities(),
            "serverInfo": server_info(),
            "instructions": INSTRUCTIONS,
        });
        return Action::Reply(answer(&id, Kind::Legacy, result));
    }
    let kind = match kind_of(params, era) {
        Ok(kind) => kind,
        // A ping may come before initialize, in the revisions that have it.
        Err(_) if method == "ping" && version_of(params).is_none() => Kind::Legacy,
        Err(refusal) => return Action::Reply(with_id(refusal, &id)),
    };
    let result = match method {
        "ping" => json!({}),
        "server/discover" => {
            let mut versions: Vec<&str> = MODERN.to_vec();
            versions.extend_from_slice(LEGACY);
            json!({
                "supportedVersions": versions,
                "capabilities": capabilities(),
                "instructions": INSTRUCTIONS,
                "ttlMs": TTL_MS,
                "cacheScope": "private",
            })
        }
        "tools/list" => {
            if params.get("cursor").is_some_and(|c| !c.is_null()) {
                return Action::Reply(error(
                    &id,
                    INVALID_PARAMS,
                    "Invalid params: no such cursor; the list has one page",
                ));
            }
            let mut result = json!({ "tools": tools });
            if kind == Kind::Modern {
                result["ttlMs"] = json!(TTL_MS);
                result["cacheScope"] = json!("private");
            }
            result
        }
        "tools/call" => return call(id, kind, params, tools),
        other => return Action::Reply(error(&id, METHOD_NOT_FOUND, &format!("Method not found: {other}"))),
    };
    Action::Reply(answer(&id, kind, result))
}

fn call(id: Value, kind: Kind, params: &Map<String, Value>, tools: &[Value]) -> Action {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Action::Reply(error(&id, INVALID_PARAMS, "Invalid params: tools/call names no tool"));
    };
    if !tools.iter().any(|tool| tool["name"] == name) {
        return Action::Reply(error(&id, INVALID_PARAMS, &format!("Unknown tool: {name}")));
    }
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(arguments)) => arguments.clone(),
        Some(_) => return Action::Reply(error(&id, INVALID_PARAMS, "Invalid params: the arguments are not an object")),
    };
    Action::Call { id, kind, name: name.to_string(), arguments }
}

/// The era of a request: the version of its `_meta`, else that of
/// `initialize`; a request with neither, or with a version that this server
/// does not have, is refused (with no id: the caller puts it in).
fn kind_of(params: &Map<String, Value>, era: &Era) -> Result<Kind, Value> {
    let meta = params.get("_meta").and_then(Value::as_object);
    let Some(version) = version_of(params) else {
        return match era.legacy {
            Some(_) => Ok(Kind::Legacy),
            None => Err(error(
                &Value::Null,
                INVALID_PARAMS,
                &format!("Invalid params: no protocol version: name it in _meta ({PROTOCOL_VERSION}), or send initialize first"),
            )),
        };
    };
    let asked = version.as_str().unwrap_or_default();
    if LEGACY.contains(&asked) {
        return Ok(Kind::Legacy);
    }
    if !MODERN.contains(&asked) {
        let mut supported: Vec<&str> = MODERN.to_vec();
        supported.extend_from_slice(LEGACY);
        let data = json!({ "supported": supported, "requested": version });
        let mut refusal = error(&Value::Null, UNSUPPORTED_VERSION, "Unsupported protocol version");
        refusal["error"]["data"] = data;
        return Err(refusal);
    }
    if !meta.and_then(|m| m.get(CLIENT_CAPABILITIES)).is_some_and(Value::is_object) {
        return Err(error(
            &Value::Null,
            INVALID_PARAMS,
            &format!("Invalid params: _meta has no {CLIENT_CAPABILITIES}"),
        ));
    }
    Ok(Kind::Modern)
}

/// The protocol version that a request names in its `_meta`.
fn version_of(params: &Map<String, Value>) -> Option<&Value> {
    params.get("_meta").and_then(Value::as_object).and_then(|m| m.get(PROTOCOL_VERSION))
}

fn capabilities() -> Value {
    json!({ "tools": { "listChanged": false } })
}

/// The answer to `id`: `result`, with the fields of the revision of `kind`.
pub fn answer(id: &Value, kind: Kind, mut result: Value) -> Value {
    if kind == Kind::Modern {
        let mut meta = Map::new();
        meta.insert(SERVER_INFO.to_string(), server_info());
        result["resultType"] = json!("complete");
        result["_meta"] = Value::Object(meta);
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A JSON-RPC error for `id`.
pub fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn with_id(mut refusal: Value, id: &Value) -> Value {
    refusal["id"] = id.clone();
    refusal
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
