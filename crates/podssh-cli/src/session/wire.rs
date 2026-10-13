//! The protocol of a session's socket (T-186): one JSON line for each
//! request and one for each answer, the version (`schema`) first, as the
//! JSON of podssh's other commands names it. A request names its session
//! and its operation: `info`, `send`, `wait`, `capture` or `stop`. An answer
//! has `ok`; a failure has the exit code that the client gives (`code`) and
//! its line (`error`). Text to type goes as a string, or as base64 when it
//! is not UTF-8; the bytes of a raw capture go as base64.
//!
//! A line of another schema is read no further than its version, and
//! refused with the version that this podssh speaks.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::exitmap::sysexits::{EX_SOFTWARE, EX_USAGE};

/// The version of the protocol.
pub const SCHEMA: u64 = 1;
/// The longest line that either side reads.
pub const MAX_LINE: usize = 1 << 20;
/// The longest wait that a request may ask for: a day.
const LONGEST: Duration = Duration::from_secs(86_400);

/// What a client asks of the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Info,
    /// Type these bytes into the session.
    Send(Vec<u8>),
    Wait(Wait),
    /// The screen, or with `raw` the last bytes as they came.
    Capture { raw: bool },
    Stop,
}

/// What a wait waits for: the output quiet for `idle`, or `text` in the
/// output since the last send, whichever comes first, within `timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wait {
    pub idle: Option<Duration>,
    pub text: Option<Vec<u8>>,
    pub timeout: Duration,
}

/// A request: the session that it is for, and what it asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub op: Op,
}

/// A failure: the exit code that the client gives, and its line.
pub type Failure = (i32, String);

/// A line with the version first: the reader sees it before the rest.
fn line(body: Map<String, Value>) -> String {
    let rest = Value::Object(body).to_string();
    match rest.strip_prefix('{').filter(|r| *r != "}") {
        Some(rest) => format!("{{\"schema\":{SCHEMA},{rest}"),
        None => format!("{{\"schema\":{SCHEMA}}}"),
    }
}

/// The line of a request.
pub fn request(name: &str, op: &Op) -> String {
    let mut body = Map::new();
    body.insert("name".into(), json!(name));
    let what = match op {
        Op::Info => "info",
        Op::Send(bytes) => {
            match std::str::from_utf8(bytes) {
                Ok(text) => body.insert("text".into(), json!(text)),
                Err(_) => body.insert("bytes".into(), json!(B64.encode(bytes))),
            };
            "send"
        }
        Op::Wait(wait) => {
            if let Some(idle) = wait.idle {
                body.insert("idle_ms".into(), json!(millis(idle)));
            }
            if let Some(text) = &wait.text {
                body.insert("match".into(), json!(String::from_utf8_lossy(text)));
            }
            body.insert("timeout_ms".into(), json!(millis(wait.timeout)));
            "wait"
        }
        Op::Capture { raw } => {
            body.insert("raw".into(), json!(raw));
            "capture"
        }
        Op::Stop => "stop",
    };
    body.insert("op".into(), json!(what));
    line(body)
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Read a request line; a failure is answered with its code and line.
pub fn parse_request(text: &[u8]) -> Result<Request, Failure> {
    let usage = |why: String| (EX_USAGE, why);
    let value: Value = serde_json::from_slice(text).map_err(|e| usage(format!("not a line of JSON: {e}")))?;
    let fields = value.as_object().ok_or_else(|| usage("a request is a JSON object".into()))?;
    schema(fields).map_err(usage)?;
    let string = |key: &str| {
        fields.get(key).and_then(Value::as_str).ok_or_else(|| usage(format!("a request names its {key}")))
    };
    let name = string("name")?.to_string();
    let op = match string("op")? {
        "info" => Op::Info,
        "send" => Op::Send(sent(fields).map_err(usage)?),
        "wait" => {
            let duration = |key: &str| fields.get(key).and_then(Value::as_u64).map(Duration::from_millis);
            let text = fields.get("match").and_then(Value::as_str).map(|t| t.as_bytes().to_vec());
            if text.as_ref().is_some_and(Vec::is_empty) {
                return Err(usage("a match that is empty".into()));
            }
            let idle = duration("idle_ms").map(|d| d.min(LONGEST));
            let idle = idle.or(if text.is_none() { Some(super::DEFAULT_IDLE) } else { None });
            let timeout = duration("timeout_ms").unwrap_or(super::DEFAULT_TIMEOUT).min(LONGEST);
            Op::Wait(Wait { idle, text, timeout })
        }
        "capture" => Op::Capture { raw: fields.get("raw").and_then(Value::as_bool).unwrap_or(false) },
        "stop" => Op::Stop,
        other => return Err(usage(format!("no operation {other:?}: info, send, wait, capture or stop"))),
    };
    Ok(Request { name, op })
}

/// The version of a line, read first.
fn schema(fields: &Map<String, Value>) -> Result<(), String> {
    match fields.get("schema").and_then(Value::as_u64) {
        Some(SCHEMA) => Ok(()),
        Some(other) => Err(format!("schema {other}: this podssh speaks schema {SCHEMA}")),
        None => Err(format!("a line with no schema: this podssh speaks schema {SCHEMA}")),
    }
}

/// The bytes of a send: its text, or its bytes in base64.
fn sent(fields: &Map<String, Value>) -> Result<Vec<u8>, String> {
    match (fields.get("text").and_then(Value::as_str), fields.get("bytes").and_then(Value::as_str)) {
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(bytes)) => B64.decode(bytes).map_err(|e| format!("bytes that are not base64: {e}")),
        _ => Err("a send has a text or bytes, one of them".into()),
    }
}

/// A success, with the fields of its operation.
pub fn ok(fields: Map<String, Value>) -> String {
    let mut body = Map::new();
    body.insert("ok".into(), json!(true));
    body.extend(fields);
    line(body)
}

/// A failure: the client exits with `code`, and says `why`.
pub fn failed(code: i32, why: &str) -> String {
    let mut body = Map::new();
    body.insert("ok".into(), json!(false));
    body.insert("code".into(), json!(code));
    body.insert("error".into(), json!(why));
    line(body)
}

/// Read an answer: its fields, or the failure that it names. A line that is
/// no answer of this schema is a fault of podssh (70).
pub fn parse_answer(text: &[u8]) -> Result<Map<String, Value>, Failure> {
    let broken = |why: String| (EX_SOFTWARE, format!("the session's podssh gave no answer that this one reads: {why}"));
    let value: Value = serde_json::from_slice(text).map_err(|e| broken(e.to_string()))?;
    let Value::Object(fields) = value else { return Err(broken("not an object".into())) };
    schema(&fields).map_err(broken)?;
    match fields.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(fields),
        Some(false) => {
            let code = fields.get("code").and_then(Value::as_i64).and_then(|c| i32::try_from(c).ok());
            let why = fields.get("error").and_then(Value::as_str).unwrap_or("it failed");
            Err((code.filter(|c| (1..=255).contains(c)).unwrap_or(EX_SOFTWARE), why.to_string()))
        }
        None => Err(broken("no ok".into())),
    }
}

/// The line that `serve` writes on stdout once its session is ready.
pub fn ready(name: &str, socket: &str, pid: u32) -> String {
    let mut body = Map::new();
    body.insert("ready".into(), json!(true));
    body.insert("name".into(), json!(name));
    body.insert("socket".into(), json!(socket));
    body.insert("pid".into(), json!(pid));
    line(body)
}

/// The socket of a line of ready, as `start` reads it.
pub fn ready_socket(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    let fields = value.as_object()?;
    schema(fields).ok()?;
    if fields.get("ready").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    fields.get("socket").and_then(Value::as_str).map(str::to_string)
}

/// The fields of `info`: the session, its daemon, and how it is.
pub fn info(name: &str, host: &str, pid: u32, ended: Option<i32>, size: (u16, u16)) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("name".into(), json!(name));
    fields.insert("host".into(), json!(host));
    fields.insert("pid".into(), json!(pid));
    let state = if ended.is_some() { "ended" } else { "running" };
    fields.insert("state".into(), json!(state));
    if let Some(status) = ended {
        fields.insert("status".into(), json!(status));
    }
    fields.insert("rows".into(), json!(size.0));
    fields.insert("cols".into(), json!(size.1));
    fields
}

/// The fields of a capture of the screen: its text, the cursor's row and
/// column from 0, and its size.
pub fn screen(text: String, cursor: (u16, u16), size: (u16, u16)) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("screen".into(), json!(text));
    fields.insert("cursor".into(), json!([cursor.0, cursor.1]));
    fields.insert("rows".into(), json!(size.0));
    fields.insert("cols".into(), json!(size.1));
    fields
}

/// The fields of a raw capture.
pub fn raw(bytes: &[u8]) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("bytes".into(), json!(B64.encode(bytes)));
    fields
}

/// The bytes of a raw capture, as the client reads them.
pub fn raw_bytes(fields: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let text = fields.get("bytes").and_then(Value::as_str).ok_or("a raw capture with no bytes")?;
    B64.decode(text).map_err(|e| format!("bytes that are not base64: {e}"))
}

/// The fields of a wait that ended: what ended it.
pub fn by(what: &str) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("by".into(), json!(what));
    fields
}
