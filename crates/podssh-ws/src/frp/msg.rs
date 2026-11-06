//! frp's messages, as its wire v1 frames them (`fatedier/golib:msg/json`,
//! `fatedier/frp:pkg/msg/msg.go` at v0.71.1): a type byte, the length of the
//! body as a big-endian `int64`, and the body in JSON. A reader takes 10,240
//! bytes of body at most, as frps does, so a podssh that sends more is refused
//! there and a server that sends more is no frps.

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The type bytes that podssh sends and reads.
pub const LOGIN: u8 = b'o';
pub const LOGIN_RESP: u8 = b'1';
pub const NEW_PROXY: u8 = b'p';
pub const NEW_PROXY_RESP: u8 = b'2';
pub const CLOSE_PROXY: u8 = b'c';
pub const NEW_WORK_CONN: u8 = b'w';
pub const REQ_WORK_CONN: u8 = b'r';
pub const START_WORK_CONN: u8 = b's';
pub const NEW_VISITOR_CONN: u8 = b'v';
pub const NEW_VISITOR_CONN_RESP: u8 = b'3';
pub const PING: u8 = b'h';
pub const PONG: u8 = b'4';

/// Each type byte that frp's v1 knows, for a reader that refuses another.
const KNOWN: &[u8] = b"o1p2cwrsv3h4uinm56";

/// The longest body that frps reads (golib's `defaultMaxMsgLength`).
pub const MAX_LEN: usize = 10_240;

/// One message: its type byte and its body.
#[derive(Debug, Clone, PartialEq)]
pub struct Msg {
    pub kind: u8,
    pub body: Value,
}

impl Msg {
    /// A field of the body as text, or empty.
    pub fn text(&self, field: &str) -> &str {
        self.body.get(field).and_then(Value::as_str).unwrap_or("")
    }

    /// The `error` of an answer: frps's own words, or `None`.
    pub fn error(&self) -> Option<&str> {
        Some(self.text("error")).filter(|e| !e.is_empty())
    }
}

/// Why a message could not be read.
#[derive(Debug)]
pub enum MsgError {
    Io(std::io::Error),
    /// A type byte that frp's v1 does not have: no frps, or its wire v2.
    Kind(u8),
    Length(i64),
    Json(String),
}

impl std::fmt::Display for MsgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MsgError::Io(e) => write!(f, "{e}"),
            MsgError::Kind(b) => write!(f, "a message of the type {b:#04x}, which frp's wire v1 does not have"),
            MsgError::Length(n) => write!(f, "a message of {n} bytes, where frp reads {MAX_LEN} at most"),
            MsgError::Json(e) => write!(f, "a message whose body is no JSON: {e}"),
        }
    }
}

/// The bytes of one message.
pub fn encode(kind: u8, body: &Value) -> Vec<u8> {
    let json = body.to_string();
    let mut out = Vec::with_capacity(9 + json.len());
    out.push(kind);
    out.extend_from_slice(&(json.len() as i64).to_be_bytes());
    out.extend_from_slice(json.as_bytes());
    out
}

/// The head of a message in `buf`: its type and the length of its body,
/// once its 9 bytes are there.
pub fn head(buf: &[u8]) -> Result<Option<(u8, usize)>, MsgError> {
    if buf.len() < 9 {
        return Ok(None);
    }
    let kind = buf[0];
    if !KNOWN.contains(&kind) {
        return Err(MsgError::Kind(kind));
    }
    let len = i64::from_be_bytes(buf[1..9].try_into().expect("8 bytes"));
    if !(0..=MAX_LEN as i64).contains(&len) {
        return Err(MsgError::Length(len));
    }
    Ok(Some((kind, len as usize)))
}

/// One whole message at the start of `buf`, and the bytes that it took.
pub fn decode(buf: &[u8]) -> Result<Option<(Msg, usize)>, MsgError> {
    let Some((kind, len)) = head(buf)? else { return Ok(None) };
    if buf.len() < 9 + len {
        return Ok(None);
    }
    let body = serde_json::from_slice(&buf[9..9 + len]).map_err(|e| MsgError::Json(e.to_string()))?;
    Ok(Some((Msg { kind, body }, 9 + len)))
}

/// Read one message from `r`, in clear: a work or visitor connection's.
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Msg, MsgError> {
    let mut head_bytes = [0u8; 9];
    r.read_exact(&mut head_bytes).await.map_err(MsgError::Io)?;
    let (kind, len) = head(&head_bytes)?.expect("9 bytes");
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(MsgError::Io)?;
    let body = serde_json::from_slice(&body).map_err(|e| MsgError::Json(e.to_string()))?;
    Ok(Msg { kind, body })
}

/// Write one message to `w`, in clear.
pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, body: &Value) -> std::io::Result<()> {
    w.write_all(&encode(kind, body)).await?;
    w.flush().await
}

/// frp's key of a timestamp (`pkg/util/util.GetAuthKey`): the hex of MD5 over
/// the secret and the decimal timestamp, so that the secret never goes on the
/// wire and a key of another second is another key.
pub fn auth_key(secret: &str, timestamp: i64) -> String {
    // The md5 crate that the lock holds already (through podssh-ssh).
    format!("{:x}", md5::compute(format!("{secret}{timestamp}")))
}

/// The seconds since the epoch, as frp's timestamps are.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The version that podssh says in its login: frpc's of the release that
/// podssh speaks, as frps keeps no rule on it and logs it.
pub const VERSION: &str = "0.71.1";

/// A login as frpc makes it, with the token's key of `timestamp`.
pub fn login(token: &str, user: &str, run_id: &str, timestamp: i64) -> Value {
    json!({
        "version": VERSION,
        "hostname": "podssh",
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "user": user,
        "privilege_key": auth_key(token, timestamp),
        "timestamp": timestamp,
        "run_id": run_id,
        "pool_count": 1,
    })
}

/// An STCP service of `name` with `secret`, as frpc registers one: no
/// public port, a visitor with the same secret reaches it.
pub fn new_stcp(name: &str, secret: &str) -> Value {
    json!({ "proxy_name": name, "proxy_type": "stcp", "sk": secret })
}

/// A work connection's first message, signed with the token.
pub fn new_work_conn(token: &str, run_id: &str, timestamp: i64) -> Value {
    json!({ "run_id": run_id, "privilege_key": auth_key(token, timestamp), "timestamp": timestamp })
}

/// A visitor's first message, signed with the service's secret; no frp
/// encryption, as podssh's own channel runs inside.
pub fn new_visitor_conn(name: &str, secret: &str, run_id: &str, timestamp: i64) -> Value {
    json!({
        "run_id": run_id,
        "proxy_name": name,
        "sign_key": auth_key(secret, timestamp),
        "timestamp": timestamp,
        "use_encryption": false,
        "use_compression": false,
    })
}

/// A heartbeat, signed with the token.
pub fn ping(token: &str, timestamp: i64) -> Value {
    json!({ "privilege_key": auth_key(token, timestamp), "timestamp": timestamp })
}
