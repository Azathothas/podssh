//! frpc's control stream and its other streams, on frp's wire v1
//! (`client/control_session.go`, `client/control.go` at v0.71.1): the first
//! stream logs in, in clear, and from frps's answer on each side writes its
//! IV and runs AES-128-CFB with the token's key ([`super::cfb`]); a work
//! connection is a new stream that names the login's run id and the token's
//! key of its second, and reads `StartWorkConn`; a visitor's is a new stream
//! that names the service and its secret's key of its second, and reads
//! `NewVisitorConnResp`. After the first message of each of those, the
//! stream is the service's bytes.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::cfb::{self, Cfb};
use super::msg::{self, Msg};
use super::mux::Mux;
use super::FrpError;

/// The bound of each answer that a step waits for (frpc's 10 s).
pub const ANSWER_LIMIT: Duration = Duration::from_secs(10);

/// The writing side of the control stream, shared by its writers.
pub struct ControlWrite {
    io: WriteHalf<DuplexStream>,
    cfb: Cfb,
    iv: Option<[u8; cfb::BLOCK]>,
}

impl ControlWrite {
    /// Send one message, encrypted; the IV goes before the first.
    pub async fn send(&mut self, kind: u8, body: &Value) -> Result<(), FrpError> {
        let mut bytes = msg::encode(kind, body);
        self.cfb.apply(&mut bytes);
        if let Some(iv) = self.iv.take() {
            self.io.write_all(&iv).await.map_err(FrpError::io)?;
        }
        self.io.write_all(&bytes).await.map_err(FrpError::io)?;
        self.io.flush().await.map_err(FrpError::io)
    }
}

/// The reading side of the control stream.
pub struct ControlRead {
    io: ReadHalf<DuplexStream>,
    key: [u8; cfb::BLOCK],
    cfb: Option<Cfb>,
    clear: Vec<u8>,
}

impl ControlRead {
    /// The next message from frps: its IV is read first, once.
    pub async fn recv(&mut self) -> Result<Msg, FrpError> {
        if self.cfb.is_none() {
            let mut iv = [0u8; cfb::BLOCK];
            self.io.read_exact(&mut iv).await.map_err(FrpError::io)?;
            self.cfb = Some(Cfb::decrypter(&self.key, &iv));
        }
        loop {
            if let Some((m, used)) = msg::decode(&self.clear).map_err(|e| FrpError::Protocol(e.to_string()))? {
                self.clear.drain(..used);
                return Ok(m);
            }
            let mut buf = [0u8; 4096];
            let n = self.io.read(&mut buf).await.map_err(FrpError::io)?;
            if n == 0 {
                return Err(FrpError::Ended("frps ended the control stream".into()));
            }
            let fresh = &mut buf[..n];
            self.cfb.as_mut().expect("set above").apply(fresh);
            self.clear.extend_from_slice(fresh);
        }
    }
}

/// A logged-in client of frps.
pub struct Session {
    pub mux: Mux,
    pub run_id: String,
    pub read: ControlRead,
    pub write: Arc<Mutex<ControlWrite>>,
    token: Zeroizing<String>,
}

impl Session {
    /// Log in on `mux` with `token`: frps's run id, or its refusal in its
    /// words (a wrong token is "token in login doesn't match token from
    /// configuration").
    pub async fn login(mux: Mux, token: &str) -> Result<Session, FrpError> {
        let mut stream = mux.open().map_err(FrpError::Ended)?;
        let login = msg::login(token, "", "", msg::now());
        msg::write(&mut stream, msg::LOGIN, &login).await.map_err(FrpError::io)?;
        let answer = tokio::time::timeout(ANSWER_LIMIT, msg::read(&mut stream))
            .await
            .map_err(|_| FrpError::Protocol(format!("no answer to the login within {} s", ANSWER_LIMIT.as_secs())))?
            .map_err(|e| FrpError::Protocol(format!("the answer to the login: {e}")))?;
        if answer.kind != msg::LOGIN_RESP {
            return Err(FrpError::Protocol(format!(
                "a message {:?} in the place of the login's answer",
                answer.kind as char
            )));
        }
        if let Some(words) = answer.error() {
            return Err(FrpError::Refused { step: "the login", words: words.to_string() });
        }
        let run_id = answer.text("run_id").to_string();
        let key = cfb::key(token.as_bytes());
        let iv = cfb::iv().map_err(FrpError::Protocol)?;
        let (read, write) = tokio::io::split(stream);
        let write = ControlWrite { io: write, cfb: Cfb::encrypter(&key, &iv), iv: Some(iv) };
        let read = ControlRead { io: read, key, cfb: None, clear: Vec::new() };
        Ok(Session { mux, run_id, read, write: Arc::new(Mutex::new(write)), token: Zeroizing::new(token.into()) })
    }

    /// A heartbeat, signed with the token.
    pub async fn ping(&self) -> Result<(), FrpError> {
        self.write.lock().await.send(msg::PING, &msg::ping(&self.token, msg::now())).await
    }

    /// A work connection, as frps asked for one: the stream, once frps
    /// started it for a visitor.
    pub async fn work_conn(mux: &Mux, token: &str, run_id: &str) -> Result<(DuplexStream, Msg), FrpError> {
        let mut stream = mux.open().map_err(FrpError::Ended)?;
        msg::write(&mut stream, msg::NEW_WORK_CONN, &msg::new_work_conn(token, run_id, msg::now()))
            .await
            .map_err(FrpError::io)?;
        // A work connection waits in frps's pool for its visitor: no bound.
        let start = msg::read(&mut stream).await.map_err(|e| FrpError::Protocol(format!("a work connection: {e}")))?;
        if start.kind != msg::START_WORK_CONN {
            return Err(FrpError::Protocol(format!(
                "a message {:?} in the place of StartWorkConn",
                start.kind as char
            )));
        }
        if let Some(words) = start.error() {
            return Err(FrpError::Refused { step: "a work connection", words: words.to_string() });
        }
        Ok((stream, start))
    }

    /// The token of the login, for the work connections.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// A visitor's stream to the STCP service `name` of `secret`, on `mux`: the
/// service's bytes, or frps's refusal in its words ("visitor connection of
/// [NAME] auth failed" for a wrong secret, "custom listener for [NAME]
/// doesn't exist" for no node).
pub async fn visit(mux: &Mux, name: &str, secret: &str, run_id: &str) -> Result<DuplexStream, FrpError> {
    visit_at(mux, name, secret, run_id, msg::now()).await
}

/// [`visit`] signed at `timestamp`, which a test plants.
pub async fn visit_at(
    mux: &Mux,
    name: &str,
    secret: &str,
    run_id: &str,
    timestamp: i64,
) -> Result<DuplexStream, FrpError> {
    let mut stream = mux.open().map_err(FrpError::Ended)?;
    let ask = msg::new_visitor_conn(name, secret, run_id, timestamp);
    msg::write(&mut stream, msg::NEW_VISITOR_CONN, &ask).await.map_err(FrpError::io)?;
    let answer = tokio::time::timeout(ANSWER_LIMIT, msg::read(&mut stream))
        .await
        .map_err(|_| FrpError::Protocol(format!("no answer to the visit within {} s", ANSWER_LIMIT.as_secs())))?
        .map_err(|e| FrpError::Protocol(format!("the answer to the visit: {e}")))?;
    if answer.kind != msg::NEW_VISITOR_CONN_RESP {
        return Err(FrpError::Protocol(format!(
            "a message {:?} in the place of the visit's answer",
            answer.kind as char
        )));
    }
    if let Some(words) = answer.error() {
        return Err(FrpError::Refused { step: "the visit", words: words.to_string() });
    }
    Ok(stream)
}
