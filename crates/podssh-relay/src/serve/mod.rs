//! The relay as a role of podssh (T-169, the operator's ruling Q63): the
//! forward road of the relay's contract, version `2026-10-03-r2`, served by
//! podssh itself, so that each client of podssh and each test of the forward
//! road works against it unchanged (`docs/relay.md`, `docs/mesh.md`). The
//! caller owns the listener and TLS (`podssh relay serve`); this serves one
//! connection's request.

pub mod docs;
pub mod forward;
pub mod policy;
pub mod tokens;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, read_request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The contract that the role serves.
pub const CONTRACT: &str = "2026-10-03-r2";
/// How long a client has to send its request's head.
const HEAD_WAIT: Duration = Duration::from_secs(30);
/// The largest body of a mint, which the contract sends as `{}`.
const MINT_BODY: usize = 4096;

/// The contract's limits (`docs/relay.md`, "Limits that users see").
#[derive(Debug, Clone)]
pub struct Limits {
    /// The dial of a target, before the upgrade.
    pub connect: Duration,
    /// No payload either way for this long ends a session.
    pub idle: Duration,
    pub session: Duration,
    /// Payload bytes, both ways together.
    pub bytes: u64,
    /// An empty binary frame to the client this often.
    pub keepalive: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(180),
            session: Duration::from_secs(12 * 3600),
            bytes: 64 << 20,
            keepalive: Duration::from_secs(25),
        }
    }
}

/// Who may mint a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mint {
    /// Anyone, as the default relay mints.
    Anyone,
    /// No one: `503`, which a client reads as "do not retry"; tokens come
    /// another way.
    Nobody,
}

/// What a role serves, and how.
pub struct Config {
    /// Said in `/health`, `/relays.json` and `/trace`.
    pub version: String,
    pub mint: Mint,
    pub tokens: tokens::Tokens,
    pub policy: policy::Policy,
    pub limits: Limits,
    /// Each mint, upgrade and client's Close as a line (`mint`, `upgrade`,
    /// `close CODE`), as the stand-in relay prints them for a harness.
    pub events: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl Config {
    fn event(&self, line: &str) {
        if let Some(say) = &self.events {
            say(line);
        }
    }
}

/// Serve the one request of `stream`, which closes after it as each request
/// of the contract is one connection's.
pub async fn serve_connection<S>(mut stream: S, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (head, pending) = match tokio::time::timeout(HEAD_WAIT, read_request(&mut stream, Vec::new())).await {
        Ok(Ok(read)) => read,
        Ok(Err(e)) => match e.status() {
            Some(status) => return answer(&mut stream, request::refusal(status, &e.to_string(), &[])).await,
            None => return,
        },
        Err(_) => return,
    };
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    match (head.method.as_str(), path.as_str()) {
        ("GET", p) if p.starts_with("/connect/") => forward::connect(stream, head, pending, cfg).await,
        ("POST", "/v1/mint") => mint(&mut stream, &head, pending, &cfg).await,
        ("GET", "/health") => answer(&mut stream, docs::json(&docs::health(&cfg))).await,
        ("GET", "/relays.json") => answer(&mut stream, docs::json(&docs::relays(&cfg, &head))).await,
        ("GET", "/trace") => {
            let reply = docs::trace(&cfg, &head).await;
            answer(&mut stream, reply).await
        }
        ("GET", "/llms-full.txt") => answer(&mut stream, docs::text(docs::SPEC)).await,
        (_, p) => answer(&mut stream, request::refusal(404, &format!("{p}: not found"), &[])).await,
    }
}

/// `POST /v1/mint`: `{token, expires, scope}`.
async fn mint<S>(stream: &mut S, head: &request::Request, mut pending: Vec<u8>, cfg: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if cfg.mint == Mint::Nobody {
        let why = "/v1/mint: this relay mints no token; its owner gives them";
        return answer(stream, request::refusal(503, why, &[])).await;
    }
    let length: usize = head.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    if length > MINT_BODY {
        return answer(stream, request::refusal(413, &format!("/v1/mint: a body of {MINT_BODY} bytes at most"), &[])).await;
    }
    let mut chunk = [0u8; 1024];
    while pending.len() < length {
        match tokio::time::timeout(HEAD_WAIT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
    cfg.event("mint");
    let (token, expires) = cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let body = serde_json::json!({ "token": token, "expires": expires, "scope": "forward" });
    answer(stream, docs::json(&body)).await;
}

/// Write `reply`, then end the connection.
async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) {
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}
