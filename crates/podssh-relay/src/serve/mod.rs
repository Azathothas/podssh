//! The relay as a role of podssh (T-169, the operator's ruling Q63): the
//! forward road of the relay's contract, version `2026-10-03-r2`, and its
//! reverse road (T-427, [`reverse`]), served by podssh itself, so that each
//! client of podssh and each test of both roads works against it unchanged
//! (`docs/relay.md`, `docs/mesh.md`). The caller owns the listener and TLS
//! (`podssh relay serve`); this serves one connection's request, and brakes
//! the mints and pairs of each address ([`brake`], T-454). Behind a quick
//! tunnel, the node's origin is the role, with no listener (T-428,
//! `behind`). Its targets are dialed through the host's proxy when one is
//! set ([`egress`], T-457), and an IPv6 target that its host cannot route
//! out is refused before the upgrade ([`ipv6`], T-253). Its probes tell a
//! client what the path does to a stream ([`probe`], T-325), and its HTTP
//! road carries a session where the upgrade is refused on the way
//! ([`http_road`], T-319). The role's own listener takes TLS, or the
//! cleartext road beside it by the first byte ([`listener`], [`cleartext`],
//! T-326), with tokens of one session alone.
//! Beside the contract, its forward road in the resumable layer keeps a
//! standard sshd's connection across a drop of the client's link ([`layer`],
//! T-173).
//! Its mailbox is a meeting point of the pairing by a short code
//! ([`mailbox`], T-086).

#[cfg(feature = "quick")]
pub mod behind;
pub mod brake;
pub mod cleartext;
pub mod docs;
pub mod egress;
pub mod forward;
pub mod http_road;
// HTTP/2 with extended CONNECT at the role's listener (T-321).
pub mod http2;
pub mod ipv6;
pub mod keys;
pub mod layer;
pub mod listener;
pub mod mailbox;
pub mod policy;
pub mod probe;
pub mod reverse;
pub mod sockets;
pub mod tokens;

use std::net::IpAddr;
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

/// Who may mint a token, and make a pair.
#[derive(Clone)]
pub enum Mint {
    /// Anyone, as the default relay mints.
    Anyone,
    /// No one: `503`, which a client reads as "do not retry"; tokens come
    /// another way.
    Nobody,
    /// The keys of this list, each by its signature of a challenge (T-448).
    Keys(std::path::PathBuf),
    /// The members of the net that the binary reads (T-455), each by the
    /// same signature, and the keys of a list beside them when one is named.
    Net(Arc<dyn keys::Members>, Option<std::path::PathBuf>),
}

impl Mint {
    /// Its word in `/health`.
    pub fn word(&self) -> &'static str {
        match self {
            Mint::Anyone => "anyone",
            Mint::Nobody => "nobody",
            Mint::Keys(_) => "keys",
            Mint::Net(_, None) => "net",
            Mint::Net(_, Some(_)) => "net,keys",
        }
    }
}

impl std::fmt::Debug for Mint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mint::Anyone => f.write_str("Anyone"),
            Mint::Nobody => f.write_str("Nobody"),
            Mint::Keys(file) => f.debug_tuple("Keys").field(file).finish(),
            // The net is the binary's, and has no words of its own here.
            Mint::Net(_, list) => f.debug_tuple("Net").field(list).finish(),
        }
    }
}

/// Where a role says each mint, upgrade and client's Close.
pub type Events = Box<dyn Fn(&str) + Send + Sync>;

/// What a role serves, and how.
pub struct Config {
    /// Said in `/health`, `/relays.json` and `/trace`.
    pub version: String,
    pub mint: Mint,
    pub tokens: tokens::Tokens,
    pub policy: policy::Policy,
    /// How its targets are dialed: directly, or through the host's proxy
    /// (T-457).
    pub egress: egress::Egress,
    pub limits: Limits,
    /// The pairs of the reverse road, and their sockets.
    pub pairs: reverse::Pairs,
    /// The sessions of the forward road in the resumable layer, with their
    /// targets, across links (T-173).
    pub resumes: layer::Resumes,
    /// The challenges that a key answered (T-448).
    pub answered: keys::Answered,
    /// The counts of `/v1/mint` and `/v1/pair` for each address (T-454).
    pub brake: brake::Brake,
    /// Each mint, upgrade, read of `/relays.json` and client's Close as a
    /// line (`mint`, `upgrade`, `relays.json`, `close CODE`), and each step of
    /// the reverse road (`reverse ...`), as
    /// the stand-in relay prints them for a harness.
    pub events: Option<Events>,
}

impl Config {
    fn event(&self, line: &str) {
        if let Some(say) = &self.events {
            say(line);
        }
    }
}

/// Whether `path`, with no query, is one of the role's, as
/// [`serve_named`] routes them: what the node of a quick tunnel gives the
/// role in place of its 404 (T-428). Each path under `/v1/` is the role's,
/// which answers the ones that it does not know.
pub fn serves(path: &str) -> bool {
    matches!(path, "/health" | "/v1/mint" | "/relays.json" | "/trace" | "/llms-full.txt")
        || path.starts_with("/connect/")
        || path.starts_with("/v1/")
}

/// Serve the one request of `stream`, which closes after it as each request
/// of the contract is one connection's.
pub async fn serve_connection<S>(stream: S, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_named(stream, cfg, None).await
}

/// [`serve_connection`] for a stream whose TLS asked for the name `sni`: a
/// key's signed request must name it (T-448).
pub async fn serve_named<S>(stream: S, cfg: Arc<Config>, sni: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_from(stream, cfg, sni, None).await
}

/// [`serve_named`] for a client at `from`, by whom the brake counts (T-454):
/// a listener's TCP peer; behind the quick tunnel, where the peer is
/// Cloudflare's edge, the visitor that the edge names
/// ([`brake::edge_visitor`]). Requests with none share one count.
pub async fn serve_from<S>(mut stream: S, cfg: Arc<Config>, sni: Option<String>, from: Option<IpAddr>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((head, pending, _)) = head_of(&mut stream).await else { return };
    // The HTTP road keeps its connection for its next request, and gives
    // back a request of another path that came on it (T-319).
    let (mut stream, head, pending) = if http_road::serves(&head.target) {
        match http_road::serve(stream, head, pending, cfg.clone()).await {
            Some(next) => next,
            None => return,
        }
    } else {
        (stream, head, pending)
    };
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    if brake::braked(&head.method, &path) {
        if let Err(braked) = cfg.brake.take(brake::Who::of(from)) {
            return slow_down(&mut stream, &head, pending, &path, braked, &cfg).await;
        }
    }
    match (head.method.as_str(), path.as_str()) {
        ("GET", p) if p.starts_with("/connect/") => forward::connect(stream, head, pending, cfg).await,
        // The forward road in the resumable layer (T-173), beside the contract.
        ("GET", p) if layer::serves(p) => layer::connect(stream, head, pending, cfg).await,
        ("POST", "/v1/mint") => mint(&mut stream, &head, pending, &cfg, sni.as_deref()).await,
        ("GET", "/health") => answer(&mut stream, docs::json(&docs::health(&cfg))).await,
        ("GET", "/relays.json") => {
            // A harness counts the reads of the document (T-173).
            cfg.event("relays.json");
            answer(&mut stream, docs::json(&docs::relays(&cfg, &head))).await
        }
        ("GET", "/trace") => {
            let reply = docs::trace(&cfg, &head).await;
            answer(&mut stream, reply).await
        }
        ("GET", "/llms-full.txt") => answer(&mut stream, docs::text(docs::SPEC)).await,
        // What a path does to a stream, for `podssh doctor --stream` (T-325).
        (_, p) if probe::serves(p) => probe::request(stream, head, pending).await,
        // The meeting point of the pairing by a short code (T-086).
        (_, p) if mailbox::serves(p) => mailbox::request(stream, head, pending, cfg).await,
        (_, p) if reverse::serves(p) => reverse::request(stream, head, pending, cfg, sni).await,
        (_, p) => answer(&mut stream, request::refusal(404, &format!("{p}: not found"), &[])).await,
    }
}

/// The head of a connection's one request, the bytes after it, and its path
/// with no query; `None` once a refusal went, or when the client went away
/// or was too slow.
async fn head_of<S>(stream: &mut S) -> Option<(request::Request, Vec<u8>, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (head, pending) = match tokio::time::timeout(HEAD_WAIT, read_request(stream, Vec::new())).await {
        Ok(Ok(read)) => read,
        Ok(Err(e)) => {
            if let Some(status) = e.status() {
                answer(stream, request::refusal(status, &e.to_string(), &[])).await;
            }
            return None;
        }
        Err(_) => return None,
    };
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    Some((head, pending, path))
}

/// `POST /v1/mint`: `{token, expires, scope}`; with `?once=1`, a token of
/// one session, `"once": true` (T-326).
async fn mint<S>(stream: &mut S, head: &request::Request, pending: Vec<u8>, cfg: &Config, sni: Option<&str>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The body first: a byte left unread would make the end of the
    // connection a reset, which can lose the answer.
    let sent = match body(stream, head, pending, MINT_BODY, "/v1/mint").await {
        Ok(sent) => sent,
        Err(refusal) => return answer(stream, refusal).await,
    };
    if matches!(cfg.mint, Mint::Nobody) {
        let why = "/v1/mint: this relay mints no token; its owner gives them";
        return answer(stream, request::refusal(503, why, &[])).await;
    }
    if let Err(refusal) = proven(cfg, head, sni, "/v1/mint", &sent) {
        return answer(stream, refusal).await;
    }
    // A token of one session, which an upgrade spends: the one that the
    // cleartext road asks for, and the only one minted in cleartext.
    if cleartext::once_asked(&head.target) {
        cfg.event("mint once");
        let body = match cfg.tokens.mint_once(tokens::now_ms()) {
            Ok((token, expires)) => {
                serde_json::json!({ "token": token, "expires": expires, "scope": "forward", "once": true })
            }
            Err(why) => return answer(stream, request::refusal(503, &format!("/v1/mint: {why}"), &[])).await,
        };
        return answer(stream, docs::json(&body)).await;
    }
    cfg.event("mint");
    let (token, expires) = cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let body = serde_json::json!({ "token": token, "expires": expires, "scope": "forward" });
    answer(stream, docs::json(&body)).await;
}

/// The brake's `429`, with the seconds to wait in `Retry-After`, which
/// podssh's client says. The body is read first, as for each answer.
async fn slow_down<S>(
    stream: &mut S,
    head: &request::Request,
    pending: Vec<u8>,
    path: &str,
    braked: brake::Braked,
    cfg: &Config,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = body(stream, head, pending, MINT_BODY, path).await;
    let limit = cfg.brake.limit();
    // Once for each address that meets the brake, not for each request: the
    // address itself is not said.
    if braked.first {
        cfg.event(&format!("{path}: braked, an address past {limit} requests in a minute"));
    }
    let wait = braked.wait_s.to_string();
    let why = format!("{path}: {limit} requests of this address in a minute; ask again in {wait} s");
    answer(stream, request::refusal(429, &why, &[("Retry-After", wait.as_str())])).await;
}

/// The key that proved itself for a mint or a pair, whose share of the pairs
/// counts it (T-630); none where the role asks for no key.
type Maker = Option<crate::identity::PublicKey>;

/// Whether a mint or a pair of `body` may go on, by whom the role mints for:
/// `Ok` holds the key that proved itself, `Err` the answer, a `401` that asks
/// for a key or a `403`.
fn proven(cfg: &Config, head: &request::Request, sni: Option<&str>, path: &str, body: &[u8]) -> Result<Maker, Vec<u8>> {
    let Some(whom) = keys::Whom::of(&cfg.mint) else { return Ok(None) };
    match keys::prove(cfg, &whom, head, sni, path, body, tokens::now_ms()) {
        keys::Proof::Key(key, member) => {
            // A member of the net by its name too (T-455), for the owner.
            let member = member.map(|words| format!(", {words}")).unwrap_or_default();
            cfg.event(&format!("{path}: the key {}{member}", key.fingerprint()));
            Ok(Some(key))
        }
        keys::Proof::Ask(challenge, ends) => Err(keys::ask(&challenge, ends)),
        keys::Proof::Refused(why) => {
            cfg.event(&format!("{path}: refused, {why}"));
            Err(request::refusal(403, &format!("{path}: {why}"), &[]))
        }
    }
}

/// The body of a request, `max` bytes at most; `Err` holds the refusal to
/// answer, empty for a client that went away.
async fn body<S>(
    stream: &mut S,
    head: &request::Request,
    mut pending: Vec<u8>,
    max: usize,
    path: &str,
) -> Result<Vec<u8>, Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let length: usize = head.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    if length > max {
        return Err(request::refusal(413, &format!("{path}: a body of {max} bytes at most"), &[]));
    }
    let mut chunk = [0u8; 1024];
    while pending.len() < length {
        match tokio::time::timeout(HEAD_WAIT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&chunk[..n]),
            _ => return Err(Vec::new()),
        }
    }
    pending.truncate(length);
    Ok(pending)
}

/// Write `reply`, then end the connection.
async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) {
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}
