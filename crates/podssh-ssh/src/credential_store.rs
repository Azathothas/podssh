//! A store of credentials in `podssh agent` (T-228): the password of a
//! server and the passphrase of a key file, in the agent's memory for its
//! life or a lifetime, never on disk. The agent protocol carries them in its
//! extension message (draft-miller-ssh-agent, section 3.8), with the names
//! of [`STORE`], [`LOOKUP`], [`FORGET`] and [`COUNT`]. russh's agent server
//! answers no extension, so [`serve_client`] stands in front of it: it
//! answers the store's requests itself, refuses an RSA key (T-257) and a key
//! for a confirmation of each use (T-284), and passes each other message
//! on. An
//! agent that is not podssh's answers `SSH_AGENT_FAILURE` or
//! `SSH_AGENT_EXTENSION_FAILURE`, or closes the connection at the question,
//! which a client reads as no store. A locked agent (`ssh-add -x`) tells
//! nothing.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Keep a credential, with its lifetime.
pub const STORE: &str = "store@podssh";
/// The credential of a target, if one is kept.
pub const LOOKUP: &str = "lookup@podssh";
/// Drop the credential of a target, as one that a server refused.
pub const FORGET: &str = "forget@podssh";
/// How many credentials are kept, for `podssh doctor`, which never asks
/// which.
pub const COUNT: &str = "count@podssh";

/// The largest frame either side reads, as OpenSSH's agent bounds its own.
pub const MAX_FRAME: usize = 256 * 1024;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const LOCK: u8 = 22;
const UNLOCK: u8 = 23;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;
const ADD_CONSTRAINED: u8 = 25;
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;

/// What a credential opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A server's password, for `user@host:port`.
    Password,
    /// A key file's passphrase, for its absolute path.
    Passphrase,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Password => "password",
            Kind::Passphrase => "passphrase",
        }
    }

    fn from_word(word: &[u8]) -> Option<Kind> {
        match word {
            b"password" => Some(Kind::Password),
            b"passphrase" => Some(Kind::Passphrase),
            _ => None,
        }
    }
}

/// The key of a credential in the store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub kind: Kind,
    pub name: String,
}

impl Target {
    /// The password of `user` at `host` and `port`; the host in lower case,
    /// an IPv6 address in brackets.
    pub fn password(user: &str, host: &str, port: u16) -> Target {
        let host = host.to_ascii_lowercase();
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host };
        Target { kind: Kind::Password, name: format!("{user}@{host}:{port}") }
    }

    /// The passphrase of the key file `path`, by its absolute path.
    pub fn passphrase(path: &Path) -> Target {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        Target { kind: Kind::Passphrase, name: absolute.display().to_string() }
    }

    /// What `-v` says of it: its kind and name, never its value.
    pub fn shown(&self) -> String {
        format!("the {} for {}", self.kind.word(), self.name)
    }
}

struct Entry {
    secret: Zeroizing<String>,
    until: Option<Instant>,
}

/// The credentials of an agent, in its memory, and its keys of security
/// keys (T-229), which russh's server cannot sign with.
#[derive(Default)]
pub struct Store {
    entries: Mutex<HashMap<(Kind, String), Entry>>,
    /// The agent is locked: nothing is told until it is unlocked.
    locked: AtomicBool,
    pub security_keys: crate::sk::agent::Held,
}

impl Store {
    /// The answer to `request`, the body of one frame from a client, when it
    /// is a request of this store; `None` for another message, which the
    /// agent's own server answers.
    pub fn answer(&self, request: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (&typ, mut rest) = request.split_first()?;
        if typ != EXTENSION {
            return None;
        }
        let name = take_string(&mut rest).ok()?;
        let name = std::str::from_utf8(&name).ok()?;
        if ![STORE, LOOKUP, FORGET, COUNT].contains(&name) {
            return None;
        }
        if self.locked.load(Ordering::SeqCst) {
            return Some(Zeroizing::new(vec![FAILURE]));
        }
        let answer = match name {
            STORE => self.store(rest),
            LOOKUP => self.lookup(rest),
            FORGET => self.forget(rest),
            _ => Some(self.count()),
        };
        Some(answer.unwrap_or_else(|| Zeroizing::new(vec![FAILURE])))
    }

    /// What a request to the agent itself said about the lock, once the
    /// agent answered it: `lock` and `unlock` that succeeded.
    pub fn observe(&self, request: &[u8], answer: &[u8]) {
        if answer.first() == Some(&SUCCESS) {
            match request.first() {
                Some(&LOCK) => self.locked.store(true, Ordering::SeqCst),
                Some(&UNLOCK) => self.locked.store(false, Ordering::SeqCst),
                _ => {}
            }
        }
    }

    fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<(Kind, String), Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn store(&self, mut rest: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let target = take_target(&mut rest)?;
        let secret = Zeroizing::new(take_string(&mut rest).ok()?);
        let lifetime = take_u32(&mut rest).ok()?;
        let secret = Zeroizing::new(String::from_utf8(secret.to_vec()).ok()?);
        let until = (lifetime > 0).then(|| Instant::now() + Duration::from_secs(u64::from(lifetime)));
        self.entries().insert((target.kind, target.name), Entry { secret, until });
        Some(Zeroizing::new(vec![SUCCESS]))
    }

    fn lookup(&self, mut rest: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let target = take_target(&mut rest)?;
        let mut entries = self.entries();
        let key = (target.kind, target.name);
        if entries.get(&key).is_some_and(|e| e.until.is_some_and(|until| Instant::now() >= until)) {
            entries.remove(&key);
        }
        let mut answer = Zeroizing::new(vec![SUCCESS]);
        match entries.get(&key) {
            Some(entry) => {
                answer.push(1);
                put_string(&mut answer, entry.secret.as_bytes());
            }
            None => answer.push(0),
        }
        Some(answer)
    }

    fn forget(&self, mut rest: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let target = take_target(&mut rest)?;
        self.entries().remove(&(target.kind, target.name));
        Some(Zeroizing::new(vec![SUCCESS]))
    }

    fn count(&self) -> Zeroizing<Vec<u8>> {
        let now = Instant::now();
        let mut entries = self.entries();
        entries.retain(|_, e| e.until.is_none_or(|until| now < until));
        let mut answer = Zeroizing::new(vec![SUCCESS]);
        answer.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        answer
    }
}

/// Serve one client of the agent until it goes: each request of the store
/// is answered here, and each other message goes to `agent`, the agent's own
/// server, whose answer goes back to the client. A request to add an RSA key
/// gets FAILURE here: russh's server would sign with it through the `rsa`
/// crate, which is not constant-time (T-257). So does a request to add a key
/// for a confirmation of each use, which russh's server would use unasked
/// (T-284). A key of a security key is kept, listed and used here (T-229).
pub async fn serve_client<C, A>(mut client: C, mut agent: A, store: &Store) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Some(request) = read_frame(&mut client).await? else { return Ok(()) };
        let held = match store.answer(&request) {
            Some(answer) => Some(answer),
            None => store.security_keys.answer(&request, store.is_locked()).await,
        };
        let answer = match held {
            Some(answer) => answer,
            None if crate::rsa_key::adds_rsa_key(&request) || adds_confirmed_key(&request) => {
                Zeroizing::new(vec![FAILURE])
            }
            None => {
                write_frame(&mut agent, &request).await?;
                let answer = read_frame(&mut agent)
                    .await?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the agent's server went"))?;
                store.observe(&request, &answer);
                store.security_keys.after(&request, answer, store.is_locked())
            }
        };
        write_frame(&mut client, &answer).await?;
    }
}

/// Whether an agent's request adds a key for a confirmation of each use
/// (`ssh-add -c`): russh's agent server keeps the constraint and signs with
/// the key unasked, so the front refuses it (T-284). The request is read as
/// russh's server reads it: the key, its comment, then each constraint.
fn adds_confirmed_key(request: &[u8]) -> bool {
    use russh::keys::ssh_encoding::Decode;
    let Some((&ADD_CONSTRAINED, mut rest)) = request.split_first() else { return false };
    let key = russh::keys::ssh_key::private::KeypairData::decode(&mut rest);
    if key.is_err() || String::decode(&mut rest).is_err() {
        return false;
    }
    while let Some((&constraint, after)) = rest.split_first() {
        match constraint {
            CONSTRAIN_CONFIRM => return true,
            CONSTRAIN_LIFETIME if after.len() >= 4 => rest = &after[4..],
            // russh's server refuses any other constraint itself.
            _ => return false,
        }
    }
    false
}

/// Why the store of an agent could not answer.
#[derive(Debug)]
pub enum StoreError {
    /// The agent has no store: it is not podssh's, or it is locked. An
    /// agent that closed the connection at the question has none either.
    NoStore,
    Io(io::Error),
    /// The answer was not one that the store gives.
    Protocol,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoStore => {
                f.write_str("the agent keeps no credentials: it is not podssh agent, or it is locked")
            }
            StoreError::Io(e) => write!(f, "the agent did not answer: {e}"),
            StoreError::Protocol => f.write_str("the agent's answer was not one of podssh agent's store"),
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// The store of the agent at the other end of `stream`.
pub struct StoreClient<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> StoreClient<S> {
    pub fn new(stream: S) -> Self {
        StoreClient { stream }
    }

    /// Keep `secret` for `target`, for `lifetime` seconds, or the agent's
    /// life with none.
    pub async fn store(&mut self, target: &Target, secret: &str, lifetime: Option<u32>) -> Result<(), StoreError> {
        let mut request = request(STORE, target);
        put_string(&mut request, secret.as_bytes());
        request.extend_from_slice(&lifetime.unwrap_or(0).to_be_bytes());
        let answer = self.ask(&request).await?;
        if answer.as_slice() == [SUCCESS] {
            Ok(())
        } else {
            Err(StoreError::Protocol)
        }
    }

    /// The secret kept for `target`, if any.
    pub async fn lookup(&mut self, target: &Target) -> Result<Option<Zeroizing<String>>, StoreError> {
        let answer = self.ask(&request(LOOKUP, target)).await?;
        match answer.as_slice() {
            [SUCCESS, 0] => Ok(None),
            [SUCCESS, 1, rest @ ..] => {
                let mut rest = rest;
                let secret = Zeroizing::new(take_string(&mut rest).map_err(|_| StoreError::Protocol)?);
                let secret = String::from_utf8(secret.to_vec()).map_err(|_| StoreError::Protocol)?;
                Ok(Some(Zeroizing::new(secret)))
            }
            _ => Err(StoreError::Protocol),
        }
    }

    /// Drop the secret of `target`.
    pub async fn forget(&mut self, target: &Target) -> Result<(), StoreError> {
        let answer = self.ask(&request(FORGET, target)).await?;
        if answer.as_slice() == [SUCCESS] {
            Ok(())
        } else {
            Err(StoreError::Protocol)
        }
    }

    /// How many secrets are kept.
    pub async fn count(&mut self) -> Result<u32, StoreError> {
        let mut body = Zeroizing::new(vec![EXTENSION]);
        put_string(&mut body, COUNT.as_bytes());
        let answer = self.ask(&body).await?;
        match answer.as_slice() {
            [SUCCESS, a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(StoreError::Protocol),
        }
    }

    async fn ask(&mut self, request: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        write_frame(&mut self.stream, request).await?;
        let Some(answer) = read_frame(&mut self.stream).await? else { return Err(StoreError::NoStore) };
        if matches!(answer.first(), Some(&FAILURE | &EXTENSION_FAILURE)) {
            return Err(StoreError::NoStore);
        }
        Ok(answer)
    }
}

/// How long a lookup in the agent's store may take, connection included.
const ASK_LIMIT: Duration = Duration::from_secs(5);

/// The secret that the agent named by `agent` keeps for `target`: none when
/// no agent runs, when it keeps no store, or when it keeps nothing for it.
/// `-v` names where a secret came from, never its value.
pub(crate) async fn stored(
    agent: &crate::options::Agent,
    target: &Target,
    log: &crate::log::Log,
) -> Option<Zeroizing<String>> {
    let ask = async {
        let client = crate::keys::connect_agent(agent).await.ok().flatten()?;
        StoreClient::new(client.into_inner()).lookup(target).await.ok().flatten()
    };
    let secret = tokio::time::timeout(ASK_LIMIT, ask).await.ok().flatten()?;
    log.verbose(&format!("{} from podssh agent", target.shown()));
    Some(secret)
}

/// Make the agent forget the secret of `target`, which a server refused, so
/// that it is never tried twice.
pub(crate) async fn forget(agent: &crate::options::Agent, target: &Target, log: &crate::log::Log) {
    let ask = async {
        let client = crate::keys::connect_agent(agent).await.ok().flatten()?;
        StoreClient::new(client.into_inner()).forget(target).await.ok()
    };
    if tokio::time::timeout(ASK_LIMIT, ask).await.ok().flatten().is_some() {
        log.verbose(&format!("{} was refused, and podssh agent forgets it", target.shown()));
    }
}

/// How many secrets the agent named by `agent` keeps, for `podssh doctor`:
/// `None` when no agent runs.
pub async fn count(agent: &crate::options::Agent) -> Option<Result<u32, StoreError>> {
    let ask = async {
        let client = match crate::keys::connect_agent(agent).await {
            Ok(Some(client)) => client,
            Ok(None) => return None,
            Err(e) => return Some(Err(StoreError::Io(io::Error::other(e)))),
        };
        Some(StoreClient::new(client.into_inner()).count().await)
    };
    let late = || Some(Err(StoreError::Io(io::Error::new(io::ErrorKind::TimedOut, "no answer within 5 s"))));
    tokio::time::timeout(ASK_LIMIT, ask).await.unwrap_or_else(|_| late())
}

/// The body of a request of the store about `target`.
fn request(name: &str, target: &Target) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(vec![EXTENSION]);
    put_string(&mut body, name.as_bytes());
    put_string(&mut body, target.kind.word().as_bytes());
    put_string(&mut body, target.name.as_bytes());
    body
}

/// One frame's body: `None` at the end of the stream before a frame.
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a frame of {length} bytes")));
    }
    let mut body = Zeroizing::new(vec![0u8; length]);
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    stream.write_all(&frame).await?;
    stream.flush().await
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_u32(rest: &mut &[u8]) -> Result<u32, ()> {
    let (bytes, tail) = rest.split_first_chunk::<4>().ok_or(())?;
    *rest = tail;
    Ok(u32::from_be_bytes(*bytes))
}

fn take_string(rest: &mut &[u8]) -> Result<Vec<u8>, ()> {
    let length = take_u32(rest)? as usize;
    if rest.len() < length {
        return Err(());
    }
    let (value, tail) = rest.split_at(length);
    *rest = tail;
    Ok(value.to_vec())
}

fn take_target(rest: &mut &[u8]) -> Option<Target> {
    let kind = Kind::from_word(&take_string(rest).ok()?)?;
    let name = String::from_utf8(take_string(rest).ok()?).ok()?;
    Some(Target { kind, name })
}

#[cfg(test)]
#[path = "credential_store_tests.rs"]
mod tests;
