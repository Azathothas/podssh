//! Encrypted Client Hello (T-642): the name of a host that publishes a list
//! in its HTTPS record goes sealed inside the ClientHello, and the hello in
//! the clear names the list's public name (`cloudflare-ech.com` in
//! Cloudflare's), so that what reads hellos on the way learns that alone.
//!
//! **Only when the user asks for it** (`PODSSH_ECH`, or the settings file's
//! `ECH`): the record is read before the session's connection, which behind
//! a proxy no resolver of podssh's makes otherwise (the call of T-642's
//! Decision, for the operator to confirm under Q86). Then, for each TLS
//! connection that podssh opens by a name ([`open`]):
//!
//! 1. the name's list, kept in the process ([`Cache`]), else read from the
//!    resolvers of DNS over HTTPS through the same proxy
//!    ([`crate::resolve::https`]), once for each name and TTL;
//! 2. a hello sealed with it; a server that refuses it with retry configs
//!    gets one more, with those, which then replace the list;
//! 3. a refusal with none, or any other failure of a sealed hello, cools the
//!    name for 5 minutes and goes on with a plain hello, as before; `strict`
//!    sends no plain hello.
//!
//! What it hides is the name alone. A proxy is given the name in its
//! CONNECT, as it must be to know where to go; the address, the times and
//! the sizes stay as they were; a resolver that lies defeats it.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use crate::client::{ConnectError, RelayStream};
use crate::dial::ProxyChoice;
use crate::tls::Trust;

pub mod cache;
mod config;
mod road;

pub use cache::{Cache, Clock, Lookup, Why};
pub use road::{Dial, READ_WITHIN, SEALED_WAIT};

/// The variable that asks for ECH.
pub const ECH_ENV: &str = "PODSSH_ECH";

/// Whether a run seals the names that publish a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Each hello names its host, as before: the default.
    #[default]
    Off,
    /// A name that publishes a list goes sealed; else, and after a refusal,
    /// a plain hello.
    On,
    /// As `On`, but no plain hello ever goes to a name that was to be sealed:
    /// the connection fails instead, with why.
    Strict,
}

impl Mode {
    /// The word of [`ECH_ENV`] or of the settings file's `ECH`: `None` for
    /// none or an empty one; another word is refused, with the words that
    /// it takes.
    pub fn parse(value: Option<&str>) -> Result<Option<Mode>, String> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") => Ok(None),
            Some("no" | "off" | "false" | "0") => Ok(Some(Mode::Off)),
            Some("yes" | "on" | "true" | "1") => Ok(Some(Mode::On)),
            Some("strict") => Ok(Some(Mode::Strict)),
            Some(_) => Err("give yes, no or strict".into()),
        }
    }

    /// [`Mode::parse`] of this process's variable, its name in a refusal.
    pub fn from_env() -> Result<Option<Mode>, String> {
        Mode::parse(std::env::var(ECH_ENV).ok().as_deref()).map_err(|why| format!("{ECH_ENV}: {why}"))
    }

    /// The word, as the variable takes it.
    pub fn word(self) -> &'static str {
        match self {
            Mode::Off => "no",
            Mode::On => "yes",
            Mode::Strict => "strict",
        }
    }
}

/// The mode that a command set, once it read its variable and its settings.
static SET: RwLock<Option<Mode>> = RwLock::new(None);

/// Set the process's mode: a command does, from [`ECH_ENV`], then its
/// settings file.
pub fn set_mode(mode: Mode) {
    *SET.write().unwrap_or_else(PoisonError::into_inner) = Some(mode);
}

/// The process's mode: the one set, else the variable's, else off.
pub fn mode() -> Mode {
    chosen(*SET.read().unwrap_or_else(PoisonError::into_inner), Mode::from_env())
}

/// The mode of `set`, else of the variable; a word of the variable that is
/// none of its own is off here, as a command refuses it before (78), and a
/// library's caller gets what it set.
fn chosen(set: Option<Mode>, env: Result<Option<Mode>, String>) -> Mode {
    set.or_else(|| env.ok().flatten()).unwrap_or_default()
}

/// Whether a connection to `server_name` under `trust` is to be sealed in
/// this process.
pub fn wanted(server_name: &str, trust: &Trust) -> bool {
    asks(mode(), server_name, trust)
}

/// Whether `mode` seals a hello to `server_name` under `trust`: a name and
/// not an address, which rustls seals no hello for; of two labels at least,
/// as a host of a local network publishes no list; and podssh's own trust,
/// as a caller's configuration cannot be made again with a list.
fn asks(mode: Mode, server_name: &str, trust: &Trust) -> bool {
    let name = server_name.trim_end_matches('.');
    mode != Mode::Off
        && !matches!(trust, Trust::Caller(_))
        && name.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_err()
        && name.contains('.')
}

/// TCP to `host:port` through `proxy`, then TLS for `server_name` with the
/// roots of `trust`, offering `alpn`: sealed where the process asks for it
/// and the name publishes a list, else a plain hello as always; and the
/// address that the TCP reached.
pub async fn open(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
    alpn: &[&[u8]],
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    let dial = Dial { host, port, server_name, trust, proxy, limit, alpn };
    let mode = mode();
    if !asks(mode, server_name, trust) {
        return road::plain(&dial).await;
    }
    // On the heap: the sealed road's future (a read of the name's record,
    // then a sealed hello and its fallbacks) is large, and on the stack of
    // each dial, ECH asked or not, it overflowed a test's thread.
    Box::pin(road::sealed(cache::process(), mode, &dial)).await
}

/// [`open`] in `mode` with the lists of `cache`, as a test holds them.
pub async fn open_with(
    cache: &Cache,
    mode: Mode,
    dial: &Dial<'_>,
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    if !asks(mode, dial.server_name, dial.trust) {
        return road::plain(dial).await;
    }
    Box::pin(road::sealed(cache, mode, dial)).await
}

/// What ECH did for a name's last connection, as `podssh doctor` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The server opened the sealed hello; `retried` when it took the retry
    /// configs that it sent to the first.
    Sealed { retried: bool },
    /// The name publishes no list: the hello was plain.
    NotPublished,
    /// The read of the name's record failed: the hello was plain.
    ReadFailed(String),
    /// The sealed hello failed, and why: the plain hello went next.
    Refused(String),
    /// Within 5 minutes of a refusal: the hello was plain, and nothing read.
    Cooled,
    /// `strict`: no plain hello went, and the connection failed.
    Strict(String),
}

impl Outcome {
    /// The outcome in words.
    pub fn words(&self) -> String {
        match self {
            Outcome::Sealed { retried: false } => "the name went sealed, and the server opened it".into(),
            Outcome::Sealed { retried: true } => {
                "the name went sealed with the retry configs of the server, which opened it".into()
            }
            Outcome::Strict(why) => format!("{why}; with {ECH_ENV}=strict no plain hello went"),
            other => format!("{}, so a plain hello named it", other.reason()),
        }
    }

    /// Why the name did not go sealed, with no word of what came after.
    fn reason(&self) -> String {
        match self {
            Outcome::Sealed { .. } => "the name went sealed".into(),
            Outcome::NotPublished => "the name publishes no list".into(),
            Outcome::ReadFailed(why) => format!("the read of its HTTPS record failed ({why})"),
            Outcome::Refused(why) => format!("the sealed hello failed ({why})"),
            Outcome::Cooled => "its sealed hello failed within the last 5 minutes".into(),
            Outcome::Strict(why) => why.clone(),
        }
    }

    /// Whether the name went sealed.
    pub fn sealed(&self) -> bool {
        matches!(self, Outcome::Sealed { .. })
    }
}

/// The names whose outcome is kept; past it, the oldest goes.
const OUTCOMES: usize = 64;

static KEPT: Mutex<Vec<(String, Outcome)>> = Mutex::new(Vec::new());

fn kept() -> MutexGuard<'static, Vec<(String, Outcome)>> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `name`'s last connection had `outcome`.
fn note(name: &str, outcome: Outcome) {
    let name = key(name);
    let mut kept = kept();
    kept.retain(|(n, _)| *n != name);
    if kept.len() >= OUTCOMES {
        kept.remove(0);
    }
    kept.push((name, outcome));
}

/// What ECH did for `name`'s last connection in this process.
pub fn outcome(name: &str) -> Option<Outcome> {
    let name = key(name);
    kept().iter().find(|(n, _)| *n == name).map(|(_, outcome)| outcome.clone())
}

/// A name as the process keeps it: lower case, with no final dot.
fn key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
