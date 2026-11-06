//! chisel's SSH inside its WebSocket (T-490), as its client speaks it at
//! v1.13.0 (`client/client.go`, `client/client_connect.go`,
//! `share/tunnel/tunnel_out_ssh.go`):
//!
//! - the client's version `SSH-chisel-v3-client`; the server's key checked
//!   by its fingerprint, SHA-256 of the key's wire form in base64 with its
//!   padding (`share/ccrypto`, `FingerprintKey`), when the file names one;
//! - password authentication with the user and password of `--auth`, empty
//!   for a server with no users, which lets each in;
//! - a global request `config`, JSON of the client's version and its
//!   remotes (`share/settings/config.go`), within the server's 10 s: the
//!   server checks each remote against the user's authfile, and refuses with
//!   its words in the failure;
//! - a channel `chisel` for each tunnel, its target `HOST:PORT` as the
//!   channel's data with no length before it (Go's `OpenChannel`, russh's
//!   `channel_open_raw` of podssh's patch); the server checks the user's
//!   authfile again and dials the target before it accepts, so a refusal is
//!   `access denied` and a failed dial `connect failed`;
//! - `ping` requests: the client's each 25 s, which the server answers
//!   `pong`; the server's, which russh answers with a failure, as chisel's
//!   client reads any answer as alive.
//!
//! The SSH connection to a server is kept for the process, so that each
//! session of `podssh each` or of a copy is a channel of one connection, as
//! chisel's own client carries its remotes.

use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use podssh_ssh::russh::client::{Config, Handle, Handler};
use podssh_ssh::russh::keys::{PublicKey, PublicKeyOrCertificate};
use podssh_ssh::russh::{ChannelOpenFailure, SshId};
use tokio::sync::Mutex;

use super::Road;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};

/// The version that chisel's client sends, and the server's.
pub const CLIENT_VERSION: &str = "SSH-chisel-v3-client";
/// How often the client pings, chisel's `--keepalive` default.
const PING_EVERY: Duration = Duration::from_secs(25);
/// The bound on the `config` request's answer and on a ping's.
const ANSWER_LIMIT: Duration = Duration::from_secs(15);

/// Why no channel opened: the line, and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub line: String,
    pub code: i32,
}

/// The fingerprint of `key` as chisel prints it.
pub fn fingerprint_of(key: &PublicKey) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let wire = key.to_bytes().unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&wire))
}

/// Takes the server's key when the file names no fingerprint, or when it
/// has that one; keeps what it saw for the words of a refusal.
pub struct Checker {
    want: Option<String>,
    seen: Arc<StdMutex<Option<String>>>,
}

impl Handler for Checker {
    type Error = podssh_ssh::russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let got = fingerprint_of(&key.public_key());
        let ok = self.want.as_ref().is_none_or(|want| *want == got);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(got);
        Ok(ok)
    }
}

type Shared = Arc<Handle<Checker>>;

/// The connections of this process, by server and user: one each.
fn kept() -> &'static Mutex<Vec<(String, Shared)>> {
    static KEPT: OnceLock<Mutex<Vec<(String, Shared)>>> = OnceLock::new();
    KEPT.get_or_init(|| Mutex::new(Vec::new()))
}

/// The JSON of the `config` request: the client's version, and the one
/// remote of a stdio tunnel to `host:port`, as `chisel client SERVER
/// stdio:HOST:PORT` sends it.
pub fn config(host: &str, port: u16) -> Vec<u8> {
    let remote = serde_json::json!({
        "LocalHost": "", "LocalPort": "", "LocalProto": "tcp",
        "RemoteHost": host, "RemotePort": port.to_string(), "RemoteProto": "tcp",
        "Socks": false, "UDPSocks": false, "Reverse": false, "Stdio": true,
    });
    let doc = serde_json::json!({ "Version": format!("podssh-{}", env!("CARGO_PKG_VERSION")), "Remotes": [remote] });
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// The target of a channel `chisel`: `HOST:PORT`, an IPv6 address in
/// brackets, as chisel's `L4Proto` reads it.
pub fn target(host: &str, port: u16) -> String {
    match host.contains(':') {
        true => format!("[{host}]:{port}"),
        false => format!("{host}:{port}"),
    }
}

/// A connection to the road's server: the one this process keeps, else a
/// new one, its `config` request made for `host:port`.
async fn connection(road: &Road, host: &str, port: u16, limit: Duration) -> Result<Shared, Failed> {
    let key = format!("{} {}", road.shown(), road.secret.user);
    let mut kept = kept().lock().await;
    kept.retain(|(_, handle)| !handle.is_closed());
    if let Some((_, handle)) = kept.iter().find(|(k, _)| *k == key) {
        return Ok(handle.clone());
    }
    let handle = Arc::new(connect(road, host, port, limit).await?);
    kept.push((key, handle.clone()));
    tokio::spawn(pings(Arc::downgrade(&handle)));
    Ok(handle)
}

/// The WebSocket, SSH inside it, the login and the `config` request.
async fn connect(road: &Road, host: &str, port: u16, limit: Duration) -> Result<Handle<Checker>, Failed> {
    let shown = road.shown();
    let dial =
        podssh_ws::chisel::Dial { trust: &road.trust, proxy: &podssh_ws::ProxyChoice::FromEnvironment, timeout: limit };
    let carried = podssh_ws::chisel::open(&road.server, &dial)
        .await
        .map_err(|e| Failed { line: e.line(&shown), code: super::reach::exit_code(&e) })?;
    let seen = Arc::new(StdMutex::new(None));
    let checker = Checker { want: road.secret.fingerprint.clone(), seen: seen.clone() };
    // No keepalive of russh's: chisel's server answers none, and its own
    // pings are sent here (`pings`).
    let config = Arc::new(Config {
        client_id: SshId::Standard(CLIENT_VERSION.into()),
        inactivity_timeout: None,
        keepalive_interval: None,
        ..Config::default()
    });
    let peer = podssh_ws::chisel::PEER;
    let handshake =
        tokio::time::timeout(limit, podssh_ssh::russh::client::connect_stream(config, carried.stream, checker)).await;
    let mut handle = match handshake {
        Err(_) => {
            return Err(Failed {
                line: format!("{peer} {shown}: no SSH within {} s of its 101", limit.as_secs()),
                code: EX_UNAVAILABLE,
            })
        }
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => return Err(handshake_failed(&shown, &road.secret.fingerprint, &seen, &e)),
    };
    let password = road.secret.password.as_str();
    let auth = tokio::time::timeout(limit, handle.authenticate_password(road.secret.user.clone(), password)).await;
    match auth {
        Ok(Ok(result)) if result.success() => {}
        Ok(Ok(_)) => {
            let line = match road.secret.user.is_empty() {
                true => format!(
                    "{peer} {shown} asks for a user and password: give auth USER:PASSWORD in --chisel-auth-file"
                ),
                false => format!("{peer} {shown} refused the user and password of --chisel-auth-file"),
            };
            return Err(Failed { line, code: EX_NOPERM });
        }
        Ok(Err(e)) => {
            return Err(Failed { line: format!("{peer} {shown}: the login failed: {e}"), code: EX_UNAVAILABLE })
        }
        Err(_) => {
            return Err(Failed {
                line: format!("{peer} {shown}: no login within {} s", limit.as_secs()),
                code: EX_UNAVAILABLE,
            })
        }
    }
    let answered =
        tokio::time::timeout(ANSWER_LIMIT, handle.send_global_request("config", &self::config(host, port), true)).await;
    match answered {
        Ok(Ok(_)) => Ok(handle),
        // The failure's words, which name the cause, are dropped by russh:
        // the server's log names it.
        Ok(Err(podssh_ssh::russh::Error::RequestDenied)) => Err(Failed {
            line: format!(
                "{peer} {shown} refused the tunnel to {}: its authfile does not let this user reach it, or the \
                 server takes no such remote (its log names which)",
                target(host, port)
            ),
            code: EX_NOPERM,
        }),
        Ok(Err(e)) => {
            Err(Failed { line: format!("{peer} {shown}: its configuration failed: {e}"), code: EX_UNAVAILABLE })
        }
        Err(_) => Err(Failed {
            line: format!("{peer} {shown}: no answer to its configuration within {} s", ANSWER_LIMIT.as_secs()),
            code: EX_UNAVAILABLE,
        }),
    }
}

/// The words of an SSH handshake that failed: a key whose fingerprint is
/// not the file's (77), else a server that spoke no SSH after its 101.
fn handshake_failed(
    shown: &str,
    want: &Option<String>,
    seen: &StdMutex<Option<String>>,
    e: &podssh_ssh::russh::Error,
) -> Failed {
    let peer = podssh_ws::chisel::PEER;
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match (want, seen) {
        (Some(want), Some(got)) if *want != got => Failed {
            line: format!(
                "{peer} {shown} showed the key {got}, not the fingerprint {want} of --chisel-auth-file: another \
                 server answered, or its key changed (chisel server prints its fingerprint at its start)"
            ),
            code: EX_NOPERM,
        },
        (_, None) => Failed {
            line: format!("{shown} answered the WebSocket, then spoke no chisel SSH: no chisel server ({e})"),
            code: EX_UNAVAILABLE,
        },
        _ => Failed { line: format!("{peer} {shown}: SSH failed: {e}"), code: EX_UNAVAILABLE },
    }
}

/// chisel's pings, each 25 s, while the connection lives; one that gets no
/// answer in time closes it, so that the next session opens a new one.
async fn pings(handle: std::sync::Weak<Handle<Checker>>) {
    loop {
        tokio::time::sleep(PING_EVERY).await;
        let Some(handle) = handle.upgrade() else { return };
        if handle.is_closed() {
            return;
        }
        // A failure is an answer too: chisel's server answers `pong`, and
        // an older one may answer no.
        let ping = tokio::time::timeout(ANSWER_LIMIT, handle.send_global_request("ping", &[], true)).await;
        if matches!(ping, Err(_) | Ok(Err(podssh_ssh::russh::Error::SendError | podssh_ssh::russh::Error::Disconnect)))
        {
            let _ = handle.disconnect(podssh_ssh::russh::Disconnect::ByApplication, "no answer to a ping", "").await;
            return;
        }
    }
}

/// A channel `chisel` to `host:port` through `road`: its stream, or why
/// not.
pub async fn open(
    road: &Road,
    host: &str,
    port: u16,
    limit: Duration,
) -> Result<podssh_ssh::russh::ChannelStream<podssh_ssh::russh::client::Msg>, Failed> {
    let handle = connection(road, host, port, limit).await?;
    let (shown, to) = (road.shown(), target(host, port));
    let peer = podssh_ws::chisel::PEER;
    let opened = tokio::time::timeout(limit, handle.channel_open_raw("chisel", to.as_bytes())).await;
    match opened {
        Ok(Ok(channel)) => Ok(channel.into_stream()),
        Ok(Err(podssh_ssh::russh::Error::ChannelOpenFailure(why))) => Err(match why {
            ChannelOpenFailure::AdministrativelyProhibited => Failed {
                line: format!("{peer} {shown} refused the tunnel to {to}: access denied (its authfile)"),
                code: EX_NOPERM,
            },
            ChannelOpenFailure::ConnectFailed => {
                Failed { line: format!("{peer} {shown} could not reach {to}"), code: EX_UNAVAILABLE }
            }
            ChannelOpenFailure::Other { reason, .. } => Failed {
                line: format!("{peer} {shown} refused the tunnel to {to}: {}", podssh_ws::text::one_line(&reason)),
                code: EX_UNAVAILABLE,
            },
            other => {
                Failed { line: format!("{peer} {shown} refused the tunnel to {to}: {other:?}"), code: EX_UNAVAILABLE }
            }
        }),
        Ok(Err(e)) => {
            Err(Failed { line: format!("{peer} {shown}: the tunnel to {to} failed: {e}"), code: EX_UNAVAILABLE })
        }
        Err(_) => Err(Failed {
            line: format!("{peer} {shown}: no tunnel to {to} within {} s", limit.as_secs()),
            code: EX_UNAVAILABLE,
        }),
    }
}
