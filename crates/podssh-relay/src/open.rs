//! Opening a forward session through the relay, with failover.
//!
//! The hosts of a [`RelayList`] are tried in the order of the list, as the
//! mode of [`crate::failover`] says: by default the next host starts when the
//! one before it has not opened within 2 s. Each host has one attempt bounded
//! by [`HOST_DEADLINE`]: a token from the environment, the cache or a fresh
//! mint (re-minted once when the relay rejects a cached one), then the
//! WebSocket upgrade. A failure that another host might not share (a dead
//! host, a proxy that refuses or cannot reach one name, a relay error) moves
//! on to the next host; one that every host would repeat (a policy refusal, a
//! target name that does not resolve, a bad token in the environment) stops at
//! once. Whole rounds repeat `rounds` times with jittered exponential backoff.
//! Shared by `podssh proxy` and `podssh ssh`, which differ only in how they
//! report a failure.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::{connect, ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use rand::Rng;

use crate::failover::{self, Attempt, MintGate, Mode, SERIAL_STEP, STAGGER};
use crate::failures::{self, Records};
use crate::relay::{Relay, RelayList};
use crate::token::{self, MintContext, Origin, TokenError};

/// Bound on each step of reaching a relay host: proxy and TCP, TLS, upgrade,
/// and each minting request.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on one whole host attempt, minting included, so a host that answers
/// slowly at every step still hands over to the next one.
pub const HOST_DEADLINE: Duration = Duration::from_secs(45);

/// Environment variable that forbids every network connection. Test suites
/// set it for the binaries they run, so no test can reach the relay by
/// accident; it is not meant for users.
pub const OFFLINE_ENV: &str = "PODSSH_OFFLINE";

/// Whether [`OFFLINE_ENV`] is set (to anything but empty or `0`).
pub fn offline() -> bool {
    std::env::var(OFFLINE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Why one host attempt failed.
#[derive(Debug)]
pub enum OpenError {
    /// [`OFFLINE_ENV`] is set.
    Offline,
    Token(TokenError),
    Connect {
        error: ConnectError,
        origin: Origin,
    },
    /// The attempt ran past [`HOST_DEADLINE`].
    Deadline,
}

impl OpenError {
    /// Whether another relay host could succeed where this one failed.
    pub fn another_host_may_help(&self) -> bool {
        match self {
            OpenError::Offline => false,
            OpenError::Deadline => true,
            OpenError::Token(TokenError::BadEnvironment | TokenError::NotIssued) => false,
            OpenError::Token(_) => true,
            OpenError::Connect { error, .. } => match error {
                ConnectError::Config(_) => false,
                ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => false,
                // The proxy wants credentials: the same for every host.
                ConnectError::Dial(DialError::ProxyRefused { status: 407, .. }) => false,
                ConnectError::Dial(_)
                | ConnectError::Tls(_)
                | ConnectError::Timeout { .. }
                | ConnectError::Upgrade(_)
                | ConnectError::Http(_) => true,
                // Policy, or a token rejected even fresh: every host agrees.
                ConnectError::Refused { status: 400 | 401 | 403, .. } => false,
                ConnectError::Refused { status: 502, body } => !target_name_fails(body),
                ConnectError::Refused { .. } => true,
            },
        }
    }

    /// What to print, one message per line, without a `podssh:` prefix.
    /// `target` is the `host:port` the session was for.
    pub fn lines(&self, target: &str) -> Vec<String> {
        match self {
            OpenError::Offline => vec![format!("{OFFLINE_ENV} is set, so podssh does not connect anywhere")],
            OpenError::Deadline => {
                vec![format!("the relay host did not answer within {} s", HOST_DEADLINE.as_secs())]
            }
            OpenError::Token(e) => vec![e.to_string()],
            OpenError::Connect { error, origin } => {
                let mut lines = vec![error.to_string()];
                let hint = match error {
                    ConnectError::Refused { status: 400 | 403, body } if is_policy_refusal(body) => {
                        Some(format!("the relay's policy does not allow {target}"))
                    }
                    ConnectError::Refused { status: 403, .. } if *origin == Origin::Environment => {
                        Some(format!("the token in {} was rejected", token::TOKEN_ENV))
                    }
                    ConnectError::Refused { status: 502, .. } => Some(format!("the relay could not reach {target}")),
                    ConnectError::Dial(DialError::ProxyRefused { status, .. }) if *status >= 500 => Some(format!(
                        "the proxy could not reach the relay (it answered {status}); another relay host may \
                         work: --relay-host or PODSSH_RELAY"
                    )),
                    ConnectError::Dial(DialError::ProxyRefused { .. }) => {
                        Some("the proxy does not allow connections to the relay".to_string())
                    }
                    _ => None,
                };
                lines.extend(hint);
                lines
            }
        }
    }
}

/// The relay's wording for a policy refusal (spec: "not in the ALLOW list"),
/// defined once in `podssh-ws`.
pub use podssh_ws::client::is_policy_refusal;

/// Whether `e` came once a connection to the host had opened, and is no
/// answer of the relay's own (a rate, a relay that issues no token): then
/// the server at that address may be another's.
fn after_connection(e: &OpenError) -> bool {
    let opened = |c: &ConnectError| !matches!(c, ConnectError::Dial(_) | ConnectError::Config(_));
    match e {
        OpenError::Connect { error, .. } | OpenError::Token(TokenError::Connect(error)) => opened(error),
        OpenError::Token(TokenError::Failed { .. }) => true,
        _ => false,
    }
}

/// A `502` whose reason is the target's name or address, which no other host
/// will resolve differently.
fn target_name_fails(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("does not resolve")
        || body.contains("no aaaa address")
        || body.contains("no a address")
        || is_policy_refusal(&body)
}

/// What to open.
pub struct Request<'a> {
    pub relays: &'a RelayList,
    /// `/connect/<host>/<port>`, with the relay's connect knobs if any.
    pub path: &'a str,
    pub trust: &'a Trust,
    /// `host:port`, for messages.
    pub target: &'a str,
    /// Rounds over the whole list (`ConnectionAttempts`); at least one.
    pub rounds: u32,
    /// How the hosts of a round are tried (T-220).
    pub failover: Mode,
}

/// An open session and the host that gave it.
#[derive(Debug)]
pub struct Opened {
    pub session: RelaySession,
    pub relay: Relay,
}

/// Every attempt that failed, in order, as (host, error).
#[derive(Debug)]
pub struct Failure {
    pub attempts: Vec<(String, OpenError)>,
}

impl Failure {
    /// The error the run is classified by: the last one, which stopped it.
    pub fn last(&self) -> &OpenError {
        &self.attempts.last().expect("a failure has at least one attempt").1
    }

    /// What to print. One host: its lines. Several: one line per host, then
    /// the last error's hints.
    pub fn lines(&self, target: &str) -> Vec<String> {
        if self.attempts.len() == 1 {
            return self.attempts[0].1.lines(target);
        }
        let mut out: Vec<String> = self
            .attempts
            .iter()
            .map(|(host, e)| format!("{host}: {}", e.lines(target).first().cloned().unwrap_or_default()))
            .collect();
        out.extend(self.last().lines(target).into_iter().skip(1));
        out
    }
}

/// Open a forward session, failing over across `req.relays` as
/// `req.failover` says. `notes` receives progress worth a user's attention (a
/// host failing, a retry, a token that could not be cached), each host's in
/// the order of the list.
pub async fn open(req: &Request<'_>, notes: &mut dyn FnMut(&str)) -> Result<Opened, Failure> {
    let mut attempts: Vec<(String, OpenError)> = Vec::new();
    if offline() {
        return Err(Failure { attempts: vec![(req.relays.primary().host.clone(), OpenError::Offline)] });
    }
    // The addresses that carried a session, for a resolver that fails (T-344).
    crate::addresses::install();
    // A host that failed lately goes last (T-059).
    let mut records = Records::load();
    let (order, moved) = failures::order(&req.relays.hosts, &records, crate::pool::now_ms());
    for note in moved {
        notes(&note);
    }
    let hosts: &Vec<Relay> = &order.iter().map(|&i| req.relays.hosts[i].clone()).collect();
    let shared = Arc::new(Shared {
        path: req.path.to_string(),
        trust: req.trust.clone(),
        target: req.target.to_string(),
        primary: req.relays.primary().host.clone(),
        explicit: req.relays.explicit,
        several: hosts.len() > 1,
    });
    let gate = MintGate::default();
    let rounds = req.rounds.max(1);
    for round in 1..=rounds {
        if round > 1 {
            let wait = backoff(round - 1);
            notes(&format!("retrying in {:.1} s (round {round} of {rounds})", wait.as_secs_f32()));
            tokio::time::sleep(wait).await;
        }
        let start = |i: usize| {
            // In `serial`, a host with a successor has a short step.
            let last = i + 1 == hosts.len();
            let step = if req.failover == Mode::Serial && !last { SERIAL_STEP } else { CONNECT_TIMEOUT };
            attempt(hosts[i].clone(), shared.clone(), gate.clone(), step)
        };
        let stops = |e: &OpenError| !e.another_host_may_help();
        let raced = failover::race(hosts.len(), req.failover, start, stops, notes).await;
        // A session that is not kept is closed at once, so that the relay
        // frees the socket of its target.
        for (_, session) in raced.dismissed {
            tokio::spawn(async move {
                let _ = session.send_close(1000, "").await;
            });
        }
        let reasons = raced.failed.iter().filter_map(|(i, e)| failures::reason(e).map(|r| (hosts[*i].host.clone(), r)));
        let silent = raced.silent.iter().map(|i| (hosts[*i].host.clone(), failures::SILENT.to_string()));
        let failed: Vec<(String, String)> = reasons.chain(silent).collect();
        let opened = raced.kept.as_ref().map(|(i, _)| hosts[*i].host.as_str());
        if records.update(&failed, opened, crate::pool::now_ms()) {
            records.store();
        }
        // A host that failed after its connection opened, as the relay itself
        // would not (TLS, the upgrade, another's refusal): an address of the
        // cache that it was reached at is not the relay's (T-344).
        for (i, e) in &raced.failed {
            if failures::reason(e).is_some() && after_connection(e) {
                crate::addresses::failed(&hosts[*i].host);
            }
        }
        attempts.extend(raced.failed.into_iter().map(|(i, e)| (hosts[i].host.clone(), e)));
        if let Some((i, session)) = raced.kept {
            // The address that carried it, for a run whose resolver fails.
            crate::addresses::carried(&hosts[i].host, session.peer());
            // The relay's own limits, as its pool's cache keeps them: the
            // run's budgets go under them, and the session takes in frames
            // up to its cap (T-342).
            let limits = crate::pool::cached_limits(&shared.primary);
            crate::pool::set_in_use(limits);
            session.set_receive_cap(podssh_ws::frame::receive_cap(limits.max_frame_bytes));
            return Ok(Opened { session, relay: hosts[i].clone() });
        }
        if raced.stopped {
            break;
        }
    }
    Err(Failure { attempts })
}

/// What the attempts of one run share.
struct Shared {
    path: String,
    trust: Trust,
    /// `host:port`, for messages.
    target: String,
    /// The first host: the key of the cached pool.
    primary: String,
    /// Whether the user named the hosts.
    explicit: bool,
    /// Whether there is more than one host, so that a failure names its own.
    several: bool,
}

/// One host within [`HOST_DEADLINE`], each step within `step`, with its
/// notes: a host that fails names itself when there are others.
async fn attempt(
    relay: Relay,
    shared: Arc<Shared>,
    gate: MintGate,
    step: Duration,
) -> Attempt<RelaySession, OpenError> {
    let mut notes = Vec::new();
    let result = tokio::time::timeout(HOST_DEADLINE, try_host(&relay, &shared, &gate, step, &mut notes))
        .await
        .unwrap_or(Err(OpenError::Deadline));
    if let Err(e) = &result {
        if e.another_host_may_help() && shared.several {
            notes.push(format!("{}: {}", relay.host, e.lines(&shared.target).first().cloned().unwrap_or_default()));
        }
    }
    Attempt { result, notes }
}

/// One host: a token, then the upgrade. A token is read or minted in the
/// turn of its deployment ([`MintGate`]): of two attempts, the second reads
/// the token that the first cached, or mints at its own host when the first
/// is still silent after [`STAGGER`].
async fn try_host(
    relay: &Relay,
    shared: &Shared,
    gate: &MintGate,
    step: Duration,
    notes: &mut Vec<String>,
) -> Result<RelaySession, OpenError> {
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = MintContext { relay, trust: &shared.trust, proxy: &proxy, timeout: step };
    let key = token::token_key(relay);
    let mut token = {
        let _turn = gate.hold(&key, STAGGER).await;
        token::obtain(&ctx, false).await.map_err(OpenError::Token)?
    };
    if let Some(why) = token.cache_warning.take() {
        notes.push(format!("the relay token could not be cached, so one is minted per run: {why}"));
    }
    if let Some(note) = token.cache_note.take() {
        notes.push(note);
    }
    if token.origin == Origin::Minted && !shared.explicit {
        spawn_pool_refresh(relay.clone(), shared.primary.clone(), shared.trust.clone());
    }
    let config = WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path: shared.path.clone() },
        trust: shared.trust.clone(),
        server_name: relay.host.clone(),
        timeout: step,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: proxy.clone(),
    };
    let mut result = connect(&config, token.secret()).await;
    // A cached token the relay no longer accepts: forget it and mint once.
    // Not for a policy refusal, which a new token cannot fix.
    if let Err(ConnectError::Refused { status: 403, body }) = &result {
        if token.origin == Origin::Cache && !is_policy_refusal(body) {
            crate::cache::remove(&key);
            token = {
                let _turn = gate.hold(&key, STAGGER).await;
                token::obtain(&ctx, true).await.map_err(OpenError::Token)?
            };
            result = connect(&config, token.secret()).await;
        }
    }
    let origin = token.origin;
    drop(token);
    result.map_err(|error| OpenError::Connect { error, origin })
}

/// Refresh the cached pool in the background after a mint: a stale or missing
/// pool only means fewer alternates, so failure is silent and the session
/// never waits for it.
fn spawn_pool_refresh(relay: Relay, primary: String, trust: Trust) {
    if !crate::pool::needs_refresh(&primary, crate::pool::now_ms()) {
        return;
    }
    tokio::spawn(async move {
        let proxy = ProxyChoice::FromEnvironment;
        let _ = crate::pool::refresh(&relay, &primary, &trust, &proxy, CONNECT_TIMEOUT).await;
    });
}

/// The first wait between rounds, before the random factor.
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);

/// The longest wait between rounds, before the random factor.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// 1 s, 2 s, 4 s … capped at 30 s, each scaled by a random factor in
/// [0.5, 1.5) so many clients retrying at once do not stay in step.
pub fn backoff(retry: u32) -> Duration {
    let first = BACKOFF_FIRST.as_millis() as u64;
    let max = BACKOFF_MAX.as_millis() as u64;
    let base = first.saturating_mul(1u64 << retry.saturating_sub(1).min(5)).min(max);
    let factor: f64 = rand::thread_rng().gen_range(0.5..1.5);
    Duration::from_millis((base as f64 * factor) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(status: u16, body: &str) -> OpenError {
        OpenError::Connect { error: ConnectError::Refused { status, body: body.into() }, origin: Origin::Minted }
    }

    #[test]
    fn errors_every_host_would_repeat_stop_the_failover() {
        assert!(!OpenError::Offline.another_host_may_help());
        assert!(!OpenError::Token(TokenError::BadEnvironment).another_host_may_help());
        assert!(!refused(403, "forward: github.com:25 not in the ALLOW list").another_host_may_help());
        assert!(!refused(400, "blocked address range").another_host_may_help());
        assert!(!refused(502, "relay: cannot reach x:22 — no AAAA address for x").another_host_may_help());
        assert!(!refused(502, "relay: nope.invalid does not resolve").another_host_may_help());
    }

    #[test]
    fn errors_of_one_host_move_to_the_next() {
        assert!(OpenError::Deadline.another_host_may_help());
        assert!(refused(503, "paused").another_host_may_help());
        assert!(refused(429, "slow down").another_host_may_help());
        assert!(refused(502, "relay: connect failed: timed out").another_host_may_help());
        let proxy_504 = OpenError::Connect {
            error: ConnectError::Dial(DialError::ProxyRefused {
                proxy: "proxy:3128".into(),
                target: "relay:443".into(),
                status: 504,
                reason: "Gateway Timeout".into(),
            }),
            origin: Origin::Cache,
        };
        assert!(proxy_504.another_host_may_help());
        assert!(proxy_504.lines("h:22").iter().any(|l| l.contains("another relay host")));
    }

    /// A host that failed once its connection opened, as no relay would, is
    /// told from one whose connection never opened, and from the relay's own
    /// refusals, which keep the address of the cache (T-344).
    #[test]
    fn a_failure_after_the_connection_is_told_from_the_others() {
        let connect = |error| OpenError::Connect { error, origin: Origin::Minted };
        assert!(after_connection(&connect(ConnectError::Tls("NotValidForName".into()))));
        assert!(after_connection(&refused(530, "error code: 1034")));
        assert!(after_connection(&OpenError::Token(TokenError::Failed { status: 409, detail: String::new() })));
        let unreachable = DialError::Connect { target: "relay:443".into(), detail: "refused".into() };
        assert!(!after_connection(&connect(ConnectError::Dial(unreachable.clone()))));
        assert!(!after_connection(&OpenError::Token(TokenError::Connect(ConnectError::Dial(unreachable)))));
        assert!(!after_connection(&OpenError::Token(TokenError::RateLimited { retry_after: None })));
        assert!(!after_connection(&OpenError::Deadline));
        assert!(failures::reason(&refused(403, "not in the ALLOW list")).is_none());
        assert!(failures::reason(&refused(502, "connect failed")).is_none());
    }

    #[test]
    fn backoff_grows_is_capped_and_jittered() {
        for _ in 0..50 {
            let first = backoff(1).as_millis();
            assert!((500..1500).contains(&first), "{first}");
            let late = backoff(20).as_millis();
            assert!((15_000..45_000).contains(&late), "{late}");
        }
    }

    #[test]
    fn a_failure_over_several_hosts_names_each_and_keeps_the_hints() {
        let f = Failure {
            attempts: vec![
                ("a.example".into(), OpenError::Deadline),
                ("b.example".into(), refused(403, "forward: x:25 not in the ALLOW list")),
            ],
        };
        let lines = f.lines("x:25");
        assert!(lines[0].starts_with("a.example: "), "{lines:?}");
        assert!(lines[1].starts_with("b.example: "), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("policy does not allow x:25")), "{lines:?}");
    }
}
