//! The relay leg of `podssh ping` (T-053): for one relay host, the time of
//! each step as `podssh ssh` takes them one after the other (a token, TCP or
//! CONNECT through the proxy, TLS, the WebSocket upgrade, which the relay
//! answers once it reached the target), then WebSocket pings, each carrying
//! its own send time and matched to its pong. The target is `--target`, or
//! `podssh doctor`'s reference, GitHub's SSH port; never the destination,
//! which would see a connection that sends no SSH bytes, and OpenSSH's
//! PerSourcePenalties count that against the relay's shared address.

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::relay::Relay;
use podssh_relay::token::{self, MintContext, Origin};
use podssh_ws::{ConnectError, ProxyChoice, RelaySession, Trust};

use super::stats::Summary;

/// The limit on each step, as the relay's own opening has.
const STEP: Duration = Duration::from_secs(20);
/// How long a ping waits for its pong.
const PING_WAIT: Duration = Duration::from_secs(5);
/// The target with no destination: GitHub's SSH port, which the relay
/// allows and `podssh doctor` reaches too.
pub const REFERENCE: (&str, u16) = ("github.com", 22);

/// What one relay host measured.
#[derive(Debug, Default)]
pub struct Leg {
    pub host: String,
    pub target: String,
    /// Where the token came from, and how long it took (a mint is an HTTPS
    /// request of its own).
    pub token: Option<(&'static str, Duration)>,
    /// `DNS and TCP`, or `CONNECT through PROXY`, and how long it took.
    pub connect: Option<(String, Duration)>,
    pub tls: Option<Duration>,
    pub upgrade: Option<Duration>,
    pub pings: Vec<Duration>,
    /// Pings with no pong within [`PING_WAIT`].
    pub lost: usize,
    pub failed: Option<String>,
}

impl Leg {
    pub fn line(&self) -> String {
        let ms = |d: &Duration| format!("{:.0} ms", d.as_secs_f64() * 1000.0);
        let mut steps = Vec::new();
        if let Some((origin, took)) = &self.token {
            steps.push(format!("token {origin} {}", ms(took)));
        }
        if let Some((how, took)) = &self.connect {
            steps.push(format!("{how} {}", ms(took)));
        }
        if let Some(took) = &self.tls {
            steps.push(format!("TLS {}", ms(took)));
        }
        if let Some(took) = &self.upgrade {
            steps.push(format!("upgrade to {} {}", self.target, ms(took)));
        }
        let mut line = format!("relay {}: {}", self.host, steps.join(", "));
        if let Some(summary) = Summary::of(&self.pings) {
            let lost = if self.lost > 0 { format!(" ({} lost)", self.lost) } else { String::new() };
            line.push_str(&format!("; {} pings: {}{lost}", self.pings.len(), summary.shown()));
        }
        if let Some(why) = &self.failed {
            line.push_str(&format!("; {why}"));
        }
        line
    }

    pub fn json(&self) -> serde_json::Value {
        let ms = |d: &Duration| (d.as_secs_f64() * 1_000_000.0).round() / 1000.0;
        serde_json::json!({
            "host": self.host,
            "target": self.target,
            "token": self.token.as_ref().map(|(origin, _)| origin),
            "token_ms": self.token.as_ref().map(|(_, d)| ms(d)),
            "connect": self.connect.as_ref().map(|(how, _)| how),
            "connect_ms": self.connect.as_ref().map(|(_, d)| ms(d)),
            "tls_ms": self.tls.as_ref().map(ms),
            "upgrade_ms": self.upgrade.as_ref().map(ms),
            "pings": Summary::of(&self.pings).map(|s| s.json()),
            "pings_lost": self.lost,
            "error": self.failed,
        })
    }
}

/// The trust for the relay: `--ca-file`, else `SSL_CERT_FILE`, else the
/// system's and the built-in roots.
pub fn trust(ca_file: Option<&str>) -> Trust {
    let file = crate::settings::ca_file(ca_file);
    match file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    }
}

/// Measure `relay` with `count` pings, on a session to `target` that the
/// relay dials in `family` when one is given.
pub async fn leg(relay: &Relay, trust: &Trust, target: (&str, u16), family: Option<u8>, count: usize) -> Leg {
    let mut leg = Leg {
        host: podssh_ws::dial::authority(&relay.host, relay.port),
        target: podssh_ws::dial::authority(target.0, target.1),
        ..Leg::default()
    };
    let path = match podssh_relay::relay::forward_path(target.0, target.1) {
        Ok(path) => match family {
            Some(f) => format!("{path}?family={f}"),
            None => path,
        },
        Err(why) => {
            leg.failed = Some(why);
            return leg;
        }
    };
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = MintContext { relay, trust, proxy: &proxy, timeout: STEP };
    let mut fresh = false;
    let session = loop {
        let started = Instant::now();
        let token = match token::obtain(&ctx, fresh).await {
            Ok(token) => token,
            Err(e) => {
                leg.failed = Some(format!("the relay token: {e}"));
                return leg;
            }
        };
        leg.token = Some((origin(token.origin), started.elapsed()));
        match open(&mut leg, relay, trust, &path, token.secret()).await {
            Ok(session) => break session,
            // A cached token that the relay no longer takes: once, a new one.
            Err(ConnectError::Refused { status: 403, .. }) if token.origin == Origin::Cache && !fresh => {
                podssh_relay::cache::remove(&token::token_key(relay));
                fresh = true;
            }
            Err(e) => {
                leg.failed = Some(e.to_string());
                return leg;
            }
        }
    };
    pings(&mut leg, Arc::new(session), count).await;
    leg
}

fn origin(origin: Origin) -> &'static str {
    match origin {
        Origin::Environment => "from PODSSH_RELAY_TOKEN",
        Origin::Cache => "cached",
        Origin::Minted => "minted",
    }
}

/// TCP or CONNECT, TLS and the upgrade, each timed into `leg`.
async fn open(
    leg: &mut Leg,
    relay: &Relay,
    trust: &Trust,
    path: &str,
    token: &str,
) -> Result<RelaySession, ConnectError> {
    let how = match podssh_ws::dial::proxy_from_env(&relay.host) {
        Ok(Some(proxy)) => {
            format!("{} through {}", proxy.kind.request(), podssh_ws::dial::authority(&proxy.host, proxy.port))
        }
        _ => "DNS and TCP".to_string(),
    };
    let started = Instant::now();
    let tcp = podssh_ws::dial::dial(&relay.host, relay.port, &ProxyChoice::FromEnvironment, STEP)
        .await
        .map_err(|e| ConnectError::Upgrade(format!("{how}: {e}")))?;
    leg.connect = Some((how, started.elapsed()));
    let started = Instant::now();
    let tls = podssh_ws::tls::connect_over(tcp, &relay.host, trust, STEP).await.map_err(ConnectError::Tls)?;
    leg.tls = Some(started.elapsed());
    let started = Instant::now();
    let host_header = podssh_ws::dial::authority(&relay.host, relay.port);
    let (tls, pending) = tokio::time::timeout(STEP, podssh_ws::client::upgrade(tls, &host_header, path, token))
        .await
        .map_err(|_| ConnectError::Timeout { step: "the WebSocket upgrade", after: STEP })??;
    leg.upgrade = Some(started.elapsed());
    Ok(RelaySession::new(tls, pending, Some(podssh_ws::DEFAULT_IDLE_TIMEOUT), podssh_ws::client::WRITE_TIMEOUT))
}

/// `count` pings, each with its sequence and its send time (nanoseconds
/// since the first) in its payload, matched to its pong.
async fn pings(leg: &mut Leg, session: Arc<RelaySession>, count: usize) {
    let reading = session.clone();
    // Frames must be read for pongs to be heard; the target's bytes go.
    let reader = tokio::spawn(async move { while reading.read_frame().await.is_ok() {} });
    let start = Instant::now();
    for seq in 0..count as u32 {
        let sent = start.elapsed();
        let mut payload = b"podssh-ping".to_vec();
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&(sent.as_nanos() as u64).to_be_bytes());
        if let Err(e) = session.send_ping(&payload).await {
            leg.failed = Some(format!("a ping could not be sent: {e}"));
            break;
        }
        let deadline = tokio::time::Instant::now() + PING_WAIT;
        loop {
            if let Some((_, at)) = session.take_pongs().into_iter().find(|(p, _)| *p == payload) {
                leg.pings.push(at.saturating_duration_since(start + sent));
                break;
            }
            if tokio::time::timeout_at(deadline, session.pong_arrived()).await.is_err() {
                leg.lost += 1;
                break;
            }
        }
    }
    if leg.pings.is_empty() && leg.failed.is_none() {
        leg.failed = Some(format!("no pong within {} s for any of the {count} pings", PING_WAIT.as_secs()));
    }
    let _ = session.send_close(1000, "").await;
    reader.abort();
}
