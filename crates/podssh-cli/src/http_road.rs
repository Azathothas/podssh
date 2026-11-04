//! The HTTP road (T-319) of `podssh proxy` and `podssh ssh`: once each relay
//! host failed, and the way to one of them refused the WebSocket upgrade (a
//! proxy's page, or a `426` of a relay that got the request with its
//! `Upgrade` taken off, as the probe of the Piping Server road tells the
//! way's refusal from the relay's own word), the session runs over plain
//! requests of HTTPS to that host, which podssh's relay role serves (`podssh
//! relay serve`): the split form first, on two connections, then the serial
//! form on one (Q44). The token is the WebSocket road's, minted once more
//! when the role no longer takes a cached one. `PODSSH_HTTP_ROAD` turns the
//! road off, or names one form.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;

use podssh_relay::http_road::client::{self, End, Ended, Opened, Road, Target};
use podssh_relay::http_road::{Form, Tuning};
use podssh_relay::open::{Failure, OpenError};
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::token::{self, MintContext, Origin};
use podssh_ws::{ConnectError, ProxyChoice, Trust};

use crate::exitmap::sysexits::{EX_CONFIG, EX_UNAVAILABLE};
use crate::pipe::pump::{End as PipeEnd, Ending, Verdict};

/// The variable that turns the road off, or names one form.
pub const ENV: &str = "PODSSH_HTTP_ROAD";

/// What `PODSSH_HTTP_ROAD` asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    No,
    /// The split form, then the serial one: the default.
    Auto,
    Only(Form),
}

/// `PODSSH_HTTP_ROAD`: unset, empty, auto or yes, the default; no; split or
/// serial. Another word is a configuration error, whose words do not echo it.
pub fn asked(value: Option<&str>) -> Result<Asked, String> {
    let Some(value) = value else { return Ok(Asked::Auto) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" | "yes" => Ok(Asked::Auto),
        "no" | "off" | "0" => Ok(Asked::No),
        "split" => Ok(Asked::Only(Form::Split)),
        "serial" => Ok(Asked::Only(Form::Serial)),
        _ => Err(format!("{ENV}: auto, no, split or serial")),
    }
}

/// The first relay host of `relays` whose upgrade the way refused, by the
/// attempts of `failure`.
pub fn refused_at(failure: &Failure, relays: &RelayList) -> Option<Relay> {
    failure.attempts.iter().find_map(|(host, e)| match e {
        OpenError::Connect { error, .. } if podssh_relay::piping::probe::upgrade_refused(error) => {
            relays.hosts.iter().find(|relay| relay.host == *host).cloned()
        }
        _ => None,
    })
}

/// The line before the road.
fn announce(relay: &Relay) -> String {
    format!(
        "{}: the way refused the WebSocket upgrade; podssh tries its HTTP road there ({ENV}=no turns it off)",
        relay.host
    )
}

/// The road at `relay` to `target`, in `form`, or the split form, then the
/// serial one: a token as the WebSocket road gets one, then the open.
pub async fn open(relay: &Relay, trust: &Trust, target: Target<'_>, form: Option<Form>) -> Result<Opened, String> {
    let proxy = ProxyChoice::FromEnvironment;
    let limit = podssh_relay::open::CONNECT_TIMEOUT;
    let ctx = MintContext { relay, trust, proxy: &proxy, timeout: limit };
    let road = Road::tls(relay, trust, &proxy, limit);
    let mut token = token::obtain(&ctx, false).await.map_err(|e| e.to_string())?;
    let mut opened = client::open(&road, &target, token.secret(), form, Tuning::default()).await;
    // A cached token that the role no longer takes: minted once more, as
    // the WebSocket road does; never for a refusal by policy.
    let stale = matches!(&opened, Err(ConnectError::Refused { status: 403, body })
        if !podssh_relay::open::is_policy_refusal(body));
    if stale && token.origin == Origin::Cache {
        podssh_relay::cache::remove(&token::token_key(relay));
        token = token::obtain(&ctx, true).await.map_err(|e| e.to_string())?;
        opened = client::open(&road, &target, token.secret(), form, Tuning::default()).await;
    }
    drop(token);
    opened.map_err(|e| words(relay, &e))
}

/// What a failed open says: a relay with no such road is named so.
fn words(relay: &Relay, e: &ConnectError) -> String {
    match e {
        ConnectError::Refused { status: status @ (404 | 405), .. } => {
            format!("{} serves no HTTP road (it answered {status}); podssh relay serve serves one", relay.host)
        }
        e => e.to_string(),
    }
}

/// `podssh proxy`'s road after the relay hosts: the exit code of its
/// session, when the road opened, or of a setting that cannot be read;
/// else `None`, once its lines were said.
pub async fn after_relay_pipe(
    failure: &Failure,
    relays: &RelayList,
    trust: &Trust,
    (host, port): (&str, u16),
    err: &mut dyn Write,
) -> Option<i32> {
    let form = match asked(std::env::var(ENV).ok().as_deref()) {
        Ok(Asked::No) => return None,
        Ok(Asked::Auto) => None,
        Ok(Asked::Only(form)) => Some(form),
        Err(why) => {
            let _ = writeln!(err, "podssh: {why}");
            return Some(EX_CONFIG);
        }
    };
    let relay = refused_at(failure, relays)?;
    let _ = writeln!(err, "podssh: {}", announce(&relay));
    let target = podssh_ws::dial::authority(host, port);
    match open(&relay, trust, Target { host, port, family: None }, form).await {
        Ok(opened) => {
            crate::session_log::opened(Some(&relay.host));
            let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), pipe_end(opened, target)).await;
            crate::session_log::carried(pumped.carried.0, pumped.carried.1);
            Some(crate::pipe::report(pumped, "podssh", err).await)
        }
        Err(why) => {
            let _ = writeln!(err, "podssh: the HTTP road at {}: {why}", relay.host);
            None
        }
    }
}

/// `podssh ssh`'s road after the relay hosts: the session's stream, when
/// the road opened; `Err` for a setting that cannot be read.
pub async fn after_relay(
    failure: &Failure,
    relays: &RelayList,
    trust: &Trust,
    (host, port): (&str, u16),
    family: Option<u8>,
    log: &podssh_ssh::Log,
) -> Result<Option<Opened>, String> {
    let form = match asked(std::env::var(ENV).ok().as_deref())? {
        Asked::No => return Ok(None),
        Asked::Auto => None,
        Asked::Only(form) => Some(form),
    };
    let Some(relay) = refused_at(failure, relays) else { return Ok(None) };
    log.info(&announce(&relay));
    match open(&relay, trust, Target { host, port, family }, form).await {
        Ok(opened) => {
            let form = opened.form.name();
            log.verbose(&format!("the HTTP road at {} carries the session, in its {form} form", relay.host));
            podssh_ssh::outcome::relay_host(&relay.host);
            Ok(Some(opened))
        }
        Err(why) => {
            log.error(&format!("the HTTP road at {}: {why}", relay.host));
            Ok(None)
        }
    }
}

/// The pump's end of an open road to `target`: its bytes, then its end.
fn pipe_end(opened: Opened, target: String) -> PipeEnd {
    let Opened { stream, ended, .. } = opened;
    let (read, write) = tokio::io::split(stream);
    let ending: Box<dyn Ending> = Box::new(RoadEnding { ended, target });
    PipeEnd { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: Some(ending) }
}

struct RoadEnding {
    ended: Arc<Ended>,
    target: String,
}

impl Ending for RoadEnding {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let RoadEnding { ended, target } = *self;
            verdict(ended.get(), &target)
        })
    }
}

/// How a pipe of the road ended: the forward road's close, said as the
/// WebSocket road says it, and `1000` a clean end.
fn verdict(end: Option<End>, target: &str) -> Verdict {
    match end {
        None => None,
        Some(End::Closed { code, reason }) => {
            crate::session_log::closed(Some(code));
            if code == 1000 {
                return None;
            }
            let leg = podssh_ws::session::forward_close(Some(code), &reason);
            let mut lines = vec![format!("{}: {code} {reason}", leg.what(target))];
            lines.extend(leg.remedy(&reason).map(str::to_string));
            Some((EX_UNAVAILABLE, lines))
        }
        Some(End::Failed(why)) => Some((EX_UNAVAILABLE, vec![why])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_turns_the_road_off_or_names_a_form() {
        assert_eq!(asked(None), Ok(Asked::Auto));
        for auto in ["", "auto", "YES"] {
            assert_eq!(asked(Some(auto)), Ok(Asked::Auto), "{auto}");
        }
        assert_eq!(asked(Some("no")), Ok(Asked::No));
        assert_eq!(asked(Some("Split")), Ok(Asked::Only(Form::Split)));
        assert_eq!(asked(Some("serial")), Ok(Asked::Only(Form::Serial)));
        let refused = asked(Some("sometimes-secret")).unwrap_err();
        assert!(refused.starts_with("PODSSH_HTTP_ROAD: ") && !refused.contains("secret"), "{refused}");
    }

    /// The host whose upgrade a proxy refused is the road's; the relay's own
    /// refusal, and a host that was not reached, are not.
    #[test]
    fn the_road_goes_to_the_host_whose_upgrade_the_way_refused() {
        let relays = RelayList {
            hosts: vec![Relay { host: "a.test".into(), port: 443 }, Relay { host: "b.test".into(), port: 8443 }],
            explicit: true,
        };
        let refused = |status: u16, body: &str| OpenError::Connect {
            error: ConnectError::Refused { status, body: body.into() },
            origin: Origin::Minted,
        };
        let failure = Failure {
            attempts: vec![
                ("a.test".into(), refused(403, "forward: x:25 not in the ALLOW list")),
                ("b.test".into(), refused(403, "Forbidden: WebSocket upgrades are not allowed by policy")),
            ],
        };
        assert_eq!(refused_at(&failure, &relays), Some(Relay { host: "b.test".into(), port: 8443 }));
        let own = Failure { attempts: vec![("a.test".into(), refused(403, "forward: missing or wrong token"))] };
        assert_eq!(refused_at(&own, &relays), None);
        let silent = Failure { attempts: vec![("a.test".into(), OpenError::Deadline)] };
        assert_eq!(refused_at(&silent, &relays), None);
    }

    #[test]
    fn a_close_of_the_road_is_said_as_the_websocket_road_says_it() {
        let closed = |code, reason: &str| Some(End::Closed { code, reason: reason.into() });
        assert_eq!(verdict(None, "h:22"), None);
        assert_eq!(verdict(closed(1000, "target closed"), "h:22"), None);
        let (code, lines) = verdict(closed(1001, "idle timeout"), "h:22").expect("a verdict");
        assert_eq!(code, EX_UNAVAILABLE);
        assert!(lines[0].ends_with(": 1001 idle timeout"), "{lines:?}");
        let failed = verdict(Some(End::Failed("no answer".into())), "h:22");
        assert_eq!(failed, Some((EX_UNAVAILABLE, vec!["no answer".to_string()])));
        let relay = Relay { host: "relay.test".into(), port: 443 };
        let none = words(&relay, &ConnectError::Refused { status: 404, body: "not found".into() });
        assert!(none.contains("serves no HTTP road") && none.contains("404"), "{none}");
    }
}
