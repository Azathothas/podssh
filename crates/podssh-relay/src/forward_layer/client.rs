//! The links of one session of the forward road with the layer (T-173): each
//! a WebSocket to `/v1/layer/HOST/PORT` of the one relay host that holds the
//! session, with a token from the environment, the cache or a mint, as each
//! forward session gets one (`crate::open`), and the session across them.
//!
//! A resume must reach the process that holds the target's connection, so
//! no other host of a list is tried: a host that cannot be reached is tried
//! again with the layer's backoff, until the far end's deadline. A refusal
//! that a new link would only get again (the token, the policy, a host that
//! no longer serves the path) ends the session with its words. Where the
//! host's offer names the process that answered, each link goes to that
//! name, the first too ([`super::offer`]).
//!
//! A host with no room for a new session refuses it in the first link's
//! handshake, before any byte of the session went ([`no_room`]): its client
//! takes the contract's road then.

use podssh_ws::{ConnectError, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::offer::Offer;
use crate::failover::Mode;
use crate::open::{self, Failure, OpenError, Request};
use crate::relay::{Relay, RelayList};
use crate::session::client::{Client, ClientError, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ended, HandshakeError, OsEntropy, RefuseCode};
use crate::transit::link::Link;

/// Who a link's failure names.
const WHO: &str = "the relay";

/// How the links of a session reach their host.
enum Way {
    /// TLS, through the proxy when one is set, by the forward opener.
    Tls(Trust),
    /// Plain `ws://` to a relay role on the loopback, with this token, for
    /// tests: a token over plain TCP never leaves the host
    /// (`podssh_ws::plain`). The binary never enables it.
    #[cfg(feature = "plain-ws")]
    PlainLoopback(String),
}

/// The links of one session to one host.
pub struct Dialer {
    /// The one host, as a list that the user named: the opener tries it
    /// alone.
    relays: RelayList,
    path: String,
    /// `host:port`, for messages.
    target: String,
    way: Way,
}

/// Why a link did not open.
#[derive(Debug)]
pub enum Missed {
    /// The forward opener's failure, with each attempt.
    Open(Failure),
    /// The plain upgrade's failure, on the loopback.
    #[cfg(feature = "plain-ws")]
    Plain(ConnectError),
}

/// A refusal that a new link of the same host gets again.
fn refused_for_good(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Refused { status: 401 | 403 | 404 | 410, .. })
}

/// The words of a host that had no room for a new session: its `REFUSE`
/// (busy) in the first link's handshake, which came before this side sent a
/// byte of the session, so the session can go on the contract's road.
pub fn no_room(e: &ClientError) -> Option<&str> {
    match e {
        ClientError::Handshake(HandshakeError::Refused { code: RefuseCode::BUSY, reason }) => Some(reason),
        _ => None,
    }
}

impl Missed {
    /// Whether a new link would only get the same: a refusal of the token,
    /// of the policy, or of the path, and each failure that the opener
    /// would not try at another host either (`OFFLINE`, a bad proxy).
    pub fn is_final(&self) -> bool {
        match self {
            Missed::Open(failure) => match failure.last() {
                OpenError::Connect { error, .. } if refused_for_good(error) => true,
                other => !other.another_host_may_help(),
            },
            #[cfg(feature = "plain-ws")]
            Missed::Plain(e) => refused_for_good(e),
        }
    }

    /// What to print, one line each, with no `podssh:` prefix.
    pub fn lines(&self, target: &str) -> Vec<String> {
        match self {
            Missed::Open(failure) => failure.lines(target),
            #[cfg(feature = "plain-ws")]
            Missed::Plain(e) => vec![e.to_string()],
        }
    }

    /// The opener's failure, for the exit code of a command.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Missed::Open(failure) => Some(failure),
            #[cfg(feature = "plain-ws")]
            Missed::Plain(_) => None,
        }
    }
}

impl Dialer {
    /// The links of a session to `host:port` through `relay`, over TLS with
    /// `trust`; `Err` for a target that no path can name.
    pub fn new(relay: Relay, host: &str, port: u16, trust: Trust) -> Result<Dialer, String> {
        Dialer::with(relay, host, port, Way::Tls(trust))
    }

    /// The links of a session to `host:port` at the host that holds them,
    /// as `offer`, the `/relays.json` of `asked`, names it: the process that
    /// answered, where it named itself, else `asked`.
    pub fn for_offer(asked: &Relay, offer: &Offer, host: &str, port: u16, trust: Trust) -> Result<Dialer, String> {
        Dialer::new(offer.holder(asked), host, port, trust)
    }

    /// The same over plain `ws://` to a role on the loopback, with `token`.
    #[cfg(feature = "plain-ws")]
    pub fn on_loopback(relay: Relay, host: &str, port: u16, token: &str) -> Result<Dialer, String> {
        Dialer::with(relay, host, port, Way::PlainLoopback(token.to_string()))
    }

    /// [`Dialer::for_offer`] over plain `ws://` on the loopback.
    #[cfg(feature = "plain-ws")]
    pub fn on_loopback_for(asked: &Relay, offer: &Offer, host: &str, port: u16, token: &str) -> Result<Dialer, String> {
        Dialer::on_loopback(offer.holder(asked), host, port, token)
    }

    fn with(relay: Relay, host: &str, port: u16, way: Way) -> Result<Dialer, String> {
        let path = super::path(host, port)?;
        let target = podssh_ws::dial::authority(host, port);
        Ok(Dialer { relays: RelayList { hosts: vec![relay], explicit: true }, path, target, way })
    }

    /// Each link asks for the addresses of `family` alone (4 or 6), as the
    /// forward path's `?family` does for `-4` and `-6`.
    pub fn with_family(mut self, family: Option<u8>) -> Dialer {
        if let Some(family) = family {
            self.path.push_str(&format!("?family={family}"));
        }
        self
    }

    /// The host that holds the session.
    pub fn relay(&self) -> &Relay {
        self.relays.primary()
    }

    /// The path of each link.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port` of the target.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// A new link to the host, nothing read from it yet; `notes` hears what
    /// the opener says on the way (a token that could not be cached).
    pub async fn link(&self, notes: &mut dyn FnMut(&str)) -> Result<Link, Missed> {
        match &self.way {
            Way::Tls(trust) => {
                let request = Request {
                    relays: &self.relays,
                    path: &self.path,
                    trust,
                    target: &self.target,
                    rounds: 1,
                    failover: Mode::default(),
                };
                let opened = open::open(&request, notes).await.map_err(Missed::Open)?;
                Ok(Link::start_by(opened.session, Vec::new(), WHO))
            }
            #[cfg(feature = "plain-ws")]
            Way::PlainLoopback(token) => {
                let relay = self.relays.primary();
                let idle = Some(podssh_ws::DEFAULT_IDLE_TIMEOUT);
                let limit = open::CONNECT_TIMEOUT;
                let session =
                    podssh_ws::plain::connect_loopback(&relay.host, relay.port, &self.path, token, limit, idle)
                        .await
                        .map_err(Missed::Plain)?;
                Ok(Link::start_by(session, Vec::new(), WHO))
            }
        }
    }
}

/// Carry `app` in `client`'s session, whose first link `dialer` opened, and
/// on a new link of `dialer` after each lost one, until the session ends.
/// `note` hears each loss, attempt and resume. A host that greeted with no
/// layer gets the bytes as they are, on the first link alone.
pub async fn carry<A, N>(dialer: &Dialer, client: Client<Link>, app: A, note: N) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let connect = |_: &Ended| async move {
        let mut quiet = |_: &str| {};
        match dialer.link(&mut quiet).await {
            Ok(link) => Next::Link(link),
            Err(missed) if missed.is_final() => Next::Stop(missed.lines(dialer.target()).join("; ")),
            Err(missed) => Next::Retry(missed.lines(dialer.target()).join("; ")),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::Origin;

    fn failed(error: ConnectError) -> Missed {
        let attempt = ("relay.example".to_string(), OpenError::Connect { error, origin: Origin::Minted });
        Missed::Open(Failure { attempts: vec![attempt] })
    }

    fn refused(status: u16, body: &str) -> Missed {
        failed(ConnectError::Refused { status, body: body.into() })
    }

    #[test]
    fn a_refusal_that_a_new_link_gets_again_ends_the_session() {
        assert!(refused(403, "layer: missing or wrong token").is_final());
        assert!(refused(403, "forward: 10.0.0.1:22 not in the ALLOW list").is_final());
        assert!(refused(404, "/v1/layer/h/22: not found").is_final(), "a host that no longer serves the path");
        assert!(refused(401, "a key's signature").is_final());
        let offline = Missed::Open(Failure { attempts: vec![("r".into(), OpenError::Offline)] });
        assert!(offline.is_final());
    }

    #[test]
    fn a_host_that_is_down_or_slow_is_tried_again() {
        assert!(!refused(502, "relay: cannot reach h:22: connect failed").is_final());
        assert!(!refused(503, "relay: stopping").is_final());
        assert!(!refused(429, "slow down").is_final());
        let timeout =
            ConnectError::Timeout { step: "the WebSocket upgrade", after: std::time::Duration::from_secs(20) };
        assert!(!failed(timeout).is_final());
        let deadline = Missed::Open(Failure { attempts: vec![("r".into(), OpenError::Deadline)] });
        assert!(!deadline.is_final());
    }

    #[test]
    fn a_dialer_names_the_one_host_and_the_path_of_its_target() {
        let relay = Relay { host: "relay.example".into(), port: 8443 };
        let dialer = Dialer::new(relay.clone(), "2001:db8::1", 22, Trust::Default).unwrap();
        assert_eq!((dialer.relay(), dialer.path()), (&relay, "/v1/layer/2001:db8::1/22"));
        assert_eq!(dialer.target(), "[2001:db8::1]:22");
        assert!(dialer.relays.explicit, "the opener tries this host alone");
        assert!(Dialer::new(relay.clone(), "a/b", 22, Trust::Default).is_err());
        let six = Dialer::new(relay.clone(), "github.com", 22, Trust::Default).unwrap().with_family(Some(6));
        assert_eq!(six.path(), "/v1/layer/github.com/22?family=6");
        let any = Dialer::new(relay, "github.com", 22, Trust::Default).unwrap().with_family(None);
        assert_eq!(any.path(), "/v1/layer/github.com/22");
    }

    /// Each link goes to the process that the offer names, the first too.
    #[test]
    fn a_dialer_for_an_offer_goes_to_the_host_that_it_names() {
        let asked = Relay { host: "relay.example.org".into(), port: 443 };
        let at = Relay { host: "relay-2.relay.example.org".into(), port: 443 };
        let offer = Offer { layer: true, at: Some(at.clone()), refused: None };
        let dialer = Dialer::for_offer(&asked, &offer, "github.com", 22, Trust::Default).unwrap();
        assert_eq!(dialer.relay(), &at);
        let unnamed = Offer { layer: true, ..Offer::default() };
        assert_eq!(Dialer::for_offer(&asked, &unnamed, "github.com", 22, Trust::Default).unwrap().relay(), &asked);
    }

    /// Only the far end's `REFUSE` of a new session for its room is one
    /// that the contract's road may carry instead.
    #[test]
    fn only_a_busy_refusal_in_the_handshake_is_no_room() {
        let refused = |code| ClientError::Handshake(HandshakeError::Refused { code, reason: "256 MiB".into() });
        assert_eq!(no_room(&refused(RefuseCode::BUSY)), Some("256 MiB"));
        for code in [RefuseCode::UNKNOWN_SESSION, RefuseCode::BAD_PROOF, RefuseCode::OTHER, RefuseCode::PROTOCOL] {
            assert_eq!(no_room(&refused(code)), None, "{code}");
        }
        assert_eq!(no_room(&ClientError::Handshake(HandshakeError::Closed("busy".into()))), None);
        assert_eq!(no_room(&ClientError::Timeout), None);
    }
}
