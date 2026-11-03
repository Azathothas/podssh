//! How the relay role reaches its targets (T-457): directly, or through the
//! proxy that its host's `HTTPS_PROXY` names, as podssh's client reaches its
//! relay (rule 2 of `AGENTS.md`: one way out, through the proxy when one is
//! set). The variables are podssh-ws's (`https_proxy`, `HTTPS_PROXY`,
//! `all_proxy`, `ALL_PROXY`, then `no_proxy`, `NO_PROXY`), read once as the
//! role starts; the loopback and what `NO_PROXY` names go directly.
//!
//! The role's policy checks each address of a name as it resolves on this
//! host, and the proxy is then asked for each checked address in turn,
//! never for the name: a proxy that resolves the name otherwise (its own
//! DNS, a split horizon, a name that rebinds) reaches nothing that was not
//! checked, as the exit of T-431 dials its addresses. Where nothing is
//! checked (`--allow-private`) and no family is asked, the name goes to the
//! proxy as it came, so that a host with no DNS reaches each target that
//! its proxy reaches. A proxy's refusal is the role's `502`, with the
//! proxy's status; the client's words never name the host's proxy, and the
//! owner's line does, never its credentials.

use std::net::SocketAddr;
use std::time::Duration;

use podssh_ws::dial::{self as ws, DialError, Proxy, ProxyChoice, ProxyKind, NO_PROXY_VARS, PROXY_VARS};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// How the role reaches its targets.
#[derive(Debug, Clone, Default)]
pub enum Egress {
    /// From this host, as on a listener with a way out of its own.
    #[default]
    Direct,
    /// Through `proxy`, which the variable `from` names; the loopback and
    /// the hosts of `bypass`, a list in the form of `NO_PROXY`, directly.
    Proxy { proxy: Proxy, bypass: Option<String>, from: &'static str },
}

impl Egress {
    /// The host's, from its variables: `Err` for a proxy that cannot be
    /// read, which stops the role's start, as a client refuses it.
    pub fn from_env() -> Result<Egress, String> {
        Egress::from_vars(|name| std::env::var(name).ok())
    }

    /// [`Egress::from_env`] with the variables given: lower-case names win
    /// over upper-case ones, and an empty value is unset, as podssh-ws reads
    /// them for the client.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Egress, String> {
        let first = |names: &[&'static str]| {
            names.iter().find_map(|name| var(name).filter(|v| !v.trim().is_empty()).map(|v| (*name, v)))
        };
        let Some((from, url)) = first(&PROXY_VARS) else { return Ok(Egress::Direct) };
        let proxy = Proxy::parse(&url).map_err(|why| format!("{from}: {why}"))?;
        Ok(Egress::Proxy { proxy, bypass: first(&NO_PROXY_VARS).map(|(_, list)| list), from })
    }

    /// The proxy for `host`, a name or an address, or none: the loopback,
    /// which no proxy reaches as this host's, and what the list names.
    pub fn proxy_for(&self, host: &str) -> Option<&Proxy> {
        let Egress::Proxy { proxy, bypass, .. } = self else { return None };
        let bypassed = bypass.as_deref().is_some_and(|list| ws::no_proxy_matches(list, host));
        (!ws::is_loopback(host) && !bypassed).then_some(proxy)
    }

    /// The role's words for its egress in its first line; none when it
    /// dials directly, as it did before T-457.
    pub fn shown(&self) -> Option<String> {
        let Egress::Proxy { proxy, bypass, from } = self else { return None };
        let but = match bypass {
            Some(_) => ", but the loopback and what NO_PROXY names directly",
            None => ", but the loopback directly",
        };
        // `proxy` shows its host and port alone, never its credentials.
        Some(format!("its targets through the {} proxy {proxy} of {from}{but}", proxy.kind.name()))
    }
}

/// What the role dials for a target, once its policy let the target: the
/// addresses that it checked, or the name as it came, for the proxy to
/// resolve, where nothing is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Addresses(Vec<SocketAddr>),
    Name(String, u16),
}

/// How a target was reached, for `/trace`: what was dialed (an address, or
/// the name that the proxy resolved), its family, and the proxy's kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leg {
    pub dialed: String,
    pub family: Option<u8>,
    pub proxy: Option<ProxyKind>,
}

/// Why no target was reached: words for the client, which never name the
/// host's proxy, and a line for the role's owner, which does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub said: String,
    pub line: Option<String>,
}

/// The target `name` by `plan`, through the proxy that `egress` gives it,
/// within `limit` in all: the first address that answers, in order.
pub async fn dial(name: &str, plan: &Plan, egress: &Egress, limit: Duration) -> Result<(TcpStream, Leg), Missed> {
    let deadline = Instant::now() + limit;
    let attempt = async {
        let addresses = match plan {
            Plan::Name(host, port) => return by_name(host, *port, egress, deadline).await,
            Plan::Addresses(addresses) => addresses,
        };
        let mut missed = Missed { said: "no address".into(), line: None };
        for address in addresses {
            let ip = address.ip().to_string();
            let family = Some(if address.is_ipv4() { 4 } else { 6 });
            // The name's NO_PROXY, and the address's: either sends it direct.
            let via = egress.proxy_for(name).and(egress.proxy_for(&ip));
            let got = match via {
                Some(proxy) => through(proxy, &ip, address.port(), deadline).await,
                None => TcpStream::connect(address)
                    .await
                    .map_err(|e| Missed { said: format!("{address}: {e}"), line: None }),
            };
            match got {
                Ok(tcp) => return Ok((tcp, Leg { dialed: ip, family, proxy: via.map(|p| p.kind) })),
                Err(why) => missed = why,
            }
        }
        Err(missed)
    };
    let late = Missed { said: format!("no answer within {}s", limit.as_secs()), line: None };
    tokio::time::timeout_at(deadline, attempt).await.unwrap_or(Err(late))
}

/// The name as it came, through the proxy, which resolves it: nothing of
/// the policy is to check, and this host may have no DNS.
async fn by_name(host: &str, port: u16, egress: &Egress, deadline: Instant) -> Result<(TcpStream, Leg), Missed> {
    let Some(proxy) = egress.proxy_for(host) else {
        // A plan by name is made only for a proxy; one that the list took
        // away since is a fault of the caller, not a dial.
        return Err(Missed { said: format!("{host}: no proxy for a name that this host did not resolve"), line: None });
    };
    let tcp = through(proxy, host, port, deadline).await?;
    Ok((tcp, Leg { dialed: host.to_string(), family: None, proxy: Some(proxy.kind) }))
}

/// `host:port` through `proxy`, by its CONNECT (or SOCKS5's), until
/// `deadline`.
async fn through(proxy: &Proxy, host: &str, port: u16, deadline: Instant) -> Result<TcpStream, Missed> {
    let left = deadline.saturating_duration_since(Instant::now());
    ws::dial(host, port, &ProxyChoice::Via(proxy.clone()), left)
        .await
        .map_err(|e| Missed { said: said(proxy.kind, &e), line: Some(e.to_string()) })
}

/// The client's words for a fault of the dial through the proxy: what the
/// proxy answered, never where the proxy is.
fn said(kind: ProxyKind, e: &DialError) -> String {
    let request = kind.request();
    match e {
        DialError::ProxyRefused { target, status, reason, .. } => {
            format!("the proxy of the relay's host refused {request} {target}: {status} {reason}")
        }
        DialError::ProxyUnreachable { .. } => "the proxy of the relay's host could not be reached".into(),
        DialError::ProxyProtocol { .. } => "the proxy of the relay's host did not answer as its protocol says".into(),
        DialError::Timeout { after, .. } => {
            format!("the proxy of the relay's host gave no tunnel within {}s", after.as_secs())
        }
        // A target's name that cannot go into a request: no proxy's words.
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
