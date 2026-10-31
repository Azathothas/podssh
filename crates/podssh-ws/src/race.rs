//! The direct connection to a name: the addresses of the first source of the
//! resolver that gives any ([`crate::resolve`]), raced as RFC 8305 says
//! (T-265); when none of them connects and the source falls back (the cache's
//! addresses, those of DNS over HTTPS), the addresses of the sources after it
//! (T-344). A source with another after it has [`SOURCE_WAIT`] to connect, so
//! that a remembered address that no longer answers does not hold the dial.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::dial::{authority, DialError, ATTEMPT_DELAY};
use crate::mptcp::Multipath;
use crate::resolve::{self, SOURCE_WAIT};

/// Resolve and connect, with plain TCP: [`connect_race`].
pub(crate) async fn connect_direct(
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    connect_race(host, port, deadline, budget, None).await.map(|(stream, _)| stream)
}

/// One attempt of the race: plain TCP, or with `ask`, the probe's answer,
/// Multipath TCP where the host offers it.
async fn attempt(addr: SocketAddr, ask: Option<Result<(), String>>) -> std::io::Result<(TcpStream, Multipath)> {
    match ask {
        Some(offer) => crate::mptcp::connect(addr, offer).await,
        None => Ok((TcpStream::connect(addr).await?, Multipath::Plain("Multipath TCP was not asked for".into()))),
    }
}

/// [`connect_direct`], each attempt as `ask` says. The source of the address
/// that connected is kept, for `podssh doctor` and for the cache.
pub(crate) async fn connect_race(
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
    ask: Option<Result<(), String>>,
) -> Result<(TcpStream, Multipath), DialError> {
    let target = authority(host, port);
    // Pinned addresses, the system resolver, the addresses that carried a
    // session, then DNS over HTTPS: a host with a broken resolver but working
    // TCP egress still gets there.
    let mut found = resolve::resolve_from(host, port, deadline, None)
        .await
        .map_err(|detail| DialError::Resolve { host: host.to_string(), detail })?;
    let mut tried: Vec<SocketAddr> = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(DialError::Timeout { step: format!("resolving {host}"), after: budget });
        }
        let addrs: Vec<SocketAddr> = found.addrs.iter().copied().filter(|a| !tried.contains(a)).collect();
        tried.extend(addrs.iter().copied());
        let until = if found.more { deadline.min(Instant::now() + SOURCE_WAIT) } else { deadline };
        match race(&target, addrs, until, deadline, budget, &ask).await {
            Ok((stream, how)) => {
                if let Ok(peer) = stream.peer_addr() {
                    resolve::note_dialed(host, peer, found.source);
                }
                return Ok((stream, how));
            }
            Err(failed) if found.more && Instant::now() < deadline => {
                match resolve::resolve_from(host, port, deadline, Some(found.source)).await {
                    Ok(next) => found = next,
                    Err(_) => return Err(failed),
                }
            }
            Err(failed) => return Err(failed),
        }
    }
}

/// The addresses in the order of [`interleave`], each started
/// [`ATTEMPT_DELAY`] after the one before, or at once when the one before
/// failed; the first that connects wins, and the others stop. Past `until`,
/// short of `deadline`, they failed, and another source may have more.
async fn race(
    target: &str,
    addrs: Vec<SocketAddr>,
    until: Instant,
    deadline: Instant,
    budget: Duration,
    ask: &Option<Result<(), String>>,
) -> Result<(TcpStream, Multipath), DialError> {
    let mut waiting = interleave(addrs).into_iter();
    // Dropped at the return: each attempt that still runs stops.
    let mut running = tokio::task::JoinSet::new();
    let mut next_at = Instant::now();
    let mut last = String::from("each address of this source was tried already");
    loop {
        if running.is_empty() || Instant::now() >= next_at {
            if let Some(addr) = waiting.next() {
                let ask = ask.clone();
                running.spawn(async move { (addr, attempt(addr, ask).await) });
                next_at = Instant::now() + ATTEMPT_DELAY;
                continue;
            }
            if running.is_empty() {
                return Err(DialError::Connect { target: target.to_string(), detail: last });
            }
        }
        let wake = if waiting.len() > 0 { next_at.min(until) } else { until };
        tokio::select! {
            joined = running.join_next() => match joined {
                Some(Ok((_, Ok(stream)))) => return Ok(stream),
                Some(Ok((addr, Err(e)))) => {
                    last = format!("{addr}: {e}");
                    next_at = Instant::now();
                }
                // An attempt that panicked counts as one that failed.
                Some(Err(e)) => last = e.to_string(),
                None => {}
            },
            _ = tokio::time::sleep_until(wake) => {
                if Instant::now() >= deadline {
                    return Err(DialError::Timeout { step: format!("connecting to {target}"), after: budget });
                }
                if Instant::now() >= until {
                    let detail = format!("no address of this source answered within {} s", SOURCE_WAIT.as_secs());
                    return Err(DialError::Connect { target: target.to_string(), detail });
                }
            }
        }
    }
}

/// The addresses with the families taking turns, the first family first
/// (RFC 8305, section 4): a family that does not work costs one attempt
/// delay, not each of its addresses in a row.
pub fn interleave(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let Some(first) = addrs.first().map(|a| a.is_ipv6()) else { return addrs };
    let (mut lead, mut other): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6() == first);
    let mut out = Vec::with_capacity(lead.len() + other.len());
    lead.reverse();
    other.reverse();
    loop {
        match (lead.pop(), other.pop()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}
