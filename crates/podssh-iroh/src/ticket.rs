//! A node's address on the iroh road (T-163): `iroh:` and iroh's own ticket
//! of an endpoint, which holds the node's key and its home relay. A ticket
//! is an address, not a credential: the node's allowlist of client keys
//! gives access, so a ticket may go on a command line.

use iroh::{Endpoint, EndpointAddr, RelayUrl, Watcher as _};
use iroh_tickets::endpoint::EndpointTicket;

/// The scheme of an iroh destination: `iroh:TICKET`.
pub const SCHEME: &str = "iroh:";

/// The address in `text`: `iroh:TICKET`, or iroh's ticket alone, as iroh's
/// tools print it. A ticket that names neither a relay nor an address of the
/// node is refused: nothing could reach the node.
pub fn parse(text: &str) -> Result<EndpointAddr, String> {
    let ticket = text.strip_prefix(SCHEME).unwrap_or(text);
    if ticket.is_empty() {
        return Err(format!("{text:?}: no ticket after {SCHEME}"));
    }
    let parsed: EndpointTicket =
        ticket.parse().map_err(|e| format!("{SCHEME}{}: not an iroh ticket: {e}", shorten(ticket)))?;
    let addr = EndpointAddr::from(parsed);
    if addr.is_empty() {
        return Err(format!("{SCHEME}{}: the ticket names no relay and no address of the node", shorten(ticket)));
    }
    Ok(addr)
}

/// `addr` as `iroh:TICKET`.
pub fn format(addr: &EndpointAddr) -> String {
    format!("{SCHEME}{}", EndpointTicket::new(addr.clone()))
}

/// The ticket of `endpoint` at its home relay: its key and the relay, and no
/// address of its host, which the relay tells a peer when UDP works.
pub fn of(endpoint: &Endpoint, relay: &RelayUrl) -> String {
    format(&EndpointAddr::new(endpoint.id()).with_relay_url(relay.clone()))
}

/// The home relay of `endpoint`, when it has one.
pub fn home_relay(endpoint: &Endpoint) -> Option<RelayUrl> {
    endpoint.addr().relay_urls().next().cloned()
}

/// Call `say` with the new ticket each time the home relay of `endpoint`
/// changes, until the endpoint closes: a client then needs the new ticket.
pub async fn follow(endpoint: Endpoint, mut relay: Option<RelayUrl>, say: impl Fn(String)) {
    let mut addrs = endpoint.watch_addr();
    while let Ok(addr) = addrs.updated().await {
        let now = addr.relay_urls().next().cloned();
        if now.is_some() && now != relay {
            if let Some(url) = &now {
                say(of(&endpoint, url));
            }
            relay = now;
        }
    }
}

/// The start and the end of a long ticket, for a message.
fn shorten(ticket: &str) -> String {
    if ticket.chars().count() <= 40 {
        return ticket.to_string();
    }
    let head: String = ticket.chars().take(24).collect();
    let tail: String = ticket.chars().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{head}...{tail}")
}
