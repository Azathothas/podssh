//! E15 — ⛔ **the two queries, and the rule that an empty type is not a failure.**
//!
//! ⛔ **Both families are asked, in one call each, and the order is fixed.**
//! **READ**, `dropssh` `src/dns.c:221-223`:
//!
//! > THE DNS QUERY TYPE IS ASKED FOR EXPLICITLY AND BOTH FAMILIES ARE
//! > REQUESTED IN ONE CALL, so a name that is AAAA-only does not need a second
//! > round trip to be discovered.
//!
//! ⛔ **Both are asked even when the first answers**, ⛔ because ⛔ **a host with
//! both families is the common case** ⛔ and ⛔ **a v6-only host must not cost
//! two round trips to discover.**
//!
//! ⛔ **A per-type empty answer is NOT an error**, ⛔ because ⛔ **an A-only
//! name legitimately has no `AAAA` record** ⛔ — ⛔ **and getting this backwards
//! turns every A-only name on the internet into a DoH failure.** ⛔ The error is
//! raised only when ⛔ **both** types came back empty, ⛔ which is the case
//! `dns.md`'s plant names: ⛔ *"an empty answer for a real name"*.

use std::net::SocketAddr;
use std::time::Duration;

use super::doh::{parse_json, DohEndpoint, DohError, DohQuery, DohTransport, TYPE_A, TYPE_AAAA};

/// ⛔ **Ask for both families and return the addresses, or a named error.**
///
/// ⛔ **The port is applied here and not inside the parse** ⛔ — ⛔ **a DoH
/// answer carries addresses and no ports**, ⛔ **and a parse that stamped a
/// port in would make a caller that asked for `22` and got a `0` a silent
/// dial to port zero.**
pub async fn lookup(
    transport: &dyn DohTransport,
    endpoint: &DohEndpoint,
    name: &str,
    port: u16,
    budget: Duration,
) -> Result<Vec<SocketAddr>, DohError> {
    // ⛔ **The endpoint is named in every error**, ⛔ because ⛔ *"DoH did not
    // answer"* without the endpoint ⛔ **is a message with no way to act on it**
    // ⛔ — ⛔ and E17's whole Problem is messages the operator cannot act on.
    let endpoint_name = format!("{}:{}", endpoint.name, endpoint.address.port());
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut last_error: Option<DohError> = None;

    for kind in [TYPE_A, TYPE_AAAA] {
        let query = DohQuery { name: name.to_string(), kind };
        let encoded = query.wire();
        // ⛔ **A name that cannot be encoded is refused, not queried.** ⛔ The
        // encoder returns an empty string for a label over 63 bytes, and ⛔
        // **an empty `dns=` parameter is a question about nothing.**
        if encoded.is_empty() {
            return Err(DohError::Unparseable {
                endpoint: endpoint_name,
                detail: format!("{name} cannot be encoded as a DNS question"),
            });
        }
        let line = endpoint.request_line(query);
        let headers = endpoint.headers();
        match transport.send(&endpoint, &line, &headers, budget).await {
            Ok(response) => match parse_json(&endpoint_name, name, &response) {
                Ok(addrs) => found.extend(addrs),
                // ⛔ **One empty type does not end the lookup.** ⛔ The reason is
                // recorded here because getting it backwards is invisible on an
                // IPv6-only test machine and catastrophic on a real one.
                Err(e @ DohError::EmptyAnswer { .. }) => {
                    last_error = Some(e);
                }
                // ⛔ **An unparseable body does end it**, ⛔ because ⛔ **the
                // endpoint is not a DNS endpoint** ⛔ and ⛔ asking the second
                // type of a captive portal tells you nothing the first did not.
                Err(e) => return Err(e),
            },
            Err(detail) => {
                return Err(DohError::Transport { endpoint: endpoint_name, detail })
            }
        }
    }

    if found.is_empty() {
        return Err(last_error.unwrap_or(DohError::EmptyAnswer {
            endpoint: endpoint_name,
            name: name.to_string(),
            status: None,
        }));
    }
    Ok(found.into_iter().map(|a| SocketAddr::new(a.ip(), port)).collect())
}