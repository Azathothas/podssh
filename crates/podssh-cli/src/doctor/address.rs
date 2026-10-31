//! Whether the way out takes an address as well as a name (T-366). Each
//! road of the release binaries asks the proxy for a name, so a proxy that
//! allows listed names only and one that takes any public address give the
//! probes of names the same answers; a road to an address (`--direct` to
//! one, WARP's endpoint, Tor's first hops) leaves only through the second.
//! Through a proxy: one CONNECT to the first resolver of DNS over HTTPS by
//! its address, sampled as the other probes are (T-324), then TLS with it
//! for that address, so that a `200` which carries nothing is named; and a
//! line that names the case.

use std::time::Duration;

use podssh_ws::dial::{self, HttpProxy, ProxyChoice};
use podssh_ws::{Trust, Verdict};

use super::samples::{sample, Tried};
use super::Report;

/// The bound on the probe, and on its handshake.
const PROBE: Duration = Duration::from_secs(8);

/// The address that the probe asks for: the first of the resolvers, which
/// podssh reaches by address already, public and long lived, with a
/// certificate for that address.
pub(super) fn address() -> &'static str {
    podssh_ws::resolve::DOH_RESOLVERS[0].0
}

/// The probe through `proxy`: whether the proxy took a CONNECT to an
/// address, and the TLS of that address came through it.
pub(super) async fn through_proxy(report: &mut Report<'_>, proxy: &HttpProxy, trust: &Trust) -> bool {
    let ip = address();
    let via = &ProxyChoice::Via(proxy.clone());
    let target = dial::authority(ip, 443);
    let Tried { samples, first, error } = sample(PROBE, move |bound| dial::dial(ip, 443, via, bound)).await;
    let summary = samples.summary();
    let (took, detail) = match first {
        Some(stream) => match podssh_ws::tls::connect_over(stream, ip, trust, PROBE).await {
            Ok(_) => (true, format!("{target}: allowed by {proxy}, and TLS with {ip} for its address; {summary}")),
            Err(why) => (
                false,
                format!(
                    "{target}: {proxy} took the CONNECT, then {why}: it carries nothing to that address; {summary}"
                ),
            ),
        },
        None => (false, format!("{target}: {}; {summary}", error.map(|e| e.to_string()).unwrap_or_default())),
    };
    report.sampled("IP CONNECT", Verdict::Ok { detail }, &samples);
    took
}

/// The line of the case: what the way out takes, names, addresses, both or
/// neither, and what each means for the roads. `proxy` says whether the
/// probes went through one.
pub(super) fn case(report: &mut Report<'_>, names: bool, addresses: bool, proxy: bool) {
    let ip = address();
    let way = if proxy { "the proxy" } else { "this host" };
    let detail = match (names, addresses) {
        (true, true) => format!(
            "names and addresses: {way} reaches a name and the address {ip}, so a road to an address (--direct to \
             one, WARP's endpoint, Tor's first hops) can leave too"
        ),
        (true, false) => format!(
            "names only: {way} reaches a name, and not the address {ip}; each road that asks for a name leaves, and \
             a road that asks for an address (--direct to one, WARP's endpoint, Tor's first hops) cannot leave here"
        ),
        (false, true) => format!(
            "addresses only: {way} reaches the address {ip}, and no name of the probes; a road by address can leave, \
             and the relay's name is refused here"
        ),
        (false, false) => format!("neither: {way} reaches no name of the probes, and not the address {ip}"),
    };
    report.ok("egress takes", detail);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address is a literal of an address, as the probe must ask for one.
    #[test]
    fn the_address_is_a_literal() {
        assert!(address().parse::<std::net::IpAddr>().is_ok(), "{}", address());
    }
}
