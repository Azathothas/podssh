//! The probe of an open tunnel (T-560): a front door that completes the
//! proxy's CONNECT, TLS and the CONNECT of HTTP/2, then relays nothing, gives
//! a tunnel that looks open, and each stream in it goes quiet, so that each
//! command above it says a timeout of its own. One TCP connection inside the
//! tunnel, to Cloudflare's resolver on port 443, proves that a packet went
//! out and one came back: a SYN-ACK, or a reset, is the far side's answer
//! through the tunnel. Two tries, [`GAP`] apart, so that one lost packet is
//! no verdict. It goes inside the one connection of the road, so it opens
//! nothing more outside.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::stack::Stack;

/// Cloudflare's resolver on port 443, of each family: WARP's own network
/// answers it for each device, and its port of TLS is open where a port of
/// DNS may be filtered.
/// The endpoint `trace` of `cloudflare-dns` (`pod-services`).
fn trace() -> Vec<SocketAddr> {
    let service = pod_services::get("cloudflare-dns").expect("pod-services holds the service cloudflare-dns");
    service.endpoint("trace").map(|e| e.socket_addrs()).unwrap_or_default()
}
/// The address of the IPv4 family.
pub fn target_v4() -> SocketAddr {
    trace().into_iter().find(SocketAddr::is_ipv4).expect("the trace of cloudflare-dns has an IPv4 address")
}
/// The address of the IPv6 family.
pub fn target_v6() -> SocketAddr {
    trace().into_iter().find(SocketAddr::is_ipv6).expect("the trace of cloudflare-dns has an IPv6 address")
}
/// The ceiling of each try, within the opening's own limit: smoltcp sends
/// its SYN again within it, a second after the first.
pub const TRY: Duration = Duration::from_secs(3);
/// The pause before the second try.
pub const GAP: Duration = Duration::from_millis(700);
/// How many tries make a verdict.
pub const TRIES: usize = 2;

/// The probe's target for a device with `addresses`: IPv4's when it has
/// one, as WARP gives each device both; none for a device with neither.
pub fn target(addresses: &[IpAddr]) -> Option<SocketAddr> {
    if addresses.iter().any(IpAddr::is_ipv4) {
        Some(target_v4())
    } else if addresses.iter().any(IpAddr::is_ipv6) {
        Some(target_v6())
    } else {
        None
    }
}

/// What the probe met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An answer came back through the tunnel: the connection opened, or
    /// the far side reset it.
    Carried,
    /// No answer in any try: why each one failed.
    Silent(Vec<String>),
    /// The tunnel ended while the probe waited: why.
    Ended(String),
}

/// A TCP connection to `to` inside `stack`'s tunnel, [`TRIES`] times at
/// most, [`GAP`] apart, each within `limit` and [`TRY`].
pub async fn run(stack: &Stack, to: SocketAddr, limit: Duration) -> Verdict {
    let ceiling = limit.min(TRY);
    let mut failed = Vec::new();
    for attempt in 0..TRIES {
        if attempt > 0 {
            tokio::time::sleep(GAP).await;
        }
        match stack.connect(to, ceiling).await {
            // Its drop closes it with a FIN: the probe sends no byte.
            Ok(stream) => {
                drop(stream);
                return Verdict::Carried;
            }
            Err(why) if why.ends_with(crate::stream::RESET) => return Verdict::Carried,
            Err(why) => {
                if let Some(ended) = stack.ended() {
                    return Verdict::Ended(ended);
                }
                failed.push(why);
            }
        }
    }
    Verdict::Silent(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4's target for a device of both families, IPv6's for one of IPv6
    /// alone, and none for a device with no address.
    #[test]
    fn the_target_is_of_a_family_that_the_device_has() {
        let v4: IpAddr = "172.16.0.2".parse().unwrap();
        let v6: IpAddr = "2606:4700:110:8a36::2".parse().unwrap();
        assert_eq!(target(&[v4, v6]), Some(target_v4()));
        assert_eq!(target(&[v6]), Some(target_v6()));
        assert_eq!(target(&[]), None);
        assert_eq!(target_v4().to_string(), "1.1.1.1:443");
        assert_eq!(target_v6().to_string(), "[2606:4700:4700::1111]:443");
    }
}
