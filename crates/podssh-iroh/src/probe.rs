//! Whether this host's UDP goes out and comes back (T-359). A sandbox can
//! refuse UDP (`docs/target-environment.md`), and iroh's endpoint does not
//! start when its UDP bind is required and fails; a host can also let a UDP
//! socket bind and drop its datagrams further on, as a network whose way out
//! is a proxy can. A bind is not what a direct path uses, so the iroh road
//! takes UDP after a datagram came back: the round trip of QUIC address
//! discovery (QAD) to its own relay, in the endpoint's first report of the
//! network (rule 1 of `AGENTS.md`).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use iroh::{Endpoint, Watcher as _};

/// How long the first report may take. iroh gives each QAD probe 3 s, so a
/// host that drops UDP waits about that long, and the report 5 s for its
/// HTTPS probes, which go through the proxy; one second more, and no report
/// is an answer of its own.
pub const REPORT_LIMIT: Duration = Duration::from_secs(6);

/// Bind a UDP socket to port 0 of each address, and close it at once: the
/// address that the system gave, or why it refused. Nothing is sent, and
/// nothing listens.
pub fn udp() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.local_addr()
}

/// What the iroh road found of this host's UDP, and so whether it took it.
#[derive(Debug)]
pub enum Answer {
    /// A QAD round trip to the home relay came back, within this time: the
    /// endpoint keeps its UDP sockets for direct paths.
    Answered(Duration),
    /// No UDP socket binds here: the relay carries each byte.
    Refused(std::io::Error),
    /// A socket bound, and no round trip came back within this time: the
    /// relay carries each byte, as on a host that drops UDP further on.
    Unknown(Duration),
    /// `PODSSH_IROH_UDP=on`: UDP after the bind alone, nothing sent, for a
    /// relay that runs no QAD.
    BindOnly(SocketAddr),
    /// `PODSSH_IROH_UDP=off`: the relay carries each byte, with no probe.
    Off,
}

impl Answer {
    /// Whether the endpoint keeps UDP sockets for direct paths.
    pub fn keeps_udp(&self) -> bool {
        matches!(self, Answer::Answered(_) | Answer::BindOnly(_))
    }
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::Answered(took) => write!(
                f,
                "a QUIC address discovery to the home relay came back in {} ms, so direct paths may take UDP",
                took.as_millis()
            ),
            Answer::Refused(e) => write!(f, "no UDP socket binds here ({e}), so the relay carries each byte"),
            Answer::Unknown(waited) => write!(
                f,
                "a UDP socket binds, and no QUIC address discovery to the home relay came back within {} ms, so \
                 the relay carries each byte (PODSSH_IROH_UDP=on takes UDP after the bind alone)",
                waited.as_millis()
            ),
            Answer::BindOnly(addr) => write!(f, "PODSSH_IROH_UDP=on: UDP after a socket bound ({addr}), nothing sent"),
            Answer::Off => write!(f, "PODSSH_IROH_UDP=off: the relay carries each byte"),
        }
    }
}

/// Whether the endpoint's first report of the network holds a QAD round
/// trip, within `limit`; `None` when no report came in time. The report
/// waits for its QAD probes before it is published, so a fast HTTPS probe
/// does not answer for them.
pub async fn round_trip(endpoint: &Endpoint, limit: Duration) -> Option<bool> {
    let mut reports = endpoint.net_report();
    tokio::time::timeout(limit, reports.initialized()).await.ok().map(|report| report.has_udp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_round_trip_or_the_variable_keeps_udp() {
        assert!(Answer::Answered(Duration::from_millis(40)).keeps_udp());
        assert!(Answer::BindOnly("0.0.0.0:41000".parse().unwrap()).keeps_udp());
        assert!(!Answer::Unknown(REPORT_LIMIT).keeps_udp());
        assert!(!Answer::Refused(std::io::Error::from(std::io::ErrorKind::PermissionDenied)).keeps_udp());
        assert!(!Answer::Off.keeps_udp());
    }

    #[test]
    fn each_answer_says_what_carries_the_bytes() {
        let unknown = Answer::Unknown(Duration::from_millis(3010)).to_string();
        assert!(unknown.contains("within 3010 ms") && unknown.contains("relay carries each byte"), "{unknown}");
        assert!(unknown.contains("PODSSH_IROH_UDP=on"), "{unknown}");
        let answered = Answer::Answered(Duration::from_millis(12)).to_string();
        assert!(answered.contains("came back in 12 ms") && answered.contains("direct paths"), "{answered}");
        assert!(!Answer::Off.to_string().contains("direct paths"));
    }
}
