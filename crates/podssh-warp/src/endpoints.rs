//! The endpoints of a device, tried in turn (T-561): the road dialled one
//! constant address, whatever WARP's API had said, so a prefix that a proxy
//! refuses or a network drops took the road with it while the device was
//! well. [`crate::Device::endpoints`] gives the list: the run's one
//! endpoint alone when it has one (`PODSSH_WARP_ENDPOINT`, a stand-in);
//! else the endpoint that last opened, the record's endpoint of HTTP/2, then
//! the API's peers. Each is tried alone, one after the other, never in a
//! race, so that the road keeps its one connection; a failure of one
//! address goes on to the next, and a failure that would be the same at each
//! ends the road.

use std::time::Duration;

use crate::road::Fault;

/// The ceiling of the dial (TCP, and the proxy's CONNECT) of each endpoint
/// that another one follows: a prefix that a network drops hangs the dial,
/// and the next endpoint should not wait out the whole limit for it.
pub const DIAL_EACH: Duration = Duration::from_secs(3);

/// The dial's ceiling of an endpoint: [`DIAL_EACH`] while another endpoint
/// waits after it, else the opening's whole `limit`, as the one endpoint
/// of a road had.
pub fn dial_limit(last: bool, limit: Duration) -> Duration {
    if last {
        limit
    } else {
        limit.min(DIAL_EACH)
    }
}

/// Whether `fault` at one endpoint lets the next one be tried: a way out
/// that did not reach it, an edge that failed there, and a tunnel that
/// carried nothing are of that address. A device that the edge refused, a
/// proxy that re-terminates TLS, and this host's part would be the same at
/// each, so they end the road.
pub fn goes_on(fault: &Fault) -> bool {
    matches!(fault, Fault::Unreachable(_) | Fault::Edge(_) | Fault::Silent(_))
}

/// The faults of the endpoints tried so far, in turn.
#[derive(Debug, Default)]
pub struct Tried(Vec<Fault>);

impl Tried {
    /// One endpoint's fault, which let the next be tried.
    pub fn push(&mut self, fault: Fault) {
        self.0.push(fault);
    }

    /// The road's fault when each endpoint failed: the one fault as it is
    /// when one was tried; else a fault of the first one's kind, whose line
    /// names each endpoint and why it failed, as each line names its own.
    pub fn all(self) -> Fault {
        let mut faults = self.0;
        match faults.len() {
            0 => Fault::Local("the device has no endpoint of WARP to try".into()),
            1 => faults.remove(0),
            n => {
                let lines: Vec<String> = faults.iter().map(Fault::to_string).collect();
                like(&faults[0], format!("each of WARP's {n} endpoints failed, in turn: {}", lines.join("; then ")))
            }
        }
    }

    /// The road's fault when `fault`, one that would be the same at each
    /// endpoint, ended it: itself, with the endpoints that failed before it.
    pub fn end(self, fault: Fault) -> Fault {
        if self.0.is_empty() {
            return fault;
        }
        let before: Vec<String> = self.0.iter().map(Fault::to_string).collect();
        let line = format!("{fault}; before it: {}", before.join("; then "));
        like(&fault, line)
    }
}

/// A fault of `fault`'s kind with `line`, so that the run's exit code stays
/// the kind's.
fn like(fault: &Fault, line: String) -> Fault {
    match fault {
        Fault::Unreachable(_) => Fault::Unreachable(line),
        Fault::Intercepted(_) => Fault::Intercepted(line),
        Fault::Device(_) => Fault::Device(line),
        Fault::Edge(_) => Fault::Edge(line),
        Fault::Silent(_) => Fault::Silent(line),
        Fault::Local(_) => Fault::Local(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each endpoint but the last dials within 3 s; the last takes the
    /// opening's limit.
    #[test]
    fn the_last_endpoint_takes_the_whole_limit() {
        let limit = Duration::from_secs(20);
        assert_eq!(dial_limit(false, limit), DIAL_EACH);
        assert_eq!(dial_limit(true, limit), limit);
        assert_eq!(dial_limit(false, Duration::from_secs(1)), Duration::from_secs(1));
    }

    /// The faults of an address go on; those that each address would give
    /// end the road.
    #[test]
    fn a_fault_of_an_address_goes_on() {
        for fault in [Fault::Unreachable("a".into()), Fault::Edge("b".into()), Fault::Silent("c".into())] {
            assert!(goes_on(&fault), "{fault:?}");
        }
        for fault in [Fault::Device("d".into()), Fault::Intercepted("e".into()), Fault::Local("f".into())] {
            assert!(!goes_on(&fault), "{fault:?}");
        }
    }

    /// One endpoint's fault stays as it is; several name each, in turn, of
    /// the first one's kind; a fault that ends the road keeps its kind and
    /// names those before it.
    #[test]
    fn the_failure_of_each_endpoint_is_named() {
        let mut one = Tried::default();
        one.push(Fault::Unreachable("WARP's endpoint 192.0.2.1:443 was not reached".into()));
        assert_eq!(one.all(), Fault::Unreachable("WARP's endpoint 192.0.2.1:443 was not reached".into()));
        let mut two = Tried::default();
        two.push(Fault::Unreachable("WARP's endpoint 192.0.2.1:443 was not reached".into()));
        two.push(Fault::Silent("WARP's endpoint 192.0.2.2:443: the tunnel opened and carried nothing".into()));
        let Fault::Unreachable(line) = two.all() else { panic!("the first one's kind") };
        let head = "each of WARP's 2 endpoints failed, in turn: WARP's endpoint 192.0.2.1:443";
        assert!(line.starts_with(head), "{line}");
        assert!(line.contains("; then WARP's endpoint 192.0.2.2:443: the tunnel opened"), "{line}");
        let mut before = Tried::default();
        before.push(Fault::Edge("HTTP/2 with WARP's endpoint 192.0.2.1:443: reset".into()));
        let Fault::Device(line) = before.end(Fault::Device("refused the tunnel of this device".into())) else {
            panic!("the ending fault's kind")
        };
        assert!(line.starts_with("refused the tunnel of this device; before it: HTTP/2"), "{line}");
        assert!(matches!(Tried::default().all(), Fault::Local(_)));
    }
}
