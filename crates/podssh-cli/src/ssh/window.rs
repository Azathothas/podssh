//! The road that a session took, for the cap of its SSH windows (T-662):
//! what a road holds for a slow reader bounds what a server may have in
//! flight. Where nothing tells the road, a session keeps the window of
//! before.

use podssh_ssh::pace::Road;
use podssh_ssh::Options;

use super::resolve::Transport;
use super::transport::Reached;

/// The kind of a resolved road, as far as its cap goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Direct,
    Relay,
    Iroh,
    Node,
    Other,
}

/// The road of a session of `transport` that `reached` opened.
pub fn road(transport: &Transport, reached: &Reached) -> Road {
    let kind = match transport {
        Transport::Direct => Kind::Direct,
        Transport::Relay { .. } => Kind::Relay,
        Transport::Iroh { .. } => Kind::Iroh,
        Transport::Node { .. } => Kind::Node,
        _ => Kind::Other,
    };
    of(kind, reached.relay.is_some(), reached.layer.is_some())
}

/// The road of `kind`: a relay host's session is the contract's when it
/// has a relay leg, podssh's relay role's when the resumable layer carries
/// it (T-173), and the direct road's when neither (T-363, T-253). A node
/// races its roads, and the pair's is the one that every node has: its cap
/// holds whichever won.
fn of(kind: Kind, relay: bool, layer: bool) -> Road {
    match kind {
        Kind::Direct => Road::Direct,
        Kind::Relay if layer => Road::Role,
        Kind::Relay if relay => Road::Relay,
        Kind::Relay => Road::Direct,
        Kind::Iroh => Road::Iroh,
        Kind::Node => Road::Pair,
        Kind::Other => Road::Other,
    }
}

/// `opts` with the cap of `road`.
pub fn on(opts: &Options, road: Road) -> Options {
    let mut opts = opts.clone();
    opts.window_cap = road.cap();
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_road_of_a_resolved_transport() {
        assert_eq!(of(Kind::Direct, false, false), Road::Direct);
        assert_eq!(of(Kind::Relay, true, false), Road::Relay);
        assert_eq!(of(Kind::Relay, false, true), Road::Role);
        assert_eq!(of(Kind::Relay, false, false), Road::Direct, "the direct road after the relay hosts");
        assert_eq!(of(Kind::Iroh, false, true), Road::Iroh);
        assert_eq!(of(Kind::Node, false, true), Road::Pair);
        assert_eq!(of(Kind::Other, false, false), Road::Other);
        assert_eq!(of(Kind::Other, true, false), Road::Other);
    }

    /// The pair's cap is the layer's window on the pair's road, under its
    /// relay's bound for a slow receiver (T-443).
    #[test]
    fn the_pairs_cap_is_the_layers_window_there() {
        assert_eq!(Road::Pair.cap() as usize, podssh_relay::session::replay::PAIR_WINDOW);
    }

    #[test]
    fn the_cap_goes_into_the_options() {
        let hop = podssh_ssh::Hop { user: None, host: "h".into(), port: 22, tls: false };
        let opts = Options::new(hop, "u".into());
        assert_eq!(opts.window_cap, Road::Other.cap(), "the window of before, unless the road is known");
        assert_eq!(on(&opts, Road::Direct).window_cap, Road::Direct.cap());
    }
}
