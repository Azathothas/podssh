//! The most window that a channel may have on each road (T-662): where
//! nobody types, a bulk channel's window grows to twice the bytes that the
//! path carries in a round trip, up to what its road holds for a slow
//! reader, since a window is what a server may have in flight, and so what
//! may wait between it and podssh when podssh reads slowly.

/// 16 MiB: what a road with nothing of the contract between the ends takes,
/// beside OpenSSH's 2 MiB and osewa's 4 MiB, for a path of 100 ms at about
/// 1 Gbit/s. Memory is bounded by it, a channel at a time.
pub const DIRECT_CAP: u32 = 16 << 20;

/// The default relay: under the 2 MiB at which its document closes a
/// session for a slow reader (`1013`, T-062), by a quarter for the frames
/// around SSH's bytes; 3 of today's windows, as `podssh cp` shares among
/// its tasks on one relay session.
pub const RELAY_CAP: u32 = 1536 << 10;

/// The pair's road: the most that one link of the resumable layer carries
/// with no acknowledgement, under the relay's 1 MiB for a slow receiver
/// (T-443).
pub const PAIR_CAP: u32 = 768 << 10;

/// The road under a connection, as its caller knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Road {
    /// `--direct`, through `HTTPS_PROXY` or not, and the direct road after
    /// the relay hosts: the kernel's buffers alone.
    Direct,
    /// A node over the iroh road: QUIC's own windows, and the layer's buffer.
    Iroh,
    /// The resumable layer at podssh's relay role, whose queue for a slow
    /// reader waits for it (T-336).
    Role,
    /// The default relay, or another of its contract.
    Relay,
    /// A node over the pair's road, through a relay.
    Pair,
    /// Each other road (a tunnel, a forwarder, a server that the user runs):
    /// what it holds was not measured, so it keeps the window of before.
    Other,
}

impl Road {
    /// The most window that a channel may have on this road.
    pub fn cap(self) -> u32 {
        match self {
            Road::Direct | Road::Iroh | Road::Role => DIRECT_CAP,
            Road::Relay => RELAY_CAP,
            Road::Pair => PAIR_CAP,
            Road::Other => crate::run::WINDOW,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u32 = 1024;
    const MIB: u32 = 1024 * KIB;

    #[test]
    fn each_road_has_its_cap() {
        assert_eq!(Road::Direct.cap(), 16 * MIB);
        assert_eq!(Road::Iroh.cap(), 16 * MIB);
        assert_eq!(Road::Role.cap(), 16 * MIB);
        assert_eq!(Road::Relay.cap(), 1536 * KIB);
        assert_eq!(Road::Pair.cap(), 768 * KIB);
        assert_eq!(Road::Other.cap(), 512 * KIB);
    }

    #[test]
    fn the_relays_cap_stays_under_its_close_for_a_slow_reader() {
        assert!(Road::Relay.cap() < 2 * MIB, "the relay's document closes a session at 2 MiB queued");
        assert!(Road::Pair.cap() < MIB, "the pair's relay holds 1 MiB for a slow receiver");
    }

    /// No road takes less than the window of before T-662: a road whose
    /// cap was 512 KiB keeps it, and the others grow from it.
    #[test]
    fn no_road_is_under_the_window_of_before() {
        for road in [Road::Direct, Road::Iroh, Road::Role, Road::Relay, Road::Pair, Road::Other] {
            assert!(road.cap() >= crate::run::WINDOW, "{road:?}");
        }
    }
}
