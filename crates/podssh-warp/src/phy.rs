//! The tunnel as smoltcp's device: IP packets in two queues, with no link
//! layer (smoltcp's medium IP), as a TUN device would give them. The stack's
//! driver fills the queue of packets in from the tunnel and empties the
//! queue of packets out into it.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// Packets that wait to go out: smoltcp waits when more are queued, as at a
/// full link, until the driver has sent them. While the tunnel takes none
/// (HTTP/2's window is closed), they stay here.
pub const MAX_OUT: usize = 64;
/// Packets that wait to be read: a packet past them is dropped, as a full
/// link drops one, and TCP sends it again.
pub const MAX_IN: usize = 1024;

/// The two queues.
#[derive(Debug)]
pub struct Queue {
    pub inbound: VecDeque<Vec<u8>>,
    /// Oldest first, as the tunnel takes them.
    pub outbound: VecDeque<Vec<u8>>,
    mtu: usize,
    /// Packets dropped as the queue in was full.
    pub dropped: u64,
}

impl Queue {
    pub fn new(mtu: usize) -> Queue {
        Queue { inbound: VecDeque::new(), outbound: VecDeque::new(), mtu, dropped: 0 }
    }

    /// A packet from the tunnel.
    pub fn arrive(&mut self, packet: Vec<u8>) {
        if self.inbound.len() >= MAX_IN {
            self.dropped += 1;
            return;
        }
        self.inbound.push_back(packet);
    }
}

pub struct Rx(Vec<u8>);

pub struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let out = f(&mut packet);
        self.0.push_back(packet);
        out
    }
}

impl Device for Queue {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // A packet in may take an answer out: with the queue out full, the
        // packets in wait, and past MAX_IN are dropped, so that nothing grows
        // while the tunnel takes nothing (T-398).
        if self.outbound.len() >= MAX_OUT {
            return None;
        }
        let packet = self.inbound.pop_front()?;
        Some((Rx(packet), Tx(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.outbound.len() < MAX_OUT).then_some(Tx(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_queue_drops_and_says_so() {
        let mut queue = Queue::new(crate::MTU);
        for _ in 0..MAX_IN + 3 {
            queue.arrive(vec![0x45]);
        }
        assert_eq!((queue.inbound.len(), queue.dropped), (MAX_IN, 3));
        let caps = queue.capabilities();
        assert_eq!((caps.medium, caps.max_transmission_unit), (Medium::Ip, crate::MTU));
    }

    /// With the queue out full, a packet in waits, kept, and nothing more
    /// goes out; once one has gone, it is read.
    #[test]
    fn a_full_queue_out_holds_the_packets_in() {
        let mut queue = Queue::new(crate::MTU);
        queue.outbound.extend((0..MAX_OUT).map(|_| vec![0x45]));
        queue.arrive(vec![0x60]);
        let now = Instant::from_micros(0);
        assert!(queue.receive(now).is_none());
        assert!(queue.transmit(now).is_none());
        assert_eq!((queue.inbound.len(), queue.dropped), (1, 0));
        queue.outbound.pop_front();
        let (rx, _) = queue.receive(now).expect("the packet in, once one went out");
        assert_eq!(rx.consume(|packet| packet.to_vec()), vec![0x60]);
    }
}
