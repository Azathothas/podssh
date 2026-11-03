//! The stack's driver (T-599): packets in that smoltcp leaves while the
//! queue out is full are read once it has room again, with no new packet
//! and no timer of TCP to wake the driver for them.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};
use tokio::sync::mpsc;

use crate::phy::MAX_OUT;
use crate::stack::{Link, Stack, Why};

const DEVICE: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 2);
const FAR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// A SYN from FAR's `port` to a port of the device that no socket holds:
/// smoltcp answers each with a RST, one packet out for each packet in.
fn syn(port: u16) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: port,
        dst_port: 22,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: FAR,
        dst_addr: DEVICE,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let caps = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; 20 + tcp.buffer_len()];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.emit(&mut packet, &caps);
    let mut segment = TcpPacket::new_unchecked(packet.payload_mut());
    tcp.emit(&mut segment, &IpAddress::Ipv4(FAR), &IpAddress::Ipv4(DEVICE), &caps);
    bytes
}

/// Whether `packet` is a RST of TCP to FAR.
fn is_reset(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else { return false };
    if ip.dst_addr() != FAR || ip.next_header() != IpProtocol::Tcp {
        return false;
    }
    TcpPacket::new_checked(ip.payload()).is_ok_and(|tcp| tcp.rst())
}

/// Three queues out's worth of SYNs, each in the stack before it polls:
/// a RST comes for each, within a second, where a driver that slept with
/// packets in left all but the first queue's worth for a minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packets_left_while_the_queue_out_was_full_are_read_once_it_has_room() {
    const SENT: usize = 3 * MAX_OUT + 8;
    let (to_stack, inbound) = mpsc::channel(SENT);
    let (out, mut from_stack) = mpsc::channel(SENT);
    for port in 0..SENT {
        to_stack.try_send(syn(40_000 + port as u16)).unwrap();
    }
    let link = Link { out, inbound, why: Why::default(), tasks: Vec::new() };
    let _stack = Stack::start(&[IpAddr::V4(DEVICE)], link).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut resets = 0;
    while resets < SENT {
        match tokio::time::timeout_at(deadline, from_stack.recv()).await {
            Ok(Some(packet)) => resets += usize::from(is_reset(&packet)),
            Ok(None) | Err(_) => break,
        }
    }
    assert_eq!(resets, SENT, "a RST for each SYN within 5 s");
    // The sender stays until here: its end would wake the driver too.
    drop(to_stack);
}
