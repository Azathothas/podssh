//! The probe of UDP before the quick tunnel's QUIC (T-400), against stand-ins
//! of the edge's port on the loopback: one that answers each packet with a
//! Version Negotiation of 27 bytes, as cfrs's testers saw the edge answer
//! (its Source the packet's Destination, three versions); one that answers
//! with another id, which answers no packet of the probe's; and a closed
//! port, whose refusal comes at once on Linux.
#![cfg(feature = "quick")]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use podssh_relay::quick::probe;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// A stand-in of the edge's port: for each packet, a Version Negotiation
/// whose Source is the packet's Destination, or, `astray`, another id.
async fn negotiating(astray: bool) -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut packet = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut packet).await {
            if n < 14 {
                continue;
            }
            // The long form and the version 0; no Destination, as the probe
            // sends no Source; its Destination of 8 bytes as the Source.
            let mut answer = vec![0x80, 0, 0, 0, 0, 0, 8];
            answer.extend_from_slice(&packet[6..14]);
            if astray {
                answer[7] ^= 0xff;
            }
            answer.extend_from_slice(&[0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0xff, 0, 0, 0x1d]);
            assert_eq!(answer.len(), 27);
            let _ = socket.send_to(&answer, from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probe_takes_a_version_negotiation_of_its_packet_and_no_other_answer() {
    let edge = negotiating(false).await;
    let (answered, took) = probe::probe(&[edge], probe::WAIT).await.expect("the edge's answer");
    assert_eq!(answered, edge);
    assert!(took < probe::WAIT, "{took:?}");
    let astray = negotiating(true).await;
    let started = Instant::now();
    let why = probe::probe(&[astray], probe::WAIT).await.expect_err("an answer to another packet");
    assert!(why.contains(&format!("{astray} said nothing within 300 ms")), "{why}");
    assert!(started.elapsed() < probe::WAIT + Duration::from_millis(200), "{:?}", started.elapsed());
    // Both at once, as the node probes each family: the one that answers.
    let (answered, _) = probe::probe(&[astray, edge], probe::WAIT).await.expect("one answer");
    assert_eq!(answered, edge);
}

/// A port with nothing on it: the system's refusal (ICMP) comes back on the
/// connected socket, before the wait.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_port_is_said_at_once() {
    let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap();
    let started = Instant::now();
    let why = probe::probe(&[closed], probe::WAIT).await.expect_err("a closed port");
    assert!(started.elapsed() < probe::WAIT, "{:?}", started.elapsed());
    assert!(why.contains(&closed.to_string()) && why.contains("refused"), "{why}");
}
