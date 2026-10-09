//! Whether this host lets a UDP socket bind. A sandbox can refuse UDP
//! (`docs/target-environment.md`), and iroh's endpoint does not start when
//! its UDP bind is required and fails, so the iroh road asks first and runs
//! on the relay alone when the answer is no (rule 1 of `AGENTS.md`).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Bind a UDP socket to port 0 of each address, and close it at once: the
/// address that the system gave, or why it refused. Nothing is sent, and
/// nothing listens.
pub fn udp() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.local_addr()
}
