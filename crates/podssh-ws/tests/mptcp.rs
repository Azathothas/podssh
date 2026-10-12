//! Multipath TCP on the direct road (T-172). Asked for where the kernel
//! refuses it, the connection is plain TCP and carries the same bytes: a
//! dial that failed instead fails here. The direct dial that asks for it
//! carries the same bytes on each host, as MPTCP where the host offers it
//! and else as plain TCP with the probe's reason. Where the host offers
//! MPTCP (Linux, with `/proc/sys/net/mptcp/enabled` at 1), a socket of MPTCP
//! to a listener of MPTCP carries them too; elsewhere that test says that
//! it did not run. The live test asks the relay's edge for MPTCP, and says
//! whether it took it; it runs by hand, on Linux (`--ignored`).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use podssh_ws::dial::{dial_multipath, ProxyChoice};
use podssh_ws::mptcp::{self, Multipath};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const SENT: &[u8] = b"the same bytes on either kind of socket";

/// One connection of `listener`: what it reads, it sends back.
fn echo(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => sock.write_all(&buf[..n]).await.unwrap(),
            }
        }
    })
}

/// An echo server on the loopback, of plain TCP.
async fn plain_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr, echo(listener))
}

/// Send [`SENT`], and read as much back, within 10 s.
async fn there_and_back(stream: &mut TcpStream) -> Vec<u8> {
    stream.write_all(SENT).await.unwrap();
    let mut back = vec![0u8; SENT.len()];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back));
    read.await.expect("the echo within 10 s").unwrap();
    back
}

/// The kernel's refusal, planted: the protocol is not supported.
fn refused(_: &SocketAddr) -> io::Result<TcpSocket> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Protocol not supported (planted)"))
}

#[tokio::test]
async fn a_refused_mptcp_socket_gives_plain_tcp_with_the_same_bytes() {
    let (addr, server) = plain_echo().await;
    let (mut stream, how) = mptcp::connect_with(addr, Ok(()), refused).await.expect("plain TCP, not a failure");
    match &how {
        Multipath::Plain(why) => assert!(why.contains("planted"), "{why}"),
        other => panic!("plain TCP was expected: {other:?}"),
    }
    assert_eq!(there_and_back(&mut stream).await, SENT);
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn a_host_that_offers_no_mptcp_gives_plain_tcp_and_the_probe_s_reason() {
    let (addr, server) = plain_echo().await;
    let offer = Err("no Multipath TCP here (planted)".to_string());
    let (mut stream, how) = mptcp::connect_with(addr, offer, mptcp::socket).await.expect("plain TCP");
    assert_eq!(how, Multipath::Plain("no Multipath TCP here (planted)".into()));
    assert_eq!(there_and_back(&mut stream).await, SENT);
    drop(stream);
    server.await.unwrap();
}

/// The dial of `--direct` with Multipath TCP asked for, on each host.
#[tokio::test]
async fn the_direct_dial_that_asks_for_mptcp_carries_the_same_bytes() {
    let (addr, server) = plain_echo().await;
    let dialled = dial_multipath("127.0.0.1", addr.port(), &ProxyChoice::Direct, Duration::from_secs(5)).await;
    let (mut stream, how) = dialled.expect("a direct connection");
    match (mptcp::probe(), &how) {
        (Err(why), _) => assert_eq!(how, Multipath::Plain(why)),
        // A listener of plain TCP: the kernel falls back, where it says so.
        (Ok(()), Multipath::Mptcp { server }) => assert_ne!(*server, Some(true), "{how}"),
        // A sandbox may refuse the protocol while the switch is on.
        (Ok(()), Multipath::Plain(why)) => assert!(why.contains("refused"), "{why}"),
    }
    eprintln!("the direct dial: {how}");
    assert_eq!(there_and_back(&mut stream).await, SENT);
    drop(stream);
    server.await.unwrap();
}

/// Both ends of MPTCP on the loopback, where the host offers it.
#[tokio::test]
async fn a_socket_of_mptcp_carries_the_bytes_where_the_host_offers_one() {
    if let Err(why) = mptcp::probe() {
        eprintln!("did not run: {why}");
        return;
    }
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket = match mptcp::socket(&any) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("did not run: the kernel refused a socket of Multipath TCP: {e}");
            return;
        }
    };
    socket.bind(any).unwrap();
    let listener = socket.listen(4).unwrap();
    let addr = listener.local_addr().unwrap();
    let echoing = echo(listener);
    let (mut stream, how) = mptcp::connect(addr, Ok(())).await.expect("a connection");
    eprintln!("both ends of MPTCP: {how}");
    match how {
        // Linux 5.16 and later say whether the server took it; it did.
        Multipath::Mptcp { server } => assert_ne!(server, Some(false), "the listener of MPTCP fell back"),
        Multipath::Plain(why) => panic!("the socket was made above, and the connect was plain: {why}"),
    }
    assert_eq!(there_and_back(&mut stream).await, SENT);
    drop(stream);
    echoing.await.unwrap();
}

/// Whether the edge of the relay takes MPTCP (T-172, step 4): one direct
/// connection to the relay's port 443, asked for MPTCP. It asserts only the
/// connection; the answer is printed, for docs/design.md.
#[tokio::test]
#[ignore = "live: the relay's edge, from a Linux host that offers Multipath TCP"]
async fn live_the_relay_s_edge_answers_a_socket_of_mptcp() {
    if let Err(why) = mptcp::probe() {
        eprintln!("did not run: {why}");
        return;
    }
    let host = "tcp.ssh.relay.ajam.dev";
    let dialled = dial_multipath(host, 443, &ProxyChoice::Direct, Duration::from_secs(20)).await;
    let (_stream, how) = dialled.expect("a direct connection to the relay");
    eprintln!("{host}:443: {how}");
}
