//! The road from end to end on the loopback: the client against the
//! stand-in edge, whose TLS is rustls's server, whose HTTP/2 is h2's
//! server, and whose far end is smoltcp, software that podssh did not
//! write; the registration against a stand-in of the API; the proxies of a
//! cage, each as a test of its own; and a front door that changes its key
//! (T-399). Nothing here writes a file.

mod api;
mod edge;
mod proxies;
mod rotated_key;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// The bound on each wait of a test.
pub(crate) const LIMIT: Duration = Duration::from_secs(20);

/// An echo service on the loopback: each connection's bytes back, then its
/// end.
pub(crate) async fn echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// A resolver of DNS over TCP on the loopback that answers each question
/// of type A with `v4`, and each other with no record (RFC 1035's form, by
/// hand: the parser under test is podssh-ws's, measured against resolvers
/// of the Internet in T-344).
pub(crate) async fn resolver(v4: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if tcp.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if tcp.read_exact(&mut query).await.is_err() {
                    return;
                }
                let answer = answer(&query, v4);
                let framed = [(answer.len() as u16).to_be_bytes().to_vec(), answer].concat();
                let _ = tcp.write_all(&framed).await;
            });
        }
    });
    addr
}

/// The answer to `query`: its ID and question, and for type A one record
/// of `v4` behind a pointer to the question's name.
fn answer(query: &[u8], v4: Ipv4Addr) -> Vec<u8> {
    let question = &query[12..];
    let kind = u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    let records = u16::from(kind == 1);
    let mut out = query[..2].to_vec();
    out.extend_from_slice(&[0x81, 0x80, 0, 1]);
    out.extend_from_slice(&records.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    if records == 1 {
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        out.extend_from_slice(&v4.octets());
    }
    out
}
