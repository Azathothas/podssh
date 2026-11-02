//! One TLS configuration for each trust in a process (T-444): rustls keeps
//! its cache of sessions in the configuration, so the second connection of a
//! trust resumes TLS, as the server's side says; a session that one trust
//! verified is never resumed under another; and a CA file is read again only
//! when it changed. The server is rustls's own, with its own cache of
//! sessions, which podssh did not write.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls::{config_for, connect_over, Trust};
use rustls::HandshakeKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "resume.podssh.test";
const LIMIT: Duration = Duration::from_secs(10);

/// The root of the server's certificate for [`NAME`], in a file of its own
/// under `tag`: its key comes from its name, so the root minted again is the
/// server's.
fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-tls-resume-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory for the root");
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).expect("the root is written");
    path
}

/// A server for [`NAME`] on the loopback that takes `count` connections in
/// turn, each with a byte after its handshake, which the client reads after
/// the tickets that rustls sends at the handshake's end; then it waits for
/// the client's end. It gives how each handshake went.
async fn server(count: usize) -> (SocketAddr, JoinHandle<Vec<Option<HandshakeKind>>>) {
    let (acceptor, _) = cert::server_for(NAME).expect("a server for the name");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("an address");
    let task = tokio::spawn(async move {
        let mut kinds = Vec::new();
        for _ in 0..count {
            let Ok((stream, _)) = listener.accept().await else { break };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                kinds.push(None);
                continue;
            };
            kinds.push(tls.get_ref().1.handshake_kind());
            let _ = tls.write_all(b"x").await;
            let _ = tls.flush().await;
            let mut rest = Vec::new();
            let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut rest)).await;
        }
        kinds
    });
    (addr, task)
}

/// One connection through `trust`: the handshake, the server's byte, and the
/// end.
async fn connect(addr: SocketAddr, trust: &Trust) {
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let mut tls = connect_over(tcp, NAME, trust, LIMIT).await.expect("the handshake");
    let mut byte = [0u8; 1];
    tokio::time::timeout(LIMIT, tls.read_exact(&mut byte)).await.expect("the byte in time").expect("the byte");
    let _ = tls.shutdown().await;
}

async fn kinds(served: JoinHandle<Vec<Option<HandshakeKind>>>) -> Vec<Option<HandshakeKind>> {
    tokio::time::timeout(LIMIT, served).await.expect("the server in time").expect("the server")
}

#[tokio::test]
async fn the_second_connection_of_a_trust_resumes_tls() {
    let trust = Trust::File(root_file("same"));
    let (addr, served) = server(2).await;
    connect(addr, &trust).await;
    connect(addr, &trust).await;
    let kinds = kinds(served).await;
    assert_eq!(
        kinds,
        vec![Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)],
        "a configuration made again for the second connection resumes nothing"
    );
}

/// A resumed handshake checks no certificate, so a session is resumed under
/// the trust that verified it alone: the same root in another file is
/// another trust, and its handshake is whole.
#[tokio::test]
async fn another_trust_does_not_resume_the_session_of_the_first() {
    let (one, other) = (Trust::File(root_file("one")), Trust::File(root_file("other")));
    let (addr, served) = server(2).await;
    connect(addr, &one).await;
    connect(addr, &other).await;
    assert_eq!(kinds(served).await, vec![Some(HandshakeKind::Full), Some(HandshakeKind::Full)]);
}

/// A trust's configuration is made once, and its CA file read once; another
/// trust has its own; a file that changed is read again.
#[test]
fn a_trust_keeps_one_configuration_until_its_file_changes() {
    let path = root_file("changed");
    let trust = Trust::File(path.clone());
    let first = config_for(&trust).expect("a configuration");
    assert!(Arc::ptr_eq(&first, &config_for(&trust).unwrap()), "one configuration for the trust");
    let beside = config_for(&Trust::File(root_file("beside"))).unwrap();
    assert!(!Arc::ptr_eq(&first, &beside), "another trust, another configuration");
    assert!(Arc::ptr_eq(&config_for(&Trust::Default).unwrap(), &config_for(&Trust::Default).unwrap()));
    // The same root and a line more: another length.
    let mut text = std::fs::read(&path).unwrap();
    text.extend_from_slice(b"\n");
    std::fs::write(&path, text).unwrap();
    let again = config_for(&trust).expect("the file read again");
    assert!(!Arc::ptr_eq(&first, &again), "a file that changed is read again");
    assert!(Arc::ptr_eq(&again, &config_for(&trust).unwrap()), "and kept again");
}
