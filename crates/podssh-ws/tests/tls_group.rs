//! The group that a TLS server took, kept across runs (T-664): a server that
//! takes P-256 alone answers podssh's first offer, X25519, with a
//! HelloRetryRequest; a later run, with a configuration of its own whose
//! groups come from the file that the first run kept, offers P-256 at once,
//! and the server's side says that no retry came. The server is rustls's
//! own; each run's configuration is new, so no ticket resumes it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::crypto::kx::SECP256R1;
use podssh_ws::tls::groups::{GroupFile, Kept};
use podssh_ws::tls::{client_config_keeping, TlsRoots};
use rustls::{ClientConfig, HandshakeKind, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "group.podssh.test";
const LIMIT: Duration = Duration::from_secs(10);

/// A file of the test's memory, as the cache keeps one between runs.
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Option<String>>>);

impl GroupFile for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

/// One run: groups of its own over `file`, and a configuration made for it.
fn run(file: &Memory, roots: &RootCertStore) -> (Arc<ClientConfig>, Arc<Kept>) {
    let kept = Arc::new(Kept::new());
    assert!(kept.keep_in(Box::new(file.clone())));
    let roots = TlsRoots { roots: roots.clone(), source: "the test's root".into(), count: roots.len() };
    let config = client_config_keeping(&roots, podssh_ws::crypto::provider(), kept.clone()).expect("a configuration");
    (config, kept)
}

/// A server for [`NAME`] that takes P-256 alone, for `count` connections in
/// turn, each with a byte after its handshake: how each handshake went.
async fn server(count: usize) -> (SocketAddr, RootCertStore, JoinHandle<Vec<Option<HandshakeKind>>>) {
    let (acceptor, roots) = cert::server::server_for_groups(NAME, Some(vec![SECP256R1])).expect("a server");
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
    (addr, roots, task)
}

/// One connection with `config`: the handshake, the server's byte, the end.
async fn connect(addr: SocketAddr, config: Arc<ClientConfig>) {
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let name = rustls_pki_types::ServerName::try_from(NAME.to_string()).expect("a name");
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = tokio::time::timeout(LIMIT, connector.connect(name, tcp)).await.expect("in time").expect("TLS");
    let mut byte = [0u8; 1];
    tokio::time::timeout(LIMIT, tls.read_exact(&mut byte)).await.expect("the byte in time").expect("the byte");
    let _ = tls.shutdown().await;
}

async fn kinds(served: JoinHandle<Vec<Option<HandshakeKind>>>) -> Vec<Option<HandshakeKind>> {
    tokio::time::timeout(LIMIT, served).await.expect("the server in time").expect("the server")
}

#[tokio::test]
async fn a_later_run_offers_the_group_that_the_server_took() {
    let (addr, roots, served) = server(2).await;
    let file = Memory::default();
    connect(addr, run(&file, &roots).0).await;
    let kept = file.load().expect("the group is kept");
    assert!(kept.contains(&format!("{NAME} 23 ")), "{kept}");
    connect(addr, run(&file, &roots).0).await;
    assert_eq!(
        kinds(served).await,
        vec![Some(HandshakeKind::FullWithHelloRetryRequest), Some(HandshakeKind::Full)],
        "a later run that does not read the group offers X25519 again, and the server asks for P-256 again"
    );
}

/// The control: runs with no file between them retry each time.
#[tokio::test]
async fn runs_with_no_file_between_them_retry_each_time() {
    let (addr, roots, served) = server(2).await;
    connect(addr, run(&Memory::default(), &roots).0).await;
    connect(addr, run(&Memory::default(), &roots).0).await;
    assert_eq!(
        kinds(served).await,
        vec![Some(HandshakeKind::FullWithHelloRetryRequest), Some(HandshakeKind::FullWithHelloRetryRequest)]
    );
}

/// A file that does not read is set aside, said once, and made again: the
/// run connects as with no file.
#[tokio::test]
async fn a_file_that_does_not_read_is_set_aside() {
    let (addr, roots, served) = server(1).await;
    let file = Memory(Arc::new(Mutex::new(Some("podssh tls groups 1\nno fields\n".into()))));
    let (config, kept) = run(&file, &roots);
    connect(addr, config).await;
    assert_eq!(kinds(served).await, vec![Some(HandshakeKind::FullWithHelloRetryRequest)]);
    let note = kept.take_note().expect("the note of -v");
    assert!(note.contains("set aside") && note.contains("line 2"), "{note}");
    let made = file.load().expect("the file");
    assert!(made.starts_with("podssh tls groups 1\n") && made.contains(NAME), "{made}");
}
