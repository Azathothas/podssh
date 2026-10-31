//! A server of pkarr on the loopback, for the tests of this crate and of the
//! command line (feature `test-relay`; never in a release): pkarr's relay
//! API, `PUT` and `GET` of `/pkarr/KEY` with KEY in z-base-32, over HTTPS
//! with a self-signed certificate for `localhost`, in a PEM file that
//! podssh's trust store takes. A `PUT` is read with iroh's own reading of a
//! signed packet, as iroh's test server of pkarr reads one, so a record that
//! podssh signs wrong is refused there by code that podssh did not write;
//! and a newer record wins, as pkarr's relays keep the newest (409 for an
//! older one).

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use iroh::PublicKey;
use iroh_dns::pkarr::SignedPacket;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Each key's record, as a server keeps the payload of a `PUT`.
type Records = Arc<Mutex<HashMap<PublicKey, Vec<u8>>>>;

/// The bound on a request's head and on its body.
const MAX_REQUEST: usize = 16 * 1024;

/// The header of a record's answer, as pkarr's relays send it.
const PAYLOAD_TYPE: &str = "Content-Type: application/pkarr.org/relays#payload\r\n";

/// A running server; it stops when this is dropped.
pub struct TestPkarr {
    /// `https://localhost:PORT/pkarr`, as the variable of the server takes it.
    pub url: url::Url,
    /// The server's certificate, as `--ca-file` and `SSL_CERT_FILE` take it.
    pub cert: PathBuf,
    /// The same certificate's DER, for a client of iroh's own.
    pub der: Vec<u8>,
    records: Records,
    asked: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for TestPkarr {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestPkarr {
    /// Keep `payload` under `key` with no check, as a server that forged a
    /// record would serve it.
    pub fn plant(&self, key: &PublicKey, payload: Vec<u8>) {
        lock(&self.records).insert(*key, payload);
    }

    /// The payload kept under `key`.
    pub fn payload(&self, key: &PublicKey) -> Option<Vec<u8>> {
        lock(&self.records).get(key).cloned()
    }

    /// How many requests the server answered.
    pub fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

/// A server on the loopback, with its certificate written into `dir`.
pub async fn spawn(dir: &Path) -> io::Result<TestPkarr> {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    let der = made.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(made.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![made.cert.der().clone()], key.into())
        .map_err(io::Error::other)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let url: url::Url = format!("https://localhost:{port}/pkarr").parse().map_err(io::Error::other)?;
    let cert = dir.join("pkarr-cert-localhost.pem");
    std::fs::write(&cert, crate::test_relay::pem(&der))?;
    let (records, asked) = (Records::default(), Arc::new(AtomicUsize::new(0)));
    let task = tokio::spawn(serve(listener, acceptor, records.clone(), asked.clone()));
    Ok(TestPkarr { url, cert, der, records, asked, task })
}

/// Each connection: one request, its answer, and the end, as podssh asks
/// with `Connection: close`; iroh's client opens another for its next.
async fn serve(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor, records: Records, asked: Arc<AtomicUsize>) {
    while let Ok((tcp, _)) = listener.accept().await {
        let (acceptor, records, asked) = (acceptor.clone(), records.clone(), asked.clone());
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else { return };
            let Ok(Some(request)) = read_request(&mut tls).await else { return };
            asked.fetch_add(1, Ordering::SeqCst);
            let (status, body) = answer(&records, &request);
            // pkarr's type of a record's payload, on a record alone.
            let kind = if status.starts_with("200") { PAYLOAD_TYPE } else { "" };
            let length = body.len();
            let head = format!("HTTP/1.1 {status}\r\n{kind}Content-Length: {length}\r\nConnection: close\r\n\r\n");
            let _ = tls.write_all(head.as_bytes()).await;
            let _ = tls.write_all(&body).await;
            let _ = tls.shutdown().await;
        });
    }
}

/// A request: its method, its path and its body.
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// The request on `stream`; none for one that ends early or is too long.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<Request>> {
    let mut have = Vec::new();
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(at) = have.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if have.len() > MAX_REQUEST {
            return Ok(None);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        have.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&have[..end]).into_owned();
    let mut words = head.lines().next().unwrap_or_default().split(' ');
    let method = words.next().unwrap_or_default().to_string();
    let path = words.next().unwrap_or_default().to_string();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if length > MAX_REQUEST {
        return Ok(None);
    }
    let mut body = have[end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(Some(Request { method, path, body }))
}

/// The status and the body of the answer to `request`.
fn answer(records: &Records, request: &Request) -> (&'static str, Vec<u8>) {
    let Some(z32) = request.path.strip_prefix("/pkarr/") else { return ("404 Not Found", Vec::new()) };
    let Ok(key) = PublicKey::from_z32(z32) else { return ("400 Bad Request", b"not a key".to_vec()) };
    let mut records = lock(records);
    match request.method.as_str() {
        "GET" => match records.get(&key) {
            Some(payload) => ("200 OK", payload.clone()),
            None => ("404 Not Found", Vec::new()),
        },
        "PUT" => {
            let new = match SignedPacket::from_relay_payload(&key, &request.body) {
                Ok(new) => new,
                Err(e) => return ("400 Bad Request", e.to_string().into_bytes()),
            };
            let kept = records.get(&key).and_then(|payload| SignedPacket::from_relay_payload(&key, payload).ok());
            if kept.is_some_and(|kept| kept.more_recent_than(&new)) {
                return ("409 Conflict", b"a newer record is kept".to_vec());
            }
            records.insert(key, request.body.clone());
            ("204 No Content", Vec::new())
        }
        _ => ("405 Method Not Allowed", Vec::new()),
    }
}

/// The value behind `mutex`, also after a panic elsewhere.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
