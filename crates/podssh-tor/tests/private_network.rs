//! The Tor road against a Tor network of C tor on the loopback (T-353),
//! software that podssh did not write: chutney's network `basic-min`,
//! whose arti-client configuration (`arti.toml`) `PODSSH_TEST_TOR_NETWORK`
//! names (`scripts/tor-net.sh` starts it). Arti bootstraps from its
//! authorities with each first hop through a stand-in proxy, and a stream
//! through its exit reaches a service on the loopback. With no network the
//! test says so and passes, as each test of another program's server does
//! where that program is missing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_tor::{Options, Tor};
use podssh_ws::dial::ProxyChoice;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const NETWORK_ENV: &str = "PODSSH_TEST_TOR_NETWORK";

/// A proxy of HTTP CONNECT on the loopback that carries each connection
/// and keeps the target of each CONNECT.
async fn proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut client = BufReader::new(client);
                let mut line = String::new();
                if client.read_line(&mut line).await.is_err() {
                    return;
                }
                let target = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                loop {
                    let mut header = String::new();
                    match client.read_line(&mut header).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) if header == "\r\n" => break,
                        Ok(_) => {}
                    }
                }
                seen.lock().unwrap().push(target.clone());
                let Ok(mut far) = TcpStream::connect(&target).await else {
                    let _ = client.get_mut().write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let mut client = client.into_inner();
                if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut far).await;
                }
            });
        }
    });
    (port, asked)
}

/// A service on the loopback that greets each client.
async fn target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"target says hi\n").await;
        }
    });
    port
}

/// Arti bootstraps in the private network with each first hop through the
/// proxy, and a stream through its exit reaches the service; the proxy saw
/// the relays, by their addresses, and never the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_through_a_private_network_reaches_the_service() {
    let Some(file) = std::env::var_os(NETWORK_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{NETWORK_ENV} is not set: no private Tor network, nothing to test (scripts/tor-net.sh)");
        return;
    };
    let network = std::fs::read_to_string(&file).unwrap();
    let _ = podssh_ws::crypto::provider().install_default();
    let (proxy_port, asked) = proxy().await;
    let service = target().await;
    let home = std::env::temp_dir().join(format!("podssh-tor-private-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let options = Options {
        state_dir: home.join("state"),
        cache_dir: home.join("cache"),
        proxy: ProxyChoice::Via(podssh_ws::proxy::Proxy::parse(&format!("http://127.0.0.1:{proxy_port}")).unwrap()),
        // chutney's relays listen on ports from 5000 up.
        first_hop_ports: None,
        trust_directories: true,
        network: Some(network),
    };
    let tor = Tor::bootstrap(&options, Duration::from_secs(120)).await.unwrap_or_else(|f| panic!("{f}"));
    let mut stream = tor.connect("127.0.0.1", service, Duration::from_secs(60)).await.unwrap_or_else(|f| panic!("{f}"));
    let mut greeting = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut greeting)).await.unwrap().unwrap();
    assert_eq!(&greeting, b"target says hi\n");
    let asked = asked.lock().unwrap().clone();
    assert!(!asked.is_empty(), "no first hop went through the proxy");
    let literal = |t: &String| t.parse::<std::net::SocketAddr>().is_ok();
    assert!(asked.iter().all(literal), "a relay asked by a name: {asked:?}");
    let service_at = format!("127.0.0.1:{service}");
    assert!(!asked.contains(&service_at), "the service was reached through the proxy, not Tor: {asked:?}");
    let _ = std::fs::remove_dir_all(&home);
}
