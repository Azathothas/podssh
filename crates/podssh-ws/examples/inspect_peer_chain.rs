//! ⛔ **A one-off probe, run once, to read the live relay's certificate
//! chain.** ⛔ It is NOT a test: it prints, it asserts nothing, and it is
//! excluded from the suite by living in `examples/`. The question it answers
//! is "which curve and which signature algorithm does the relay actually
//! present", and the answer decides whether E03's provider is complete.
//!
//! Run with:  cargo run -p podssh-ws --example inspect_peer_chain

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let host = "tcp.ssh.relay.ajam.dev";
    let addr = format!("{host}:443")
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("an address");

    let roots = podssh_ws::tls::roots_from_compiled_set();
    let config = podssh_ws::tls::client_config(&roots).expect("a config");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = rustls_pki_types::ServerName::try_from(host.to_string()).expect("a name");

    // ⛔ `dangerous` is used here deliberately and ONLY here: this probe wants
    // to see the peer's chain precisely because podssh's own verifier refuses
    // it. Nothing in the shipped path uses this.
    let mut cfg = (*config).clone();
    cfg.dangerous().set_certificate_verifier(Arc::new(podssh_ws::probe::PrintChain));

    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    match connector.connect(name, tcp).await {
        Ok(tls) => {
            let (_, session) = tls.get_ref();
            println!("handshake OK with a permissive verifier");
            println!("suite: {:?}", session.negotiated_cipher_suite().map(|s| s.suite()));
            if let Some(certs) = session.peer_certificates() {
                for (i, c) in certs.iter().enumerate() {
                    println!("cert {i}: {} bytes", c.as_ref().len());
                }
            }
        }
        Err(e) => println!("handshake failed even with a permissive verifier: {e}"),
    }
}

use std::net::ToSocketAddrs as _;
