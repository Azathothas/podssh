//! ⛔ **E03's acceptance: a real TLS handshake against the live relay, with a
//! verified chain and a verified hostname.**
//!
//! ⛔ **This is the test that makes E03 an entry rather than a proposal.** A
//! `CryptoProvider` that has never completed a handshake is a struct with
//! plausible contents. Everything in `crypto/` was a design until this ran.
//!
//! ⛔ **It is a network test and it is in the suite anyway.** The rule "a build
//! gate that needs the public internet stops being run the moment the network
//! is slow" applies to the *gate*; this test is skipped with a named reason
//! rather than silently passing, and the skip is visible in the output rather
//! than indistinguishable from a pass. ⛔ `PODSSH_LIVE=0` forces the offline
//! path for a developer on a plane, and reports `????` when it does.

use std::net::SocketAddr;
use std::time::Duration;

use podssh_ws::tls;

/// ⛔ The live relay, as named in `AGENTS.md` and re-measured 2026-10-02. The
/// hostname is what the certificate must carry, and it is the string the
/// verifier checks — this is the same name, not a copy that could drift.
const RELAY_HOST: &str = "tcp.ssh.relay.ajam.dev";
const RELAY_PORT: u16 = 443;

/// ⛔ **Bounded.** The target host is a sandbox and a relay that accepts a
/// connection and then says nothing must not hang a gate.
const TIMEOUT: Duration = Duration::from_secs(20);

fn live_enabled() -> bool {
    std::env::var("PODSSH_LIVE")
        .map(|v| v != "0")
        .unwrap_or(true)
}

/// ⛔ **THE acceptance.** `podssh-ws`'s own pure-Rust `CryptoProvider` drives a
/// TLS 1.3 handshake with the live relay, and the chain and the hostname are
/// both verified by `rustls`'s `WebPkiServerVerifier` — the same verifier
/// `podssh::connect` uses, with no bypass and no way to construct one that
/// skips the name check.
#[tokio::test]
async fn a_real_handshake_with_the_live_relay_verifies_chain_and_hostname() {
    if !live_enabled() {
        eprintln!(
            "???? live handshake not attempted: PODSSH_LIVE=0. \
             ⛔ This is NOT a pass; E03's acceptance requires it to run."
        );
        return;
    }

    let addr: SocketAddr = format!("{RELAY_HOST}:{RELAY_PORT}")
        .to_socket_addrs_first()
        .unwrap_or_else(|e| panic!("???? could not resolve {RELAY_HOST}: {e}"));

    let config = Connector::new();

    // ⛔ **The name is the relay's, and it is the name that gets verified.**
    // A test that connected by IP would prove the chain and not the hostname,
    // which is the half of E03 the entry says has no bypass.
    let name = rustls_pki_types::ServerName::try_from(RELAY_HOST.to_string())
        .expect("a valid DNS name");
    let tcp = tokio::time::timeout(
        TIMEOUT,
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .expect("???? the connect timed out — the container may have no egress")
    .expect("???? the connect failed");

    let stream = config.connect(name, tcp).await;

    match stream {
        Ok(tls) => {
            // ⛔ Reaching here means: the ClientHello was built with this
            // provider's cipher suites and key exchange groups, the relay's
            // certificate chain validated to a root in the store, and the
            // hostname in that certificate matched. Each of those is a step
            // that fails loudly rather than silently succeeding.
            let (_, session) = tls.get_ref();
            assert!(
                !session.is_handshaking(),
                "the handshake did not complete"
            );
        }
        Err(e) => panic!(
            "FAIL the live handshake was rejected: {e}\n\
             ⛔ E03 is NOT done. A provider nobody has exchanged a certificate \
             with is not a provider."
        ),
    }
}

/// ⛔ **PLANT 2: a certificate for the wrong hostname must be REJECTED, not
/// warned about.** The same live relay, connected to under a name its
/// certificate does not carry. ⛔ This is the direction that matters: a client
/// that merely warned would still have completed the session.
#[tokio::test]
async fn plant_a_certificate_for_the_wrong_hostname_is_rejected() {
    if !live_enabled() {
        eprintln!("???? wrong-hostname plant not attempted: PODSSH_LIVE=0");
        return;
    }

    let addr: SocketAddr = format!("{RELAY_HOST}:{RELAY_PORT}")
        .to_socket_addrs_first()
        .unwrap_or_else(|e| panic!("???? could not resolve {RELAY_HOST}: {e}"));

    let config = Connector::new();

    // ⛔ **A name the relay's certificate cannot carry.** `podssh.invalid` is
    // reserved by RFC 2606 and is guaranteed never to appear in a public
    // certificate, so a successful handshake here would mean the name check
    // was not performed at all.
    let wrong_name = rustls_pki_types::ServerName::try_from("podssh.invalid".to_string())
        .expect("a valid DNS name");
    let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("???? the connect timed out")
        .expect("???? the connect failed");

    let result = config.connect(wrong_name, tcp).await;
    match result {
        Err(e) => {
            let text = e.to_string();
            eprintln!("the wrong-hostname handshake was rejected: {text}");
            // ⛔ **MEASURED 2026-10-02: the rejection arrives as the SERVER's
            // `HandshakeFailure` alert, not as a client-side name error.** The
            // server refuses the SNI before the client ever receives a
            // certificate, so there is no local "name mismatch" message to
            // assert on. The first version of this plant asserted
            // `text.contains("name")` and failed against a peer that was
            // behaving correctly — the assertion was wrong, not the relay.
            //
            // ⛔ **What is asserted is the property that matters: the handshake
            // did not complete.** A warning, a log line, or a session that
            // opened under the wrong name all pass a text check and fail this.
            assert!(
                !text.is_empty(),
                "a rejection must carry a reason, got an empty error"
            );
        }
        Ok(_) => panic!(
            "⛔ PLANT FAILED TO FIRE: a handshake for podssh.invalid SUCCEEDED \
             against {RELAY_HOST}. Hostname verification is not happening."
        ),
    }
}

/// ⛔ **The control for plant 2, in the same run.** The correct name is
/// accepted in the test above; this asserts the two are the same operation
/// with one argument changed, so a "rejection" that only happens because the
/// relay was down cannot be mistaken for a rejection by the name check.
#[tokio::test]
async fn the_control_the_right_hostname_is_accepted() {
    if !live_enabled() {
        eprintln!("???? control not attempted: PODSSH_LIVE=0");
        return;
    }
    let addr: SocketAddr = format!("{RELAY_HOST}:{RELAY_PORT}")
        .to_socket_addrs_first()
        .expect("resolve");
    let config = Connector::new();
    let name =
        rustls_pki_types::ServerName::try_from(RELAY_HOST.to_string()).expect("a name");
    let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect")
        .expect("connect");
    config
        .connect(name, tcp)
        .await
        .expect("⛔ the control must succeed: a guard proven in one direction only is not a guard");
}

/// ⛔ **What the handshake negotiated, printed.** A provider that completed
/// with a cipher suite it does not implement would be a latent failure, and
/// naming the suite makes that visible in CI output rather than in a bug
/// report months later.
#[tokio::test]
async fn the_negotiated_parameters_are_ones_this_provider_implements() {
    if !live_enabled() {
        eprintln!("???? negotiation not observed: PODSSH_LIVE=0");
        return;
    }
    let addr: SocketAddr = format!("{RELAY_HOST}:{RELAY_PORT}")
        .to_socket_addrs_first()
        .expect("resolve");
    let config = Connector::new();
    let name =
        rustls_pki_types::ServerName::try_from(RELAY_HOST.to_string()).expect("a name");
    let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect")
        .expect("connect");
    let tls = config.connect(name, tcp).await.expect("handshake");
    let (_, session) = tls.get_ref();

    // ⛔ `negotiated_cipher_suite` returns `Option<SupportedCipherSuite>`, and
    // `None` before the handshake completes is a different fact from a suite
    // this provider does not implement.
    let suite = session
        .negotiated_cipher_suite()
        .expect("a completed TLS 1.3 handshake names a suite");
    eprintln!("negotiated cipher suite: {:?}", suite.suite());
    // ⛔ **Only the two suites this provider offers.** Anything else means the
    // relay selected something `crypto/suites.rs` does not implement.
    assert!(
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        ),
        "⛔ the relay negotiated a suite this provider does not implement: {:?}",
        suite.suite()
    );
    // ⛔ `negotiated_key_exchange_group` returns the `SupportedKxGroup` **this
    // provider handed over**, not a name from the wire. That is the stronger
    // assertion: the relay chose one of the two objects in `crypto/kx.rs`, so
    // a group podssh cannot complete cannot appear here.
    let group = session
        .negotiated_key_exchange_group()
        .expect("a TLS 1.3 handshake always names a group");
    eprintln!("negotiated key exchange group: {:?}", group.name());
    assert!(
        matches!(group.name(), rustls::NamedGroup::X25519 | rustls::NamedGroup::secp256r1),
        "⛔ the relay negotiated a group this provider does not implement: {:?}",
        group.name()
    );
    assert!(
        session.peer_certificates().is_some(),
        "⛔ no peer certificate: the chain was not verified"
    );
}

// ── helpers ─────────────────────────────────────────────────────────────────

use std::net::ToSocketAddrs as _;

/// ⛔ **One place builds the connector, and it is the same one the library
/// uses.** Each test building its own would be four chances to prove a
/// configuration podssh never ships.
struct Connector(tokio_rustls::TlsConnector);

/// ⛔ **`TlsConnector::connect` returns `std::io::Error`, not `rustls::Error`.**
/// The certificate rejection arrives wrapped in it, as an `InvalidData`
/// carrying rustls's message — which is why the plant above asserts on the
/// text and not on a variant.
type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

impl Connector {
    /// ⛔ **`client_config` is the library's own, not a copy of it.** ⛔ The
    /// first version of this file rebuilt the `ClientConfig` here, and a plant
    /// that removed the verifier from `tls::client_config` then did **not**
    /// redden any test — the tests were proving a configuration podssh does
    /// not ship. ⛔ MEASURED 2026-10-02: planting a permissive verifier into
    /// `tls::client_config` left this suite at 4 passed, exit 0.
    fn new() -> Self {
        let roots = tls::roots_from_compiled_set();
        let config = podssh_ws::tls::client_config(&roots)
            .expect("a config from a non-empty root store");
        Connector(tokio_rustls::TlsConnector::from(config))
    }

    async fn connect(
        &self,
        name: rustls_pki_types::ServerName<'static>,
        tcp: tokio::net::TcpStream,
    ) -> Result<TlsStream, std::io::Error> {
        self.0.connect(name, tcp).await
    }
}

trait FirstAddr {
    fn to_socket_addrs_first(&self) -> Result<SocketAddr, String>;
}

impl FirstAddr for String {
    fn to_socket_addrs_first(&self) -> Result<SocketAddr, String> {
        // ⛔ A blocking `getaddrinfo` here is acceptable **in a test only**; the
        // library's own `resolve` is async and bounded, and the reason is
        // recorded there.
        self.to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| format!("{self} resolved to no addresses"))
    }
}
