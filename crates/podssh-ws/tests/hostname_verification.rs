//! ⛔ **E03's second plant, proven against podssh's own verifier, with no
//! relay involved.**
//!
//! ⛔ **Why this file exists, and the measurement that forced it.** E03's plant
//! is "a certificate for the wrong hostname must be rejected". ⛔ MEASURED
//! 2026-10-02 in `rust:1-alpine`: the *live* plant does **not** discriminate.
//! Replacing `tls::client_config`'s verifier with one that accepts everything
//! left the live suite at **4 passed, exit 0**, and with `--nocapture` the
//! chain was still being presented while the handshake failed — the relay's
//! edge refuses the SNI itself and never sends a certificate for the client
//! to reject locally. ⛔ A plant that cannot fail is a guard nobody has
//! checked, and this repository has shipped six of those.
//!
//! ⛔ So the proof lives here: a server podssh controls, serving a certificate
//! for one name, asked for by another. The live test keeps its own claim — the
//! *peer* accepts the right name and rejects the wrong one. Together they are
//! E03's sentence; neither alone is.

mod cert {
    include!("common/cert_for_test.rs");
}

use cert::server_for;

/// ⛔ **THE PLANT.** A valid certificate, chaining to a root in the store,
/// presented by a working TLS server — carrying `wrong.example`, asked for as
/// `podssh.invalid`. ⛔ The handshake must fail, in the name check.
#[tokio::test]
async fn plant_a_certificate_for_the_wrong_hostname_is_rejected() {
    let (acceptor, roots) = server_for("wrong.example").expect("a server for the name under test");
    let leaf = cert::encoding::self_signed("wrong.example");
    let anchor = cert::encoding::self_signed_inner("wrong.example-anchor", true);
    // Which certificate does webpki refuse?
    let mut only_leaf = rustls::RootCertStore::empty();
    let _ = only_leaf.add(rustls_pki_types::CertificateDer::from(leaf.der.clone()));
    let mut only_anchor = rustls::RootCertStore::empty();
    let anchor_added = only_anchor
        .add(rustls_pki_types::CertificateDer::from(anchor.der.clone()))
        .is_ok();
    eprintln!(
        "ANCHOR-ACCEPTED-AS-TRUST-ANCHOR: {anchor_added} leaf={} anchor={}",
        leaf.der.len(),
        anchor.der.len()
    );
    let leaf_as_anchor = {
        let mut store = rustls::RootCertStore::empty();
        store
            .add(rustls_pki_types::CertificateDer::from(leaf.der.clone()))
            .is_ok()
    };
    eprintln!("LEAF-ACCEPTED-AS-TRUST-ANCHOR: {leaf_as_anchor}");
    let client = tokio_rustls::TlsConnector::from(
        podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
            count: roots.len(),
            roots,
            source: "the test's own generated root".into(),
        })
        .expect("a config from a non-empty store"),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("an address");
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name =
        rustls_pki_types::ServerName::try_from("podssh.invalid").expect("a valid name");

    let result = client.connect(name, tcp).await;
    let _ = server.await;

    match result {
        Err(e) => {
            let text = e.to_string();
            eprintln!("rejected: {text}");
            // ⛔ **The failure must BE the name check.** A rejection for any
            // other reason would pass this assertion and leave the entry
            // unproven — which is exactly what the live-only plant did.
            assert!(
                text.contains("not valid for")
                    || text.contains("NotValidForName")
                    || text.contains("name"),
                "⛔ the rejection must name the certificate's name mismatch, got: {text}"
            );
        }
        Ok(_) => panic!(
            "⛔ PLANT FAILED TO FIRE: a certificate for wrong.example was accepted \
             for the name podssh.invalid."
        ),
    }
}

/// ⛔ **THE CONTROL, and it differs by one argument.** The same certificate,
/// the same trust store, the same configuration, the same server — asked for
/// by the name it actually carries. ⛔ A guard proven in one direction only is
/// a guard nobody has seen accept a correct input, and this is the half that
/// makes the rejection above attributable to the name check.
#[tokio::test]
async fn the_control_the_right_hostname_is_accepted() {
    let (acceptor, roots) = server_for("wrong.example").expect("a server for the name under test");
    let client = tokio_rustls::TlsConnector::from(
        podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
            count: roots.len(),
            roots,
            source: "the test's own generated root".into(),
        })
        .expect("a config"),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("an address");
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name =
        rustls_pki_types::ServerName::try_from("wrong.example").expect("a valid name");

    let tls = client
        .connect(name, tcp)
        .await
        .expect("⛔ the control must succeed: a guard proven one way only is not a guard");
    let (_, session) = tls.get_ref();
    assert!(
        !session.is_handshaking(),
        "the control handshake did not finish"
    );
    let _ = server.await;
}

/// ⛔ **The pair above is the claim, and this is what makes it one.** The same
/// certificate and the same trust store, two names, opposite outcomes — so a
/// permissive verifier, which is what was planted, cannot satisfy both.
#[tokio::test]
async fn a_permissive_verifier_could_not_satisfy_both() {
    // The two tests above are the halves. This asserts the property that
    // binds them, using the real verifier both times, so a future edit that
    // made one of them vacuous is caught here rather than by a reader.
    let (acceptor_ok, roots_ok) = server_for("right.example").expect("a server for the right name");
    let (acceptor_bad, roots_bad) = server_for("right.example").expect("the same server again");

    let ok_config = podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
        count: roots_ok.len(),
        roots: roots_ok,
        source: "generated".into(),
    })
    .expect("a config");
    let bad_config = podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
        count: roots_bad.len(),
        roots: roots_bad,
        source: "generated".into(),
    })
    .expect("a config");

    let right = rustls_pki_types::ServerName::try_from("right.example").expect("a name");
    let wrong = rustls_pki_types::ServerName::try_from("podssh.invalid").expect("a name");

    let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let a_addr = a.local_addr().expect("addr");
    let a_server = tokio::spawn(async move {
        if let Ok((s, _)) = a.accept().await {
            let _ = acceptor_ok.accept(s).await;
        }
    });
    let tcp = tokio::net::TcpStream::connect(a_addr).await.expect("connect");
    let ok_result = tokio_rustls::TlsConnector::from(ok_config)
        .connect(right, tcp)
        .await;
    eprintln!("RIGHT-NAME RESULT: {:?}", ok_result.as_ref().err().map(|e| e.to_string()));
    let _ = a_server.await;
    match &ok_result {
        Ok(_) => {}
        Err(e) => panic!("the right name must be accepted: {e}"),
    }

    let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let b_addr = b.local_addr().expect("addr");
    let b_server = tokio::spawn(async move {
        if let Ok((s, _)) = b.accept().await {
            let _ = acceptor_bad.accept(s).await;
        }
    });
    let tcp = tokio::net::TcpStream::connect(b_addr).await.expect("connect");
    let bad_result = tokio_rustls::TlsConnector::from(bad_config)
        .connect(wrong, tcp)
        .await;
    let _ = b_server.await;
    assert!(
        bad_result.is_err(),
        "⛔ the wrong name was accepted by the same configuration that \
         accepted the right one"
    );
}
