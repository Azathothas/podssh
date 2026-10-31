//! The stores of Windows and macOS (T-340), on a runner of CI that adds the
//! test's root to the system and takes it out again
//! (`.github/workflows/build.yml`, the jobs `windows` and `macos`). In order:
//!
//! ```sh
//! PODSSH_TEST_STORE_ROOT=FILE cargo test -p podssh-ws --test system_store -- --ignored --exact the_root_is_written
//! PODSSH_TEST_STORE_HOLDS=0 cargo test -p podssh-ws --test system_store -- --ignored --exact \
//!     a_server_that_the_root_signs_is_trusted_through_the_store_alone
//! # the root of FILE added to the system's store
//! PODSSH_TEST_STORE_HOLDS=1 cargo test ...   # the same test
//! ```
//!
//! The first run of the second test is the control: the same server, with
//! the root out of the store, ends in `UnknownIssuer`.

#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

use std::path::Path;
use std::time::Duration;

use podssh_ws::tls::{connect_over, Trust};

/// The name that the test's server holds; its root's key comes from it, so
/// each run mints the same root.
const NAME: &str = "store.podssh.test";

fn root() -> Vec<u8> {
    cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der
}

#[test]
#[ignore = "a step of CI: the root that the next step adds to the system's store, in DER"]
fn the_root_is_written() {
    let path = std::env::var_os("PODSSH_TEST_STORE_ROOT").expect("PODSSH_TEST_STORE_ROOT names the file");
    std::fs::write(&path, root()).expect("the root is written");
}

#[tokio::test]
#[ignore = "a step of CI, with the root out of the system's store (PODSSH_TEST_STORE_HOLDS=0) or in it (1)"]
async fn a_server_that_the_root_signs_is_trusted_through_the_store_alone() {
    let holds = match std::env::var("PODSSH_TEST_STORE_HOLDS").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        other => panic!("PODSSH_TEST_STORE_HOLDS is 0 or 1, not {other:?}"),
    };
    let root = root();
    let stores = podssh_ws::stores::read();
    eprintln!("the stores: {}", podssh_ws::stores::summary(&stores).unwrap_or_else(|| "none".into()));
    let holder = stores.iter().find(|store| store.roots.iter().any(|cert| cert.as_ref() == root.as_slice()));
    assert_eq!(holder.is_some(), holds, "a store gives the root: {:?}", holder.map(|store| store.name));
    if let Some(store) = holder {
        eprintln!("the root comes from {}", store.name);
    }
    // No bundle file holds it, on macOS `/etc/ssl/cert.pem` among them: what
    // trusts the root is the store.
    for bundle in podssh_ws::tls::SYSTEM_BUNDLES {
        if let Ok(certs) = podssh_ws::bundle::load_bundle(Path::new(bundle)) {
            assert!(!certs.iter().any(|cert| cert.as_ref() == root.as_slice()), "{bundle} holds the test's root");
        }
    }

    let (acceptor, _) = cert::server_for(NAME).expect("a server for the name");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("an address");
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let result = connect_over(tcp, NAME, &Trust::Default, Duration::from_secs(10)).await;
    let _ = server.await;
    match (holds, result) {
        (true, Ok(_)) => {}
        (true, Err(why)) => panic!("the root is in the store, and the handshake failed: {why}"),
        (false, Ok(_)) => panic!("the root is in no store, and the handshake passed"),
        (false, Err(why)) => assert!(why.contains("UnknownIssuer"), "the control must fail on the issuer: {why}"),
    }
}
