//! The question of a refused version (T-348) against iroh's own relay
//! server: this build's versions are taken, and a version that the relay
//! does not serve is refused in the server's own words, which the notice
//! quotes; a relay that takes them gives no notice.

mod cleanup;

use podssh_iroh::version::{self, Answer};
use podssh_ws::{ProxyChoice, Trust};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-version-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iroh_s_relay_takes_this_build_s_versions_and_refuses_another_in_its_words() {
    let dir = scratch("relay");
    let relay = podssh_iroh::test_relay::spawn(&dir).await.expect("a relay on the loopback");
    let trust = Trust::File(relay.cert.clone());
    let direct = ProxyChoice::Direct;
    assert_eq!(version::ask(&relay.url, &trust, &direct, version::LIMIT).await, Answer::Takes);
    match version::ask_with(&relay.url, "iroh-relay-v0", &trust, &direct, version::LIMIT).await {
        Answer::Refuses(words) => {
            assert!(words.contains("unsupported relay version") && words.contains("iroh-relay-v0"), "{words}");
            let said = version::notice(&relay.url, &words);
            assert!(said.contains("we support iroh-relay-v2") && said.contains("--iroh-relay URL"), "{said}");
        }
        other => panic!("a refusal of the version, not {other:?}"),
    }
    assert_eq!(version::refusal(std::slice::from_ref(&relay.url), &trust, &direct).await, None);
}

/// A relay whose certificate the trust store does not hold tells nothing:
/// no notice blames the version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_is_not_trusted_tells_nothing() {
    let dir = scratch("trust");
    let relay = podssh_iroh::test_relay::spawn(&dir).await.expect("a relay on the loopback");
    let answer = version::ask(&relay.url, &Trust::Default, &ProxyChoice::Direct, version::LIMIT).await;
    assert!(matches!(&answer, Answer::Unknown(why) if why.contains("localhost")), "{answer:?}");
}
