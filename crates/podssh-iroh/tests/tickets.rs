//! The tickets of the iroh road, and the allowlist of a node (T-163).
//!
//! The fixed tickets are iroh's own form: the bytes of the test vector of
//! iroh-tickets 1.0.0 (its `test_ticket_base32`: a key, the relay
//! `http://derp.me./` and `127.0.0.1:1024`), written as text by Python's
//! base32, not by podssh's encoder. A node lets in only a client whose key
//! its allowlist holds, and a key added to the file counts at once; a
//! planted node that admits each key fails the same check.

mod cleanup;
mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use podssh_iroh::{ticket, Allowlist, Dialer, Failure};
use podssh_relay::session::client::Outcome;
use podssh_relay::session::Settings;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use common::{options, proxy, relay, LIMIT};

/// The key of iroh's vector, in hex and in base32.
const KEY: &str = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
const KEY_BASE32: &str = "vzmp7cbteqnmqllp65qrarxnm62qoliufrmi2add5fbntj2vak3a";
/// iroh's vector: the key at the relay `http://derp.me./` and at
/// `127.0.0.1:1024`.
const VECTOR: &str =
    "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
/// The same form with the relay `https://relay.podssh.test/` alone: a node's
/// ticket.
const RELAY_ONLY: &str =
    "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaiadjuhi5dqom5c6l3smvwgc6joobxwi43tnaxhizltoqxq";
/// The same key with no address at all.
const NO_ADDRESS: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaa";

const PIPE: usize = 64 * 1024;

#[test]
fn iroh_s_own_ticket_parses_to_its_key_relay_and_address() {
    let addr = ticket::parse(&format!("iroh:{VECTOR}")).unwrap();
    assert_eq!(addr.id.to_string(), KEY);
    assert_eq!(addr.relay_urls().map(ToString::to_string).collect::<Vec<_>>(), ["http://derp.me./"]);
    assert_eq!(addr.ip_addrs().map(ToString::to_string).collect::<Vec<_>>(), ["127.0.0.1:1024"]);
    // As iroh's tools print a ticket, with no scheme.
    assert_eq!(ticket::parse(VECTOR).unwrap(), addr);
    // podssh writes iroh's own text back.
    assert_eq!(ticket::format(&addr), format!("iroh:{VECTOR}"));
}

#[test]
fn a_ticket_with_a_relay_alone_is_a_node_s_ticket() {
    let addr = ticket::parse(&format!("iroh:{RELAY_ONLY}")).unwrap();
    assert_eq!(addr.id.to_string(), KEY);
    assert_eq!(addr.relay_urls().map(ToString::to_string).collect::<Vec<_>>(), ["https://relay.podssh.test/"]);
    assert_eq!(addr.ip_addrs().count(), 0, "no address of the node's host");
    let node = EndpointAddr::new(addr.id).with_relay_url("https://relay.podssh.test".parse().unwrap());
    assert_eq!(ticket::format(&node), format!("iroh:{RELAY_ONLY}"));
}

#[test]
fn a_ticket_that_reaches_nothing_or_is_not_one_is_refused() {
    let why = ticket::parse(&format!("iroh:{NO_ADDRESS}")).unwrap_err();
    assert!(why.contains("no relay and no address"), "{why}");
    let cut = format!("iroh:{}", &VECTOR[..40]);
    for bad in ["iroh:", "iroh:endpoint", "iroh:node-acxfr74igmsbvsbnn", "iroh:endpoint0189", cut.as_str()] {
        let why = ticket::parse(bad).unwrap_err();
        assert!(why.contains("not an iroh ticket") || why.contains("no ticket"), "{bad}: {why}");
    }
}

#[test]
fn an_allowlist_takes_hex_base32_and_comments_and_names_its_bad_lines() {
    let ours: PublicKey = KEY.parse().unwrap();
    let other = SecretKey::from_bytes(&[7; 32]).public();
    let stranger = SecretKey::from_bytes(&[9; 32]).public();
    let text = format!("# the operator's laptop\n{KEY} laptop\n\n  not-a-key\n{other}\n");
    let list = Allowlist::parse(&text);
    assert!(list.admits(&ours) && list.admits(&other));
    assert!(!list.admits(&stranger));
    assert_eq!(list.len(), 2);
    assert_eq!(list.bad_lines(), [4], "the line that is not a key is named, and admits nobody");
    let base32 = Allowlist::parse(&format!("{KEY_BASE32}\n"));
    assert!(base32.admits(&ours), "iroh's base32 form of a key");
    assert!(Allowlist::parse("").is_empty());
}

#[test]
fn an_allowlist_file_is_read_whole_and_a_missing_one_is_an_error() {
    let dir = scratch("allow-file");
    let path = dir.join("allow");
    let why = Allowlist::read(&path).unwrap_err();
    assert!(why.contains("no such file"), "{why}");
    write_list(&path, &format!("{KEY}\n"));
    assert!(Allowlist::read(&path).unwrap().admits(&KEY.parse().unwrap()));
}

#[cfg(unix)]
#[test]
fn an_allowlist_that_others_can_change_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("allow-open").join("allow");
    write_list(&path, &format!("{KEY}\n"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let why = Allowlist::read(&path).unwrap_err();
    assert!(why.contains("others can change it"), "{why}");
    // Others may read it: it holds public keys.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Allowlist::read(&path).is_ok());
}

/// A node over the loopback relay, through the stand-in proxy, whose
/// sessions reach an echo, and whose clients are those that `admit` lets in;
/// the count of the echoes that sessions opened.
async fn node<G>(relay: &iroh::RelayUrl, proxy: std::net::SocketAddr, admit: G) -> (Endpoint, Arc<AtomicUsize>)
where
    G: Fn(&PublicKey) -> bool + Clone + Send + Sync + 'static,
{
    let node = podssh_iroh::bind(&options(relay, proxy, true)).await.expect("the node");
    tokio::time::timeout(LIMIT, node.online()).await.expect("the node has its home relay");
    let opened = Arc::new(AtomicUsize::new(0));
    let counted = opened.clone();
    let open = move || {
        let counted = counted.clone();
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            let (target, mut echo) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(&mut echo);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok::<DuplexStream, String>(target)
        }
    };
    tokio::spawn(podssh_iroh::far::serve(node.clone(), Settings::default(), 16 << 20, open, admit));
    (node, opened)
}

/// One session from `client` to `node`: `hello` there and back, then the
/// end; or why it got none.
async fn session(client: &Endpoint, node: &Endpoint, relay: &iroh::RelayUrl) -> Result<Vec<u8>, Failure> {
    let addr = ticket::parse(&ticket::of(node, relay)).expect("the node's ticket");
    let dialer = Dialer::new(client.clone(), addr);
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let talk = async move {
        app.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        app.read_exact(&mut back).await.map(|_| back.to_vec())
    };
    let (carried, echoed) = tokio::time::timeout(LIMIT, async {
        tokio::join!(podssh_iroh::carry(&dialer, app_end, Settings::default(), |_| {}), talk)
    })
    .await
    .expect("the session within the limit");
    dialer.close().await;
    let _: Outcome = carried?;
    echoed.map_err(|e| Failure::Failed(e.to_string()))
}

/// Whether a node whose clients `admit` lets in refuses a client that is not
/// in the allowlist: no session, the refusal's code, and no target opened.
async fn refuses_a_stranger<G>(name: &str, admit: impl FnOnce(PathBuf) -> G) -> bool
where
    G: Fn(&PublicKey) -> bool + Clone + Send + Sync + 'static,
{
    let (relay_url, _relay) = relay().await;
    let (proxy, _) = proxy(relay_url.port().unwrap()).await;
    let list = scratch(name).join("allow");
    write_list(&list, &format!("# only the operator's key\n{KEY}\n"));
    let (node, opened) = node(&relay_url, proxy, admit(list)).await;
    let client = podssh_iroh::bind(&options(&relay_url, proxy, false)).await.expect("the client");
    let got = session(&client, &node, &relay_url).await;
    client.close().await;
    node.close().await;
    got == Err(Failure::Refused) && opened.load(Ordering::SeqCst) == 0
}

/// The node's own check: the allowlist file, read for each connection.
fn by_the_list(path: PathBuf) -> impl Fn(&PublicKey) -> bool + Clone + Send + Sync + 'static {
    move |key: &PublicKey| Allowlist::read(&path).map(|list| list.admits(key)).unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_refuses_a_client_that_is_not_in_its_allowlist() {
    assert!(refuses_a_stranger("stranger", by_the_list).await, "a client that is not in the allowlist got in");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_planted_node_that_admits_each_key_fails_the_check() {
    let each = |_: PathBuf| |_: &PublicKey| true;
    assert!(!refuses_a_stranger("planted", each).await, "the check cannot tell a node that admits each key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_added_to_the_allowlist_gets_in_at_once() {
    let (relay_url, _relay) = relay().await;
    let (proxy, _) = proxy(relay_url.port().unwrap()).await;
    let list = scratch("added").join("allow");
    write_list(&list, &format!("{KEY}\n"));
    let (node, opened) = node(&relay_url, proxy, by_the_list(list.clone())).await;
    let client = podssh_iroh::bind(&options(&relay_url, proxy, false)).await.expect("the client");
    assert_eq!(session(&client, &node, &relay_url).await, Err(Failure::Refused));
    // The node's operator adds the client's key: the next connection gets in,
    // with no new start of the node.
    write_list(&list, &format!("{KEY}\n{} the client\n", client.id()));
    assert_eq!(session(&client, &node, &relay_url).await, Ok(b"hello".to_vec()));
    assert_eq!(opened.load(Ordering::SeqCst), 1, "one target, for the session that got in");
    client.close().await;
    node.close().await;
}

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-tickets-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Write an allowlist as its owner would: others may read it, and not change
/// it.
fn write_list(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}
