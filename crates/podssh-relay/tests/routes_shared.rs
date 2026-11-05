//! The shares of a node (T-433) at its routes, with no relay: a share that
//! the node's file names now is reached by its name at the next session,
//! one that it names no more is refused with the words of a route that the
//! node does not have, a route of the command line wins over a share of its
//! name, and a key's grant holds a share as it holds a route. The budget of
//! the layer is asked once the route and the grant passed, never for a
//! route refused, and a full one dials nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::e2e::Ask;
use podssh_relay::identity::{Identity, PublicKey};
use podssh_relay::reverse::routes::{Grant, Route, Routes, Shared};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(10);

/// A TCP service on the loopback that writes `word` to each connection and
/// closes it; and the count of its connections.
async fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes()).await;
        }
    });
    (port, count)
}

fn route(name: Option<&str>, port: u16) -> Route {
    Route { name: name.map(str::to_string), host: "127.0.0.1".into(), port }
}

/// The share file as the node reads it, which a test changes; and the
/// count of its reads.
fn file() -> (Arc<Mutex<Vec<Route>>>, Arc<AtomicUsize>, Arc<Shared>) {
    let (now, reads) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
    let (held, counted) = (now.clone(), reads.clone());
    let shared: Arc<Shared> = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        held.lock().unwrap().clone()
    });
    (now, reads, shared)
}

/// Routes of `fixed` and the shares of `shared`, whose grant refuses the
/// route `db` alone.
fn routes(fixed: Vec<Route>, shared: Arc<Shared>) -> Routes {
    let grant: Arc<Grant> = Arc::new(|_: &PublicKey, route: &str| match route {
        "db" => Err("the allowlist does not give it db".to_string()),
        _ => Ok(()),
    });
    Routes { routes: Arc::new(fixed), grant, timeout: LIMIT, sshd: false, exit: None, shared: Some(shared) }
}

/// What a session that asked `ask` got: the service's word, or the
/// refusal's; `admit` is the layer's budget.
async fn opened(routes: &Routes, ask: Ask, admit: impl FnOnce() -> bool) -> Result<String, String> {
    let key = Identity::from_seed(&[1; 32]).public();
    match routes.open_with(&key, &ask, admit).await {
        Ok(mut stream) => {
            let mut word = String::new();
            let _ = tokio::time::timeout(LIMIT, stream.read_to_string(&mut word)).await;
            Ok(word)
        }
        Err(refusal) => Err(refusal.to_string()),
    }
}

fn web() -> Ask {
    Ask::Route("web".into())
}

#[tokio::test]
async fn a_share_is_reached_while_the_file_names_it_and_refused_once_it_does_not() {
    let ((default, _), (web_port, web_seen)) = (service("default").await, service("web").await);
    let (now, reads, shared) = file();
    let routes = routes(vec![route(None, default)], shared);
    let none = opened(&routes, web(), || true).await.expect_err("no share yet");
    assert!(none.contains("may not use the route web"), "the words of a route that the node does not have: {none}");
    // Added while the node runs: the next session reads the file again.
    now.lock().unwrap().push(route(Some("web"), web_port));
    assert_eq!(opened(&routes, web(), || true).await, Ok("web".to_string()));
    assert_eq!(opened(&routes, Ask::Target, || true).await, Ok("default".to_string()), "TARGET stays the node's");
    // Removed: refused from the next session, and not dialled.
    now.lock().unwrap().clear();
    let gone = opened(&routes, web(), || true).await.expect_err("a share removed");
    assert!(gone.contains("may not use the route web"), "{gone}");
    assert_eq!(web_seen.load(Ordering::SeqCst), 1, "the share was dialled once, while it was there");
    assert_eq!(reads.load(Ordering::SeqCst), 3, "the file is read for each session that names a route");
}

#[tokio::test]
async fn a_route_of_the_command_line_wins_over_a_share_of_its_name() {
    let ((fixed, _), (shared_port, shared_seen)) = (service("fixed").await, service("shared").await);
    let (now, reads, shared) = file();
    now.lock().unwrap().push(route(Some("web"), shared_port));
    let routes = routes(vec![route(Some("web"), fixed)], shared);
    let fixed_first = "a share took the route of the command line";
    assert_eq!(opened(&routes, web(), || true).await, Ok("fixed".to_string()), "{fixed_first}");
    assert_eq!((shared_seen.load(Ordering::SeqCst), reads.load(Ordering::SeqCst)), (0, 0), "the file was not needed");
}

#[tokio::test]
async fn a_key_s_grant_holds_a_share_as_a_route_and_the_budget_comes_after_it() {
    let (db_port, db_seen) = service("db").await;
    let (web_port, web_seen) = service("web").await;
    let (now, _, shared) = file();
    now.lock().unwrap().extend([route(Some("db"), db_port), route(Some("web"), web_port)]);
    let routes = routes(Vec::new(), shared);
    let asked = Arc::new(AtomicUsize::new(0));
    let budget = |room: bool| {
        let asked = asked.clone();
        move || {
            asked.fetch_add(1, Ordering::SeqCst);
            room
        }
    };
    // A share that the key's grant does not give: refused before the budget.
    let refused = opened(&routes, Ask::Route("db".into()), budget(true)).await.expect_err("db is not granted");
    assert!(refused.contains("may not use the route db"), "{refused}");
    assert_eq!((asked.load(Ordering::SeqCst), db_seen.load(Ordering::SeqCst)), (0, 0), "no room taken, no dial");
    // A full budget: refused with its words, and nothing dialled.
    let full = opened(&routes, web(), budget(false)).await.expect_err("no room");
    assert!(full.contains("budget"), "{full}");
    assert_eq!((asked.load(Ordering::SeqCst), web_seen.load(Ordering::SeqCst)), (1, 0));
    // Room: reached, the budget asked once more.
    assert_eq!(opened(&routes, web(), budget(true)).await, Ok("web".to_string()));
    assert_eq!((asked.load(Ordering::SeqCst), web_seen.load(Ordering::SeqCst)), (2, 1));
}
