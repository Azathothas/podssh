//! The routes of a node (T-089), over the end-to-end channel: the operator
//! names a route in its proof, which the relay carries encrypted; the node
//! gets it with the operator's key, and chooses the target, or refuses.

mod e2e_harness;

use std::sync::{Arc, Mutex};

use e2e_harness::{identity, node, LIMIT, PIPE};
use podssh_relay::e2e::ends;
use podssh_relay::e2e::{Error, Refusal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One session to a node whose target names the route that it was asked
/// for: what the operator read, and what the node was asked.
async fn session(route: Option<&str>, routed: bool) -> (Result<String, Error>, Vec<Option<String>>) {
    let asked: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
    let seen = asked.clone();
    let (node_end, _lines) = node(identity(2), |_| Ok(()));
    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, session) = ends::operator_to(app_end, identity(1), |_| Ok(()), route.map(str::to_string));
    let target = |name: String| {
        let (ours, mut theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let _ = theirs.write_all(name.as_bytes()).await;
            let _ = theirs.shutdown().await;
        });
        ours
    };
    if routed {
        tokio::spawn(async move {
            ends::serve_routed(cipher, &node_end, move |key, route: Option<String>| {
                assert_eq!(key, identity(1).public(), "the node gets the operator's key");
                seen.lock().unwrap().push(route.clone());
                async move {
                    match route.as_deref() {
                        None => Ok(target("the default".into())),
                        Some("web") => Ok(target("web".into())),
                        Some(other) => Err(Refusal::Other(format!("no route {other} for this key"))),
                    }
                }
            })
            .await
        });
    } else {
        tokio::spawn(async move {
            ends::serve_node(cipher, &node_end, move || std::future::ready(Ok::<_, String>(target("one".into())))).await
        });
    }
    let session = tokio::spawn(session);
    let (mut r, mut w) = tokio::io::split(app);
    w.shutdown().await.unwrap();
    let mut read = String::new();
    let _ = tokio::time::timeout(LIMIT, r.read_to_string(&mut read)).await;
    let ended = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    let asked = asked.lock().unwrap().clone();
    (ended.map(|_| read), asked)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_gets_the_route_and_chooses_its_target() {
    let (read, asked) = session(Some("web"), true).await;
    assert_eq!((read.unwrap(), asked), ("web".to_string(), vec![Some("web".to_string())]));
    let (read, asked) = session(None, true).await;
    assert_eq!((read.unwrap(), asked), ("the default".to_string(), vec![None]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_that_the_node_refuses_reaches_no_target() {
    let (read, asked) = session(Some("db"), true).await;
    match read {
        Err(Error::Refused(Refusal::Other(why))) => assert!(why.contains("no route db"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(asked, vec![Some("db".to_string())]);
    // A node with no routes refuses one that is named, and opens nothing.
    let (read, _) = session(Some("web"), false).await;
    match read {
        Err(Error::Refused(Refusal::Other(why))) => assert!(why.contains("has no routes"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A name that is not a route's never leaves the operator.
    let (read, asked) = session(Some("../x"), true).await;
    assert!(matches!(read, Err(Error::Handshake(_))), "{read:?}");
    assert!(asked.is_empty());
}
