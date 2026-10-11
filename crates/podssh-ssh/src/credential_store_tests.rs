//! The store of `podssh agent` over socket pairs: a stand-in for russh's
//! agent server behind [`serve_client`], and a client of the store.

use std::sync::Arc;

use super::*;

/// The agent's own server, as a stand-in: SUCCESS to `lock` and `unlock`,
/// and FAILURE to each other message, as russh's answers an extension.
async fn stand_in_agent(mut server: tokio::io::DuplexStream) {
    while let Ok(Some(request)) = read_frame(&mut server).await {
        let answer = match request.first() {
            Some(&LOCK | &UNLOCK) => vec![SUCCESS],
            _ => vec![FAILURE],
        };
        if write_frame(&mut server, &answer).await.is_err() {
            return;
        }
    }
}

/// A client of an agent with a store, over a socket pair.
fn agent_with_store() -> (StoreClient<tokio::io::DuplexStream>, Arc<Store>) {
    let store = Arc::new(Store::default());
    let (client, served) = tokio::io::duplex(MAX_FRAME);
    let (to_agent, agent) = tokio::io::duplex(MAX_FRAME);
    tokio::spawn(stand_in_agent(agent));
    let kept = store.clone();
    tokio::spawn(async move { serve_client(served, to_agent, &kept).await });
    (StoreClient::new(client), store)
}

#[tokio::test]
async fn credential_store_keeps_a_password_and_a_passphrase_for_their_targets() {
    let (mut agent, _) = agent_with_store();
    let password = Target::password("podtest", "Server.Example", 2201);
    assert_eq!(password.name, "podtest@server.example:2201");
    let passphrase = Target::passphrase(Path::new("keys/id_ed25519"));
    agent.store(&password, "s3cret-pw", None).await.unwrap();
    agent.store(&passphrase, "open sesame", None).await.unwrap();
    assert_eq!(agent.lookup(&password).await.unwrap().as_deref().map(String::as_str), Some("s3cret-pw"));
    assert_eq!(agent.lookup(&passphrase).await.unwrap().as_deref().map(String::as_str), Some("open sesame"));
    assert_eq!(agent.count().await.unwrap(), 2);

    // Another host, another port, another user, and a passphrase of the
    // same name: none is the password of the target.
    for other in [
        Target::password("podtest", "other.example", 2201),
        Target::password("podtest", "server.example", 22),
        Target::password("root", "server.example", 2201),
        Target { kind: Kind::Passphrase, name: password.name.clone() },
    ] {
        assert!(agent.lookup(&other).await.unwrap().is_none(), "{other:?}");
    }
}

/// A password that the server refused is forgotten, and a lookup then
/// finds none: it is never tried twice.
#[tokio::test]
async fn credential_store_forgets_a_refused_password() {
    let (mut agent, _) = agent_with_store();
    let target = Target::password("podtest", "127.0.0.1", 2201);
    agent.store(&target, "wrong", None).await.unwrap();
    assert!(agent.lookup(&target).await.unwrap().is_some());
    agent.forget(&target).await.unwrap();
    assert!(agent.lookup(&target).await.unwrap().is_none());
    assert_eq!(agent.count().await.unwrap(), 0);
}

/// The agent's own messages pass through to its server, and a lock that
/// it took keeps the store silent until the unlock.
#[tokio::test]
async fn credential_store_is_silent_while_the_agent_is_locked() {
    let (mut agent, store) = agent_with_store();
    let target = Target::password("podtest", "127.0.0.1", 2201);
    agent.store(&target, "pw", None).await.unwrap();
    let mut lock = vec![LOCK];
    put_string(&mut lock, b"lock-pass");
    assert_eq!(agent.ask(&lock).await.unwrap().as_slice(), [SUCCESS]);
    assert!(store.locked.load(Ordering::SeqCst));
    assert!(matches!(agent.lookup(&target).await, Err(StoreError::NoStore)));
    let mut unlock = vec![UNLOCK];
    put_string(&mut unlock, b"lock-pass");
    assert_eq!(agent.ask(&unlock).await.unwrap().as_slice(), [SUCCESS]);
    assert!(agent.lookup(&target).await.unwrap().is_some());
    // A request of the agent itself, list the keys, goes to its server.
    assert!(matches!(agent.ask(&[11]).await, Err(StoreError::NoStore)));
}

/// An agent that is not podssh's answers the extension with FAILURE or
/// EXTENSION_FAILURE, or closes the connection at it, as the stream to
/// Pageant does when none runs: no store, never an error.
#[tokio::test]
async fn credential_store_of_another_agent_is_none() {
    let (client, agent) = tokio::io::duplex(MAX_FRAME);
    tokio::spawn(stand_in_agent(agent));
    let mut client = StoreClient::new(client);
    let target = Target::password("u", "h", 22);
    assert!(matches!(client.lookup(&target).await, Err(StoreError::NoStore)));
    assert!(matches!(client.count().await, Err(StoreError::NoStore)));
    for answer in [Some(EXTENSION_FAILURE), None] {
        let (client, mut agent) = tokio::io::duplex(MAX_FRAME);
        tokio::spawn(async move {
            let _ = read_frame(&mut agent).await;
            if let Some(code) = answer {
                let _ = write_frame(&mut agent, &[code]).await;
            }
        });
        let mut client = StoreClient::new(client);
        assert!(matches!(client.count().await, Err(StoreError::NoStore)), "{answer:?}");
    }
}

/// A lifetime ends a credential; with none it lasts the agent's life.
#[tokio::test]
async fn credential_store_lifetime_ends_a_credential() {
    let (mut agent, _) = agent_with_store();
    let brief = Target::password("u", "brief.example", 22);
    let kept = Target::password("u", "kept.example", 22);
    agent.store(&brief, "pw", Some(1)).await.unwrap();
    agent.store(&kept, "pw", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(agent.lookup(&brief).await.unwrap().is_none());
    assert!(agent.lookup(&kept).await.unwrap().is_some());
    assert_eq!(agent.count().await.unwrap(), 1);
}

/// A frame past the bound ends the client's connection, with nothing
/// read past its length.
#[tokio::test]
async fn credential_store_refuses_a_frame_past_its_bound() {
    let (mut client, served) = tokio::io::duplex(64);
    let (to_agent, _agent) = tokio::io::duplex(64);
    let store = Store::default();
    let serving = async { serve_client(served, to_agent, &store).await };
    let sending = async {
        client.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).await.unwrap();
    };
    let (served, ()) = tokio::join!(serving, sending);
    assert_eq!(served.unwrap_err().kind(), io::ErrorKind::InvalidData);
}
