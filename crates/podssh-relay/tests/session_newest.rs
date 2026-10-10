//! The newest resume of a session wins at the far end by the order of the
//! handshakes, not of the tasks that run them (T-270). A client that moves
//! twice in a row resumes on link A, then on link B; when the far end's task
//! for A starts late, after B's, A gives way, and B keeps the session. When
//! the order of the tasks decided, A stopped B, and the client saw B end
//! with no word from the far end.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::DuplexStream;

use podssh_relay::session::client::{self, Client};
use podssh_relay::session::far::{self, Accepted};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{Ask, End, OsEntropy, Role, Secret, SessionId, Settings};

const PIPE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(5);

/// A resume of session `id` on a new link: the far end's side, accepted,
/// and the client's.
async fn resume(
    keeper: &Keeper<DuplexStream>,
    id: SessionId,
    secret: [u8; 32],
    settings: Settings,
) -> (Accepted<DuplexStream>, Client<DuplexStream>) {
    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let ask = Ask::Resume { id, secret: Secret::from_bytes(secret), received: 0 };
    let (mut far_entropy, mut client_entropy) = (OsEntropy, OsEntropy);
    let (accepted, client) = tokio::join!(
        far::accept(far_link, Role::NODE, settings, &keeper.sessions, &mut far_entropy),
        client::start(client_link, ask, settings, &mut client_entropy),
    );
    (accepted.expect("the far end accepts the resume"), client.expect("the client resumes"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_resume_whose_task_starts_late_gives_way_to_the_newer() {
    let settings = Settings::default();
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(30)));

    // The session on its first link. Its target's other end lives to the
    // end of the test: a target that ends would close the session.
    let (target, _app) = tokio::io::duplex(PIPE);
    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let first = {
        let keeper = keeper.clone();
        tokio::spawn(async move {
            let accepted = far::accept(far_link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy)
                .await
                .expect("the first link's handshake");
            keeper.run_new(accepted, target).await
        })
    };
    let opened = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.expect("the session opens");
    let established = opened.established().expect("the far end speaks the layer");
    let (id, secret) = (established.id, *established.secret.bytes());

    // A answers first, then B: the client's two moves in a row.
    let (a, _client_a) = resume(&keeper, id, secret, settings).await;
    let (b, _client_b) = resume(&keeper, id, secret, settings).await;

    // B's task starts first, as when the far end runs A's late.
    let b_run = {
        let keeper = keeper.clone();
        tokio::spawn(async move { keeper.run_resumed(b).await })
    };
    let stopped = tokio::time::timeout(LIMIT, first).await.expect("the first link stops for B").unwrap();
    assert!(matches!(stopped.end, End::Stopped), "{:?}", stopped.end);

    let late = tokio::time::timeout(LIMIT, keeper.run_resumed(a)).await;
    let refused = late.expect("the older resume gives way at once, and stops nothing");
    assert_eq!(refused.expect_err("A does not take the session"), "a newer link resumed the session");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!b_run.is_finished(), "B still carries the session");
    drop(opened);
}
