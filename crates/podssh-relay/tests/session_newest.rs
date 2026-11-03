//! The newest resume of a session wins at the far end by the order of the
//! handshakes, not of the tasks that run them (T-270). A client that moves
//! twice in a row resumes on link A, then on link B; when the far end's task
//! for A starts late, after B's, A gives way, and B keeps the session. When
//! the order of the tasks decided, A stopped B, and the client saw B end
//! with no word from the far end. And a session whose client asked it to end
//! with its link (T-612, `--no-resume`) leaves the far end nothing at a loss,
//! where one with no such ask waits its deadline.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::task::JoinHandle;

use podssh_relay::session::client::{self, Client, ClientError, Found, Outcome};
use podssh_relay::session::far::{self, Accepted};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{
    once, Ask, End, Ended, HandshakeError, OsEntropy, RefuseCode, Role, Secret, SessionId, Settings,
};

const PIPE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(5);
/// How long the far end keeps a lost session here.
const DEADLINE: Duration = Duration::from_secs(30);

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

/// A resume that comes before the first link's task carries the session, as
/// while a node opens its target, waits for that link and takes the session
/// from it; it used to find no slot and end the session (T-600).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resume_before_the_first_link_is_carried_waits_for_it() {
    let settings = Settings::default();
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(30)));

    let (target, _app) = tokio::io::duplex(PIPE);
    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let (mut far_entropy, mut client_entropy) = (OsEntropy, OsEntropy);
    let (accepted, opened) = tokio::join!(
        far::accept(far_link, Role::NODE, settings, &keeper.sessions, &mut far_entropy),
        client::start(client_link, Ask::New, settings, &mut client_entropy),
    );
    let (accepted, opened) = (accepted.expect("the first link's handshake"), opened.expect("the session opens"));
    let established = opened.established().expect("the far end speaks the layer");
    let (id, secret) = (established.id, *established.secret.bytes());

    // The client's first link fell while the far end opened the target: it
    // resumes before that link's task carries the session.
    let (b, _client_b) = resume(&keeper, id, secret, settings).await;
    let b_run = {
        let keeper = keeper.clone();
        tokio::spawn(async move { keeper.run_resumed(b).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!b_run.is_finished(), "the resume waits for the first link");

    let first = {
        let keeper = keeper.clone();
        tokio::spawn(async move { keeper.run_new(accepted, target).await })
    };
    let stopped = tokio::time::timeout(LIMIT, first).await.expect("the first link stops for B").unwrap();
    assert!(matches!(stopped.end, End::Stopped), "{:?}", stopped.end);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!b_run.is_finished(), "B carries the session");
    drop(opened);
}

/// A resume of a session that its first link's task closed, as when the
/// node could not reach its target, ends at once with the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resume_of_a_session_closed_before_its_first_link_ends() {
    let settings = Settings::default();
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(30)));

    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let (mut far_entropy, mut client_entropy) = (OsEntropy, OsEntropy);
    let (accepted, opened) = tokio::join!(
        far::accept(far_link, Role::NODE, settings, &keeper.sessions, &mut far_entropy),
        client::start(client_link, Ask::New, settings, &mut client_entropy),
    );
    let (accepted, opened) = (accepted.expect("the first link's handshake"), opened.expect("the session opens"));
    let established = opened.established().expect("the far end speaks the layer");
    let (id, secret) = (established.id, *established.secret.bytes());

    let (b, client_b) = resume(&keeper, id, secret, settings).await;
    let b_run = {
        let keeper = keeper.clone();
        tokio::spawn(async move { keeper.run_resumed(b).await })
    };
    // The client reads no last word here: B's ends with its link.
    drop(client_b);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The first link's task gives up: the session is no longer known. Its
    // last word waits for a client that reads nothing here.
    let closer = {
        let keeper = keeper.clone();
        tokio::spawn(async move { accepted.close("the target refused", &keeper.sessions).await })
    };
    let refused = tokio::time::timeout(LIMIT, b_run).await.expect("the resume ends with the session").unwrap();
    assert_eq!(refused.expect_err("the session is gone"), "the session ended on its old link");
    closer.abort();
    drop(opened);
}

/// A link through a stand-in relay, and the task that carries it: the
/// task's abort drops both of its ends at once, with no word, as a relay
/// drops a socket.
fn relayed() -> (DuplexStream, DuplexStream, JoinHandle<()>) {
    let (client, mut relay_client) = tokio::io::duplex(PIPE);
    let (mut relay_far, far) = tokio::io::duplex(PIPE);
    let relay = tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut relay_client, &mut relay_far).await;
    });
    (client, far, relay)
}

/// What a session left after its link was lost (T-612).
struct Lost {
    keeper: Arc<Keeper<DuplexStream>>,
    /// The target's other end: it reads the end once the far end shuts it.
    app: DuplexStream,
    /// The application's other end, open to the end, so that nothing ends
    /// the session but the loss.
    _ssh: DuplexStream,
    /// The names that both sides gave.
    features: Vec<String>,
    outcome: Outcome,
    /// How often the client asked for a new link.
    asked: usize,
    id: SessionId,
    secret: [u8; 32],
    settings: Settings,
}

/// A session with the resumes on or off, its link lost under it, once the
/// far end's link and the client's session have ended; the client gets no
/// new link.
async fn a_session_lost(resumes: bool) -> Lost {
    let settings = Settings { resumes, ..Settings::default() };
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(DEADLINE));
    let (client_link, far_link, relay) = relayed();
    let (target, app) = tokio::io::duplex(PIPE);
    let first = {
        let keeper = keeper.clone();
        tokio::spawn(async move {
            let accepted = far::accept(far_link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy)
                .await
                .expect("the far end's handshake");
            keeper.run_new(accepted, target).await
        })
    };
    let opened = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.expect("the session opens");
    let Found::Layer { features, .. } = opened.found().clone() else { panic!("the far end speaks the layer") };
    let established = opened.established().expect("the layer");
    let (id, secret) = (established.id, *established.secret.bytes());
    let asked = Arc::new(AtomicUsize::new(0));
    let (app_end, ssh) = tokio::io::duplex(PIPE);
    let counted = asked.clone();
    let session = tokio::spawn(async move {
        let connect = move |_: &Ended| {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Next::<DuplexStream>::Stop("this test gives no new link".into()) }
        };
        resume::run(opened, app_end, connect, |_| {}, &mut OsEntropy).await
    });
    // The session runs a moment, then the relay drops the link both ways.
    tokio::time::sleep(Duration::from_millis(200)).await;
    relay.abort();
    let ended = tokio::time::timeout(LIMIT, first).await.expect("the far end's link ends").unwrap();
    assert!(ended.end.resumable(), "a loss at the far end: {:?}", ended.end);
    let outcome = tokio::time::timeout(LIMIT, session).await.expect("the client's session ends").unwrap();
    let asked = asked.load(Ordering::SeqCst);
    Lost { keeper, app, _ssh: ssh, features, outcome, asked, id, secret, settings }
}

/// A resume of the lost session, with its secret: the client's end of it.
async fn resume_of(lost: &Lost) -> Result<Client<DuplexStream>, ClientError> {
    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let ask = Ask::Resume { id: lost.id, secret: Secret::from_bytes(lost.secret), received: 0 };
    let (mut far_entropy, mut client_entropy) = (OsEntropy, OsEntropy);
    let (_, resumed) = tokio::join!(
        far::accept(far_link, Role::NODE, lost.settings, &lost.keeper.sessions, &mut far_entropy),
        client::start(client_link, ask, lost.settings, &mut client_entropy),
    );
    resumed
}

/// `--no-resume` (T-612): both sides name the ask; the client carries the
/// session on its first link alone, and asks for no other; as that link
/// goes, the far end forgets the session and shuts its target, so its budget
/// is free at once, and a resume finds no session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_that_ends_with_its_link_leaves_the_far_end_nothing() {
    let mut lost = a_session_lost(false).await;
    assert!(once::agreed(&lost.features), "both sides name the ask: {:?}", lost.features);
    assert_eq!(lost.asked, 0, "the client asks for no new link");
    assert!(
        matches!(&lost.outcome, Outcome::Layer(Ended { end: End::Lost(_), .. })),
        "the session ends with its link: {:?}",
        lost.outcome
    );
    assert_eq!((lost.keeper.kept(), lost.keeper.closed()), (0, 0), "the far end keeps nothing of it");
    assert_eq!(lost.keeper.census(lost.settings.replay_capacity).held, 0, "its budget is free at once");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(LIMIT, lost.app.read(&mut byte)).await.expect("the target is shut at once");
    assert_eq!(read.expect("the target's end"), 0, "the target reads its end");
    let refused = tokio::time::timeout(LIMIT, resume_of(&lost)).await.expect("the resume is answered");
    let unknown = |e: &ClientError| {
        matches!(e, ClientError::Handshake(HandshakeError::Refused { code: RefuseCode::UNKNOWN_SESSION, .. }))
    };
    assert!(refused.as_ref().err().is_some_and(unknown), "a resume finds no session: {:?}", refused.err());
}

/// The control: with no ask, the same loss leaves the session to a resume.
/// The client asks for a new link, and the far end keeps the session and its
/// target, charged a whole buffer, until its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_ask_a_lost_session_waits_its_deadline() {
    let mut lost = a_session_lost(true).await;
    assert!(!once::agreed(&lost.features), "no ask: {:?}", lost.features);
    assert_eq!(lost.asked, 1, "the client asks for a new link");
    assert_eq!(lost.keeper.kept(), 1, "the far end keeps the session");
    let each = lost.settings.replay_capacity;
    let census = lost.keeper.census(each);
    assert_eq!((census.held, census.waiting), (each, 1), "a whole buffer, waiting for its client");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(300), lost.app.read(&mut byte)).await;
    assert!(read.is_err(), "the target waits with the session");
    let later = tokio::time::Instant::now() + DEADLINE + Duration::from_secs(1);
    assert_eq!(lost.keeper.expire_at(later).await, 1, "forgotten at its deadline");
}
