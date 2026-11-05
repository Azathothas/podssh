//! The tests of the gate of a node's person (T-638), on tokio's paused
//! clock, with an asker that the test answers: one question for two
//! sessions of one key, a no that stands 15 s, a cover while a session is
//! open and 120 s after, no answer within 100 s, a question whose session
//! went, and two keys asked apart.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::identity::Identity;

fn key(seed: u8) -> PublicKey {
    Identity::from_seed(&[seed; 32]).public()
}

/// The way to answer one question.
type Answering = oneshot::Sender<Result<(), String>>;
/// Each question, as the test reads it.
type Questions = mpsc::UnboundedReceiver<(Question, Answering)>;

/// An asker that sends each question to the test, with the way to answer
/// it, and counts them.
fn asker() -> (Arc<Asker>, Questions, Arc<AtomicUsize>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let asker: Arc<Asker> = Arc::new(move |question: Question| -> Answer {
        count.fetch_add(1, Ordering::SeqCst);
        let (answer, said) = oneshot::channel();
        let _ = tx.send((question, answer));
        // A dropped answer is no answer: the gate's limit ends the wait.
        Box::pin(async move {
            match said.await {
                Ok(said) => said,
                Err(_) => std::future::pending().await,
            }
        })
    });
    (asker, rx, asked)
}

/// Two sessions of one key that come together raise one question, and its
/// yes lets both in.
#[tokio::test(start_paused = true)]
async fn two_sessions_of_one_key_raise_one_question() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let (a, b) = (gate.clone(), gate.clone());
    let first = tokio::spawn(async move { a.cross(key(1), &Ask::Target, false).await });
    let (question, answer) = questions.recv().await.expect("a question");
    assert_eq!((question.key, question.ask.clone(), question.granted), (key(1), Ask::Target, false));
    assert_eq!(question.limit, Duration::from_secs(100));
    let second = tokio::spawn(async move { b.cross(key(1), &Ask::Route("web".into()), false).await });
    tokio::time::sleep(Duration::from_secs(5)).await;
    answer.send(Ok(())).unwrap();
    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    assert_eq!(first.as_ref().map(|(_, by)| *by), Ok(By::Answer));
    assert_eq!(second.as_ref().map(|(_, by)| *by), Ok(By::Answer));
    assert_eq!(asked.load(Ordering::SeqCst), 1, "one question for the key");
}

/// A no stands 15 s, in which the key is refused with no question; then it
/// is asked again.
#[tokio::test(start_paused = true)]
async fn a_no_stands_fifteen_seconds_with_no_question() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let g = gate.clone();
    let first = tokio::spawn(async move { g.cross(key(2), &Ask::Target, false).await });
    let (_, answer) = questions.recv().await.unwrap();
    answer.send(Err("the node's person said no".into())).unwrap();
    let why = first.await.unwrap().err().unwrap_or_default();
    assert!(why.starts_with("the node's person said no") && why.contains("stands 15 s"), "{why}");
    tokio::time::sleep(Duration::from_secs(14)).await;
    let standing = gate.standing(&key(2)).expect("the no stands at 14 s");
    assert!(standing.contains("said no") && standing.contains("1 s more"), "{standing}");
    let refused = gate.cross(key(2), &Ask::Target, false).await;
    assert!(matches!(&refused, Err(why) if why.contains("said no")), "refused with no question");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(gate.standing(&key(2)), None, "the no went at 15 s");
    let g = gate.clone();
    let again = tokio::spawn(async move { g.cross(key(2), &Ask::Target, false).await });
    let (_, answer) = questions.recv().await.expect("asked again after 15 s");
    answer.send(Ok(())).unwrap();
    assert!(again.await.unwrap().is_ok());
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// A yes covers the key while one of its sessions is open, however long,
/// and 120 s after its last; then the key is asked again.
#[tokio::test(start_paused = true)]
async fn a_yes_covers_the_key_while_a_session_is_open_and_120_s_after() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let g = gate.clone();
    let first = tokio::spawn(async move { g.cross(key(3), &Ask::Target, true).await });
    let (question, answer) = questions.recv().await.unwrap();
    assert!(question.granted, "the question says that a grant let it through");
    answer.send(Ok(())).unwrap();
    let (held, by) = first.await.unwrap().expect("a yes");
    assert_eq!(by, By::Answer);
    // An hour with the session open: the cover holds.
    tokio::time::sleep(Duration::from_secs(3600)).await;
    let (second, by) = gate.cross(key(3), &Ask::Target, false).await.expect("covered");
    assert_eq!(by, By::Cover);
    drop(held);
    tokio::time::sleep(Duration::from_secs(300)).await;
    // One session still open: still covered.
    let (third, by) = gate.cross(key(3), &Ask::Target, false).await.expect("covered");
    assert_eq!(by, By::Cover);
    drop((second, third));
    tokio::time::sleep(Duration::from_secs(119)).await;
    let (fourth, by) = gate.cross(key(3), &Ask::Target, false).await.expect("covered 119 s after the last");
    assert_eq!(by, By::Cover);
    drop(fourth);
    tokio::time::sleep(Duration::from_secs(121)).await;
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    let g = gate.clone();
    let again = tokio::spawn(async move { g.cross(key(3), &Ask::Target, false).await });
    let (_, answer) = questions.recv().await.expect("asked again 121 s after the last session");
    answer.send(Err("the node's person said no".into())).unwrap();
    assert!(again.await.unwrap().is_err());
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// No answer within 100 s is a no, which stands; each session that waited
/// for the question gets it.
#[tokio::test(start_paused = true)]
async fn no_answer_within_100_s_is_a_no() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let (a, b) = (gate.clone(), gate.clone());
    let first = tokio::spawn(async move { a.cross(key(4), &Ask::Target, false).await });
    let (_, answer) = questions.recv().await.unwrap();
    let second = tokio::spawn(async move { b.cross(key(4), &Ask::Target, false).await });
    let started = Instant::now();
    let why = first.await.unwrap().err().unwrap_or_default();
    assert!(why.contains("no answer came within 100 s"), "{why}");
    assert_eq!(started.elapsed().as_secs(), 100);
    let why = second.await.unwrap().err().unwrap_or_default();
    assert!(why.contains("no answer came within 100 s"), "the waiting session: {why}");
    assert!(gate.standing(&key(4)).is_some());
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    drop(answer);
}

/// A question whose session went before its answer leaves no slot behind:
/// the session that waited asks anew, and is not held.
#[tokio::test(start_paused = true)]
async fn a_question_whose_session_went_is_asked_again() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let (a, b) = (gate.clone(), gate.clone());
    let first = tokio::spawn(async move { a.cross(key(5), &Ask::Target, false).await });
    let (_, _first_answer) = questions.recv().await.unwrap();
    let second = tokio::spawn(async move { b.cross(key(5), &Ask::Target, false).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    first.abort();
    let (_, answer) = questions.recv().await.expect("the waiting session asks anew");
    answer.send(Ok(())).unwrap();
    assert_eq!(second.await.unwrap().map(|(_, by)| by), Ok(By::Answer));
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// A no for one key says nothing of another, and a cover neither.
#[tokio::test(start_paused = true)]
async fn two_keys_are_asked_apart() {
    let (asker, mut questions, asked) = asker();
    let gate = Gate::new(asker);
    let g = gate.clone();
    let one = tokio::spawn(async move { g.cross(key(6), &Ask::Target, false).await });
    let (_, answer) = questions.recv().await.unwrap();
    answer.send(Err("no".into())).unwrap();
    assert!(one.await.unwrap().is_err());
    let g = gate.clone();
    let other = tokio::spawn(async move { g.cross(key(7), &Ask::Target, false).await });
    let (question, answer) = questions.recv().await.expect("the other key is asked");
    assert_eq!(question.key, key(7));
    answer.send(Ok(())).unwrap();
    let (_held, _) = other.await.unwrap().expect("a yes");
    assert!(gate.standing(&key(6)).is_some() && gate.standing(&key(7)).is_none());
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}
