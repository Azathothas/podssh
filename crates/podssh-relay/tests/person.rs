//! A node's person (T-638) through the end-to-end channel: a gate after the
//! door, which an operator crosses only with a yes or its cover. A no
//! reaches no target, and the operator hears only that its key is not let
//! in; a key that the door refuses raises no question; the node's line says
//! by what each session came in; two sessions of one key that come together
//! raise one question; and the operator waits for an answer that comes after
//! a step's limit of the handshake.

mod e2e_harness;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use e2e_harness::{echo_back, identity, node, run, Fault, LIMIT};
use podssh_relay::e2e::person::{Answer, Asker, Gate, Question};
use podssh_relay::e2e::{Error, Refusal, HANDSHAKE_LIMIT};
use podssh_relay::identity::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The questions that a node's person was asked.
type Asked = Arc<Mutex<Vec<Question>>>;

/// A node's person that gives `answer` to each question, `after` it came,
/// and keeps each question.
fn person(answer: Result<(), String>, after: Duration) -> (Arc<Gate>, Asked) {
    let asked: Asked = Arc::default();
    let kept = asked.clone();
    let asker: Arc<Asker> = Arc::new(move |question: Question| -> Answer {
        kept.lock().unwrap().push(question);
        let answer = answer.clone();
        Box::pin(async move {
            tokio::time::sleep(after).await;
            answer
        })
    });
    (Gate::new(asker), asked)
}

/// A no of the node's person reaches no target, and the operator hears only
/// that its key is not let in; the reason is in the node's line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_no_reaches_no_target_and_the_operator_hears_only_not_let_in() {
    let operator = identity(0x11);
    let (gate, asked) = person(Err("the node's person said no".into()), Duration::ZERO);
    let (mut node_end, lines) = node(identity(0x22), |_| Ok(()));
    node_end.gate = Some(gate);
    let r = run(operator.clone(), |_| Ok(()), (node_end, lines), Fault::None, Fault::None);
    let outcome = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Err(Error::Refused(Refusal::NotAllowed))), "{outcome:?}");
    tokio::time::timeout(LIMIT, r.node_task).await.unwrap().unwrap();
    assert_eq!(r.opened.load(Ordering::SeqCst), 0, "a no reached the target");
    let questions = asked.lock().unwrap().clone();
    assert_eq!(questions.len(), 1, "{questions:?}");
    assert_eq!((questions[0].key, questions[0].granted), (operator.public(), false));
    let lines = r.lines.lock().unwrap().join("\n");
    let refused = format!("refused the operator key {}, which the door let through: the node's", operator.public());
    assert!(lines.contains(&refused) && lines.contains("said no; the no stands 15 s"), "{lines}");
    assert!(!lines.contains("came in"), "{lines}");
}

/// A key that the door refuses raises no question: the door decides before
/// the person, who widens nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_the_door_refuses_raises_no_question() {
    let operator = identity(0x11);
    let (gate, asked) = person(Ok(()), Duration::ZERO);
    let (mut node_end, lines) = node(identity(0x22), |_| Err("not in the test's list".into()));
    node_end.gate = Some(gate);
    let r = run(operator.clone(), |_| Ok(()), (node_end, lines), Fault::None, Fault::None);
    let outcome = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Err(Error::Refused(Refusal::NotAllowed))), "{outcome:?}");
    tokio::time::timeout(LIMIT, r.node_task).await.unwrap().unwrap();
    assert_eq!(r.opened.load(Ordering::SeqCst), 0);
    assert!(asked.lock().unwrap().is_empty(), "a key that the door refused was asked of");
    let lines = r.lines.lock().unwrap().join("\n");
    assert!(lines.contains(&format!("refused the operator key {}: not in the test's list", operator.public())));
}

/// A yes lets the key in, and the node's line says by the door and the yes;
/// a session of the same key while the first is open comes in by the yes's
/// cover, with no question; a node with no person comes in by the door.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_yes_lets_the_key_in_and_the_line_says_by_what() {
    let operator = identity(0x11);
    let (gate, asked) = person(Ok(()), Duration::ZERO);
    let (mut node_end, lines) = node(identity(0x22), |_| Ok(()));
    node_end.gate = Some(gate);
    let mut first = run(operator.clone(), |_| Ok(()), (node_end.clone(), lines.clone()), Fault::None, Fault::None);
    assert_eq!(echo_back(&mut first.app, b"one").await.unwrap(), b"one");
    let mut second = run(operator.clone(), |_| Ok(()), (node_end, lines.clone()), Fault::None, Fault::None);
    assert_eq!(echo_back(&mut second.app, b"two").await.unwrap(), b"two");
    assert_eq!(asked.lock().unwrap().len(), 1, "the second session came in by the cover");
    for r in [&mut first, &mut second] {
        r.app.shutdown().await.unwrap();
    }
    for r in [first, second] {
        assert!(tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap().is_ok());
    }
    let lines = lines.lock().unwrap().join("\n");
    let key = operator.public();
    assert!(lines.contains(&format!("the operator key {key} came in, by the door and a yes of the node's person")));
    let covered = format!("the operator key {key} came in, by the door and the cover of a yes of the node's person");
    assert!(lines.contains(&covered), "{lines}");

    let mut plain = run(operator, |_| Ok(()), node(identity(0x22), |_| Ok(())), Fault::None, Fault::None);
    assert_eq!(echo_back(&mut plain.app, b"three").await.unwrap(), b"three");
    let lines = plain.lines.lock().unwrap().join("\n");
    assert!(lines.contains(&format!("the operator key {key} came in, by the door")), "{lines}");
    assert!(!lines.contains("person"), "{lines}");
}

/// Two sessions of one key that come together raise one question, and its
/// yes lets both in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_of_one_key_that_come_together_raise_one_question() {
    let operator = identity(0x11);
    let (gate, asked) = person(Ok(()), Duration::from_secs(2));
    let (mut node_end, lines) = node(identity(0x22), |_| Ok(()));
    node_end.gate = Some(gate);
    let mut a = run(operator.clone(), |_| Ok(()), (node_end.clone(), lines.clone()), Fault::None, Fault::None);
    let mut b = run(operator.clone(), |_| Ok(()), (node_end, lines.clone()), Fault::None, Fault::None);
    let (one, two) = tokio::join!(echo_back(&mut a.app, b"a"), echo_back(&mut b.app, b"b"));
    assert_eq!((one.unwrap(), two.unwrap()), (b"a".to_vec(), b"b".to_vec()));
    assert_eq!(asked.lock().unwrap().len(), 1, "one question for the key");
    let lines = lines.lock().unwrap().join("\n");
    assert_eq!(lines.matches("by the door and a yes of the node's person").count(), 2, "{lines}");
}

/// An answer that comes after a step's limit of the handshake still lets the
/// operator in: it waits longer for the verdict of a node that asks.
#[tokio::test(start_paused = true)]
async fn the_operator_waits_for_an_answer_past_a_step_s_limit() {
    let operator = identity(0x11);
    let (gate, asked) = person(Ok(()), HANDSHAKE_LIMIT + Duration::from_secs(20));
    let (mut node_end, lines) = node(identity(0x22), |_: &PublicKey| Ok(()));
    node_end.gate = Some(gate);
    let mut r = run(operator, |_| Ok(()), (node_end, lines), Fault::None, Fault::None);
    let started = tokio::time::Instant::now();
    r.app.write_all(b"late").await.unwrap();
    let mut back = [0u8; 4];
    // Past the harness's limit, which is a step's: the echo follows the answer.
    let wait = Duration::from_secs(120);
    tokio::time::timeout(wait, r.app.read_exact(&mut back)).await.expect("the echo, after the answer").unwrap();
    assert_eq!(&back, b"late");
    assert!(started.elapsed() >= HANDSHAKE_LIMIT, "the answer came within a step's limit");
    assert_eq!(asked.lock().unwrap().len(), 1);
}
