//! The warning before the relay's idle cut (T-463), on tokio's paused clock.

use std::sync::Mutex;

use super::*;
use crate::notice::{title as stack, Action, Notice, Place, Silence};

const CUT: Duration = Duration::from_secs(180);

/// A watch of `crossed` with the default lead, its steps kept.
fn watching(crossed: &Crossed) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<Step>>>) {
    let steps = Arc::new(Mutex::new(Vec::new()));
    let (clock, into) = (crossed.clone(), steps.clone());
    let idle = Idle::new(CUT, lead(CUT, None).unwrap());
    let task = tokio::spawn(async move {
        watch(move || Some(clock.last()), idle, move |step| into.lock().unwrap().push(step.clone())).await;
    });
    (task, steps)
}

/// GitHub #98's `sleep 175`: nothing for 150 s gives the warning once, 30 s
/// before the cut, and no second one while nothing crosses.
#[tokio::test(start_paused = true)]
async fn the_warning_comes_once_after_150_s_of_nothing() {
    let crossed = Crossed::default();
    let (task, steps) = watching(&crossed);
    tokio::time::sleep(Duration::from_secs(149)).await;
    assert!(steps.lock().unwrap().is_empty(), "nothing before 150 s");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let want = Step::Warn { ends_in: Duration::from_secs(30), quiet: Duration::from_secs(150) };
    assert_eq!(steps.lock().unwrap().as_slice(), std::slice::from_ref(&want));
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert_eq!(steps.lock().unwrap().as_slice(), [want], "once");
    task.abort();
}

/// A payload at 140 s moves the warning to 150 s after it.
#[tokio::test(start_paused = true)]
async fn a_payload_at_140_s_moves_the_warning() {
    let crossed = Crossed::default();
    let (task, steps) = watching(&crossed);
    tokio::time::sleep(Duration::from_secs(140)).await;
    crossed.mark();
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(steps.lock().unwrap().is_empty(), "no warning at 160 s: a payload crossed at 140 s");
    tokio::time::sleep(Duration::from_secs(131)).await;
    assert!(matches!(steps.lock().unwrap().as_slice(), [Step::Warn { .. }]), "at 290 s, 150 s after it");
    task.abort();
}

/// A payload after the warning ends it, and the next silence warns again.
#[tokio::test(start_paused = true)]
async fn a_payload_after_the_warning_ends_it() {
    let crossed = Crossed::default();
    let (task, steps) = watching(&crossed);
    tokio::time::sleep(Duration::from_secs(155)).await;
    crossed.mark();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = steps.lock().unwrap().clone();
    assert!(matches!(got.as_slice(), [Step::Warn { .. }, Step::Crossed]), "{got:?}");
    tokio::time::sleep(Duration::from_secs(150)).await;
    assert_eq!(steps.lock().unwrap().len(), 3, "a new silence warns again");
    task.abort();
}

/// The watch ends with its session.
#[tokio::test(start_paused = true)]
async fn the_watch_ends_with_its_session() {
    let idle = Idle::new(CUT, Duration::from_secs(30));
    let task = tokio::spawn(watch(|| None, idle, |_| panic!("no step after the end")));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(task.is_finished());
}

/// The lead: 30 s, a sixth of a shorter cut, the one asked, never at the
/// cut, and none for 0.
#[test]
fn the_lead_of_the_warning() {
    let s = Duration::from_secs;
    assert_eq!(lead(CUT, None), Some(s(30)));
    assert_eq!(lead(s(90), None), Some(s(15)));
    assert_eq!(lead(CUT, Some(s(60))), Some(s(60)));
    assert_eq!(lead(CUT, Some(s(500))), Some(s(179)));
    assert_eq!(lead(CUT, Some(Duration::ZERO)), None);
    assert_eq!(lead(s(1), None), None);
}

/// The words, which name the cut and what keeps the session.
#[test]
fn the_words_of_the_warning() {
    let s = Duration::from_secs;
    assert_eq!(
        line(s(30), s(150), CUT),
        "the relay ends this session in 30 s, as nothing crossed it for 150 s: a key, or -o ServerAliveInterval \
         below 180, keeps it"
    );
    assert_eq!(title(s(30)), "podssh: the relay ends this session in 30 s, a key keeps it");
}

/// In the window's title, where the session shows T-302's notice there: up
/// at the next tick, and down with the far end's next bytes, which also end
/// the warning.
#[tokio::test(start_paused = true)]
async fn the_title_holds_the_warning_until_the_next_bytes() {
    let silence = Silence::default();
    silence.attach(|| None);
    let mut notice = Notice::new(Place::Title, &silence, "h", Some(b'~'));
    assert!(silence.titled());
    assert_eq!(notice.tick(Instant::now()), None, "no warning yet");
    silence.set_idle(Some(title(Duration::from_secs(30))));
    let mut up = stack::PUSH.to_vec();
    up.extend_from_slice(&stack::set(&title(Duration::from_secs(30))));
    assert_eq!(notice.tick(Instant::now()), Some(Action::Write(up)));
    assert_eq!(notice.tick(Instant::now()), None, "once");
    assert_eq!(notice.before_output(b"x", false), stack::POP.to_vec(), "the user's title before the bytes");
    assert_eq!(silence.idle(), None, "the bytes crossed: the warning is past");
    assert_eq!(notice.tick(Instant::now()), None);
}

/// The warning taken back by the watch, with no bytes of the far end: a key
/// crossed the other way.
#[tokio::test(start_paused = true)]
async fn the_title_comes_down_when_a_key_crossed() {
    let silence = Silence::default();
    silence.attach(|| None);
    let mut notice = Notice::new(Place::Title, &silence, "h", None);
    silence.set_idle(Some(title(Duration::from_secs(30))));
    assert!(matches!(notice.tick(Instant::now()), Some(Action::Write(_))));
    silence.set_idle(None);
    assert_eq!(notice.tick(Instant::now()), Some(Action::Write(stack::POP.to_vec())));
    drop(notice);
    assert!(!silence.titled());
}
