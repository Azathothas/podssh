//! The tests of a list of keys at a URL (T-646): its copy is read until its
//! TTL and its stale window pass, then no one mints; a fetch that fails
//! leaves the copy to age; an answer of the server's is the list, and one
//! that is no list lets no one mint; and the list is fetched again each TTL,
//! on a paused clock.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::identity::{Identity, PublicKey};
use crate::serve::brake::Clock;
use crate::serve::keys::Whom;

const TTL_MS: u64 = 300_000;
const STALE_MS: u64 = 3_600_000;
/// The time of the first copy, in ms since the epoch.
const T0: u64 = 1_800_000_000_000;

/// A server of the test: each fetch takes the next answer, and the last
/// one again when it is the last.
struct Served {
    answers: Mutex<Vec<Result<Vec<u8>, String>>>,
    asked: Arc<AtomicUsize>,
}

impl Fetch for Served {
    fn fetch(&self) -> Fetching<'_> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let answer = match answers.len() {
            0 => Err("no answer".to_string()),
            1 => answers[0].clone(),
            _ => answers.remove(0),
        };
        Box::pin(async move { answer })
    }

    fn shown(&self) -> String {
        "https://keys.test/...".to_string()
    }
}

fn key(seed: u8) -> PublicKey {
    Identity::from_seed(&[seed; 32]).public()
}

/// The line of the list that holds the key of `seed`.
fn line(seed: u8) -> String {
    format!("{} the key of seed {seed}\n", key(seed).fingerprint())
}

/// A copy of the answers of [`Served`], on a clock that the test moves, and
/// the count of its fetches.
fn copy(answers: Vec<Result<Vec<u8>, String>>) -> (Arc<AtomicU64>, Arc<AtomicUsize>, Arc<Fetched>) {
    let now = Arc::new(AtomicU64::new(T0));
    let read = now.clone();
    let asked = Arc::new(AtomicUsize::new(0));
    let served = Served { answers: Mutex::new(answers), asked: asked.clone() };
    let clock: Clock = Arc::new(move || read.load(Ordering::SeqCst));
    let (ttl, stale) = (Duration::from_millis(TTL_MS), Duration::from_millis(STALE_MS));
    (now, asked, Arc::new(Fetched::on_clock(Box::new(served), ttl, stale, clock)))
}

/// The plant reads a copy past its stale window: this test fails then.
#[test]
fn a_copy_is_read_until_its_ttl_and_its_stale_window_pass_then_no_one_mints() {
    let (now, _, fetched) = copy(Vec::new());
    let none = fetched.read().unwrap_err();
    assert!(none.contains("no copy of the list has come"), "{none}");
    fetched.put(Ok(line(1).into_bytes()), T0).unwrap();
    assert!(fetched.read().unwrap().admits(&key(1)));
    // Its server fails at the TTL: the copy ages.
    let failed = fetched.put(Err("HTTP 503 Service Unavailable".to_string()), T0 + TTL_MS);
    assert_eq!(failed.err().as_deref(), Some("HTTP 503 Service Unavailable"));
    now.store(T0 + TTL_MS + STALE_MS - 1, Ordering::SeqCst);
    assert!(fetched.read().unwrap().admits(&key(1)), "within its stale window");
    now.store(T0 + TTL_MS + STALE_MS, Ordering::SeqCst);
    let stale = fetched.read().unwrap_err();
    assert!(stale.starts_with("https://keys.test/...: ") && stale.contains("past its TTL and its stale window"));
    // As the role reads it: no key of the list, and none mints.
    let list = List::Fetched(fetched.clone());
    assert!(list.read().is_err());
    assert_eq!(Whom::list(&list).count(), 0, "a copy too old lets no key in");
    // A fetch that works again lets the list's keys in.
    fetched.put(Ok(line(1).into_bytes()), T0 + TTL_MS + STALE_MS).unwrap();
    assert!(list.read().unwrap().admits(&key(1)));
    assert_eq!(Whom::list(&list).count(), 1);
}

#[test]
fn an_answer_is_the_list_whatever_it_holds_and_one_that_is_no_list_lets_no_one_mint() {
    let (_, _, fetched) = copy(Vec::new());
    fetched.put(Ok(format!("# the owners\n{}{}", line(1), line(2)).into_bytes()), T0).unwrap();
    assert_eq!(fetched.read().unwrap().len(), 2);
    // A key taken off at the next answer is refused at once.
    fetched.put(Ok(line(2).into_bytes()), T0 + 1).unwrap();
    let list = fetched.read().unwrap();
    assert!(!list.admits(&key(1)) && list.admits(&key(2)));
    // A page that is no list: each of its lines is no key.
    let page = fetched.put(Ok(b"<html><body>sign in</body></html>\n".to_vec()), T0 + 2).unwrap();
    assert!(page.is_empty());
    assert_eq!(page.bad_lines(), &[1]);
    assert!(!fetched.read().unwrap().admits(&key(2)), "no key mints");
    // Bytes that are no text hold no key.
    assert!(fetched.put(Ok(vec![0xff, 0xfe, 0x00]), T0 + 3).unwrap().is_empty());
    // A file of the host is a list as before, by its path.
    let file = List::from(std::path::PathBuf::from("allow"));
    assert!(file.fetched().is_none() && file.shown() == "allow");
    assert_eq!(format!("{:?}", List::Fetched(fetched)), "Fetched(\"https://keys.test/...\")");
}

#[tokio::test(start_paused = true)]
async fn the_list_is_fetched_again_each_ttl_and_a_failure_is_said() {
    let answers = vec![Ok(line(1).into_bytes()), Err("HTTP 502 Bad Gateway".to_string()), Ok(line(2).into_bytes())];
    let (_, asked, fetched) = copy(answers);
    fetched.refresh().await.expect("the first copy, as the role starts");
    let said = Arc::new(Mutex::new(Vec::<String>::new()));
    let lines = said.clone();
    fetched.start(Some(Arc::new(move |line: &str| lines.lock().unwrap().push(line.to_string()))));
    fetched.start(None);
    assert_eq!(asked.load(Ordering::SeqCst), 1, "nothing more before the TTL");
    tokio::time::sleep(Duration::from_millis(TTL_MS + 10)).await;
    assert_eq!(asked.load(Ordering::SeqCst), 2, "one fetch at the TTL, of one task");
    let failed = "https://keys.test/...: HTTP 502 Bad Gateway; its copy is read until its stale window passes";
    assert_eq!(*said.lock().unwrap(), vec![failed.to_string()]);
    assert!(fetched.read().unwrap().admits(&key(1)), "the copy of before");
    tokio::time::sleep(Duration::from_millis(TTL_MS)).await;
    assert_eq!(asked.load(Ordering::SeqCst), 3);
    let list = fetched.read().unwrap();
    assert!(list.admits(&key(2)) && !list.admits(&key(1)), "a key taken off is refused after the TTL");
    assert_eq!(said.lock().unwrap().last().map(String::as_str), Some("https://keys.test/...: fetched again, 1 key"));
}
