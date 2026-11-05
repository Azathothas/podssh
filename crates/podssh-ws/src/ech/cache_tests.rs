//! The cache of lists on a clock that the tests move: a short TTL is served
//! for 30 s, a failed read and a name with no list are asked once and kept
//! for 30 s, a refused name is left alone for 5 minutes, a server's retry
//! configs are served at once, two lookups at once make one read, and the
//! maps stay within their bound.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use super::*;

/// A clock that a test moves.
struct Hand(Arc<Mutex<Instant>>);

impl Clock for Hand {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

/// A cache, and the hand of its clock.
fn cache() -> (Cache, Arc<Mutex<Instant>>) {
    let at = Arc::new(Mutex::new(Instant::now()));
    (Cache::with_clock(Box::new(Hand(at.clone()))), at)
}

fn pass(at: &Arc<Mutex<Instant>>, by: Duration) {
    *at.lock().unwrap() += by;
}

/// A list whose lengths read; the cache keeps any bytes as they are.
const LIST: &[u8] = &[0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00];
const RETRY: &[u8] = &[0x00, 0x04, 0xfe, 0x0d, 0x00, 0x01, 0x07];

type Answer = Result<Option<Published>, String>;

/// A read that counts itself and gives `answer`.
fn read(asked: &AtomicUsize, answer: Answer) -> impl FnOnce() -> std::future::Ready<Answer> + '_ {
    move || {
        asked.fetch_add(1, SeqCst);
        std::future::ready(answer)
    }
}

fn listed(ttl: Option<u32>) -> Answer {
    Ok(Some(Published { list: LIST.to_vec(), ttl }))
}

#[test]
fn a_list_is_kept_for_its_ttl_from_30_s_to_a_day_and_300_s_with_none() {
    assert_eq!(kept_for(None), Duration::from_secs(300));
    assert_eq!(kept_for(Some(5)), Duration::from_secs(30));
    assert_eq!(kept_for(Some(600)), Duration::from_secs(600));
    assert_eq!(kept_for(Some(u32::MAX)), CEILING);
}

/// A TTL of 5 s is served for 30 s, the floor, with no read; then read again.
#[tokio::test]
async fn a_ttl_of_5_s_is_served_for_30_s() {
    let (cache, at) = cache();
    let asked = AtomicUsize::new(0);
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(Some(5)))).await, Lookup::List(LIST.to_vec()));
    pass(&at, Duration::from_secs(29));
    let again = cache.lookup("Relay.Example.", read(&asked, Err("no read was due".into()))).await;
    assert_eq!(again, Lookup::List(LIST.to_vec()), "the same name, in another case and with a final dot");
    assert_eq!(asked.load(SeqCst), 1);
    pass(&at, Duration::from_secs(2));
    assert_eq!(cache.lookup("relay.example", read(&asked, Ok(None))).await, Lookup::None(Why::NotPublished));
    assert_eq!(asked.load(SeqCst), 2, "read again once the 30 s ended");
}

/// A read that failed is kept for 30 s: two cold lookups make one query.
#[tokio::test]
async fn a_failed_read_is_asked_once_and_then_remembered() {
    let (cache, at) = cache();
    let asked = AtomicUsize::new(0);
    let failed = Lookup::None(Why::ReadFailed("no resolver answered".into()));
    assert_eq!(cache.lookup("relay.example", read(&asked, Err("no resolver answered".into()))).await, failed);
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, failed);
    assert_eq!(asked.load(SeqCst), 1);
    pass(&at, MISS);
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, Lookup::List(LIST.to_vec()));
    assert_eq!(asked.load(SeqCst), 2);
}

/// An answer with no `ech` is no list and no error, and is kept for 30 s.
#[tokio::test]
async fn an_answer_without_a_list_is_no_list_and_is_kept() {
    let (cache, at) = cache();
    let asked = AtomicUsize::new(0);
    assert_eq!(cache.lookup("plain.example", read(&asked, Ok(None))).await, Lookup::None(Why::NotPublished));
    pass(&at, Duration::from_secs(29));
    assert_eq!(cache.lookup("plain.example", read(&asked, listed(None))).await, Lookup::None(Why::NotPublished));
    assert_eq!(asked.load(SeqCst), 1);
}

/// A refused name gets no list and no read for 5 minutes, then its record is
/// read again.
#[tokio::test]
async fn a_refused_name_is_left_alone_for_five_minutes() {
    let (cache, at) = cache();
    let asked = AtomicUsize::new(0);
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, Lookup::List(LIST.to_vec()));
    cache.refused("relay.example");
    pass(&at, Duration::from_secs(299));
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, Lookup::None(Why::Cooled));
    assert_eq!(asked.load(SeqCst), 1, "no read while the name is left alone");
    pass(&at, Duration::from_secs(1));
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, Lookup::List(LIST.to_vec()));
    assert_eq!(asked.load(SeqCst), 2);
}

/// A server's retry configs replace the list and are served at once, and a
/// name left alone is no longer.
#[tokio::test]
async fn a_retry_config_is_served_at_once() {
    let (cache, _at) = cache();
    let asked = AtomicUsize::new(0);
    assert_eq!(cache.lookup("relay.example", read(&asked, listed(None))).await, Lookup::List(LIST.to_vec()));
    cache.remember("relay.example", RETRY.to_vec(), NO_TTL);
    assert_eq!(cache.lookup("relay.example", read(&asked, Ok(None))).await, Lookup::List(RETRY.to_vec()));
    cache.refused("other.example");
    cache.remember("other.example", RETRY.to_vec(), Duration::from_secs(1));
    assert_eq!(cache.lookup("other.example", read(&asked, Ok(None))).await, Lookup::List(RETRY.to_vec()));
    assert_eq!(asked.load(SeqCst), 1);
}

/// Two lookups of a cold name at once make one read, and the second takes
/// what the first kept.
#[tokio::test]
async fn two_lookups_at_once_make_one_read() {
    let (cache, _at) = cache();
    let asked = AtomicUsize::new(0);
    let slow = || {
        asked.fetch_add(1, SeqCst);
        async {
            tokio::task::yield_now().await;
            Ok::<_, String>(Some(Published { list: LIST.to_vec(), ttl: Some(60) }))
        }
    };
    let (first, second) = tokio::join!(cache.lookup("relay.example", slow), cache.lookup("relay.example", slow));
    assert_eq!((first, second), (Lookup::List(LIST.to_vec()), Lookup::List(LIST.to_vec())));
    assert_eq!(asked.load(SeqCst), 1);
}

/// Names past the bound push out those that end soonest.
#[tokio::test]
async fn the_maps_stay_within_their_bound() {
    let (cache, _at) = cache();
    let asked = AtomicUsize::new(0);
    for at in 0..MOST + 44 {
        let _ = cache.lookup(&format!("n{at}.example"), read(&asked, Ok(None))).await;
        cache.refused(&format!("r{at}.example"));
    }
    let state = cache.lock();
    assert!(state.names.len() <= MOST && state.cooled.len() <= MOST, "{} {}", state.names.len(), state.cooled.len());
}
