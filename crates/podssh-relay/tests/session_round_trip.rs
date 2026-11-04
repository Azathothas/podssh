//! Liveness in round trips (T-663), on tokio's paused clock. Stand-in relay
//! hosts delay each piece one way, so a link has a round trip of its own,
//! and one can stop carrying the bytes of a link with no word to either end.
//!
//! On a link of 50 ms, whose `ACK`s the far end holds 200 ms, a question
//! that nothing answers opens a spare link 1 s after it was asked, where a
//! fixed bound waited 3 s (T-305); before the link answered anything, the
//! spare waits those 3 s. A link whose answers take 1.1 s gets no spare. A
//! tick of the clocks that comes late, as after a sleep of the host, sends a
//! `PING` at once, and on a link that died in the sleep the spare opens 1 s
//! after the wake. Planted: a fixed 3 s fails the first; a floor of 1 s for
//! each link fails the slow link; no check of the clocks fails the last two.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use podssh_relay::session::beside::{SPARE_AFTER, SPARE_SOONEST};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::pump::PING_EVERY;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, Decoder, End, Ended, OsEntropy, Record, Role, Settings};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(120);
const MS: Duration = Duration::from_millis(1);

/// The records that passed one way, with the time of each.
type Log = Arc<Mutex<Vec<(Instant, Record)>>>;
/// The session's notes, with the time of each.
type Notes = Arc<Mutex<Vec<(Instant, Note)>>>;

/// One way of a stand-in relay host: each piece goes on `delay` after it
/// came, in order, and none while `stalled` is set; `log` notes the records
/// as they come.
fn one_way(
    mut from: ReadHalf<DuplexStream>,
    mut to: WriteHalf<DuplexStream>,
    delay: Duration,
    stalled: Arc<AtomicBool>,
    log: Option<Log>,
) {
    let (pieces, mut due) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let (mut buf, mut decoder) = (vec![0u8; 16 * 1024], Decoder::new());
        while let Ok(n) = from.read(&mut buf).await {
            if n == 0 {
                return;
            }
            if let Some(log) = &log {
                decoder.push(&buf[..n]);
                while let Ok(Some(record)) = decoder.next() {
                    log.lock().unwrap().push((Instant::now(), record));
                }
            }
            if pieces.send((Instant::now() + delay, buf[..n].to_vec())).is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, piece)) = due.recv().await {
            tokio::time::sleep_until(at).await;
            while stalled.load(Ordering::SeqCst) {
                tokio::time::sleep(MS * 50).await;
            }
            if to.write_all(&piece).await.is_err() {
                return;
            }
        }
    });
}

/// A link through a stand-in relay host that delays each piece by `delay`
/// one way, a round trip of twice that; its flag stalls it both ways. The
/// client's records are noted in `up`.
fn relayed(delay: Duration, up: Option<Log>) -> (DuplexStream, DuplexStream, Arc<AtomicBool>) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let stalled = Arc::new(AtomicBool::new(false));
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    one_way(cr, fw, delay, stalled.clone(), up);
    one_way(fr, cw, delay, stalled.clone(), None);
    (client, far, stalled)
}

/// A far end that keeps its sessions, as a node does; a new session's
/// target goes to `targets`.
fn far_end(mut links: mpsc::UnboundedReceiver<DuplexStream>, targets: mpsc::UnboundedSender<DuplexStream>) {
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(600)));
    let settings = Settings::default();
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let (keeper, targets) = (keeper.clone(), targets.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                if accepted.established().resumed {
                    let _ = keeper.run_resumed(accepted).await;
                } else {
                    let (target, app) = tokio::io::duplex(PIPE);
                    let _ = targets.send(app);
                    keeper.run_new(accepted, target).await;
                }
            });
        }
    });
}

/// `len` bytes from `from`, within the limit.
async fn carried<R: AsyncRead + Unpin>(from: &mut R, len: usize) -> Vec<u8> {
    let mut got = vec![0u8; len];
    tokio::time::timeout(LIMIT, from.read_exact(&mut got)).await.expect("the bytes came in time").unwrap();
    got
}

/// A session with spare links, whose links delay each piece by `delay` one
/// way; what the test holds of it.
struct Run {
    /// Stalls the first link, with no word to either end.
    first: Arc<AtomicBool>,
    /// The client's records on the first link.
    up: Log,
    app_r: ReadHalf<DuplexStream>,
    app_w: WriteHalf<DuplexStream>,
    target_r: ReadHalf<DuplexStream>,
    target_w: WriteHalf<DuplexStream>,
    notes: Notes,
    session: JoinHandle<Outcome>,
}

impl Run {
    async fn start(delay: Duration) -> Run {
        let (links_tx, links_rx) = mpsc::unbounded_channel();
        let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
        far_end(links_rx, targets_tx);
        let up: Log = Arc::default();
        let (client_link, far_link, first) = relayed(delay, Some(up.clone()));
        links_tx.send(far_link).unwrap();
        let settings = Settings { spare_links: true, ..Settings::default() };
        let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
        // Each new link is as fast as the first, and is not stalled.
        let connect = move |_: &Ended| {
            let links_tx = links_tx.clone();
            async move {
                let (client_link, far_link, _stalled) = relayed(delay, None);
                links_tx.send(far_link).unwrap();
                Next::Link(client_link)
            }
        };
        let notes: Notes = Arc::default();
        let note = {
            let notes = notes.clone();
            move |n: Note| notes.lock().unwrap().push((Instant::now(), n))
        };
        let (app, app_end) = tokio::io::duplex(PIPE);
        let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
        let target = targets_rx.recv().await.unwrap();
        let (target_r, target_w) = tokio::io::split(target);
        let (app_r, app_w) = tokio::io::split(app);
        Run { first, up, app_r, app_w, target_r, target_w, notes, session }
    }

    /// `bytes` from the application to the target.
    async fn say(&mut self, bytes: &[u8]) {
        self.app_w.write_all(bytes).await.unwrap();
        assert_eq!(carried(&mut self.target_r, bytes.len()).await, bytes);
    }

    fn notes(&self) -> Vec<(Instant, Note)> {
        self.notes.lock().unwrap().clone()
    }

    /// When the first spare link opened.
    fn spare_at(&self) -> Option<Instant> {
        self.notes().into_iter().find(|(_, n)| matches!(n, Note::Spare { .. })).map(|(at, _)| at)
    }

    /// The times of the client's `PING`s on the first link, from `from` on.
    fn pings(&self, from: Instant) -> Vec<Instant> {
        let up = self.up.lock().unwrap();
        up.iter().filter(|(at, r)| *at >= from && matches!(r, Record::Ping { .. })).map(|(at, _)| *at).collect()
    }

    /// The session goes on both ways, then ends at this side.
    async fn goes_on_and_ends(mut self) {
        self.say(b"after").await;
        self.target_w.write_all(b"back").await.unwrap();
        assert_eq!(carried(&mut self.app_r, 4).await, b"back");
        let Run { app_r, app_w, session, .. } = self;
        drop((app_r, app_w));
        let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
        let ended = matches!(&outcome, Outcome::Layer(e) if matches!(e.end, End::LocalEnd | End::Closed(_)));
        assert!(ended, "{outcome:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn on_a_link_of_50_ms_a_spare_opens_1_s_after_a_question_that_nothing_answers() {
    let mut run = Run::start(MS * 25).await;
    // A question that the far end answers: its `ACK` times the round trip.
    run.say(b"before").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The relay host stops carrying the link; the next bytes wait in it.
    run.first.store(true, Ordering::SeqCst);
    let asked = Instant::now();
    run.say(b"question").await;
    let took = asked.elapsed();
    let notes = run.notes();
    let spare = run.spare_at().unwrap_or_else(|| panic!("no spare link: {notes:?}")) - asked;
    assert!(spare >= SPARE_SOONEST && spare <= MS * 1200, "the spare opened {spare:?} after the question: {notes:?}");
    assert!(took < MS * 1500, "the bytes came {took:?} after the stall: {notes:?}");
    assert!(notes.iter().any(|(_, n)| matches!(n, Note::Resumed { .. })), "{notes:?}");
    run.goes_on_and_ends().await;
}

#[tokio::test(start_paused = true)]
async fn before_the_link_answered_anything_a_spare_waits_the_3_s_of_before() {
    let mut run = Run::start(MS * 25).await;
    run.first.store(true, Ordering::SeqCst);
    let asked = Instant::now();
    run.say(b"question").await;
    let notes = run.notes();
    let spare = run.spare_at().unwrap_or_else(|| panic!("no spare link: {notes:?}")) - asked;
    assert!(spare >= SPARE_AFTER && spare <= SPARE_AFTER + MS * 200, "{spare:?}: {notes:?}");
    run.goes_on_and_ends().await;
}

#[tokio::test(start_paused = true)]
async fn a_link_whose_answers_take_1_1_s_gets_no_spare() {
    // 450 ms each way, and the far end's `ACK` held 200 ms: each key waits
    // 1.1 s for its answer, more than the floor of 1 s.
    let mut run = Run::start(MS * 450).await;
    for key in 0..6u8 {
        run.say(&[key]).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let notes = run.notes();
    assert!(!notes.iter().any(|(_, n)| matches!(n, Note::Spare { .. })), "a spare beside a slow link: {notes:?}");
    run.goes_on_and_ends().await;
}

#[tokio::test(start_paused = true)]
async fn a_tick_that_comes_late_sends_a_ping_at_once() {
    let mut run = Run::start(MS * 25).await;
    run.say(b"before").await;
    let begun = Instant::now();
    // Ticks on time ask nothing.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(run.pings(begun), Vec::<Instant>::new(), "no PING while the ticks come on time");

    // The host was away 4 s that the timers did not count.
    tokio::time::advance(Duration::from_secs(4)).await;
    let woke = Instant::now();
    tokio::time::sleep(MS * 100).await;
    let pings = run.pings(woke);
    assert!(woke < begun + PING_EVERY, "before the heartbeat's own PING");
    assert!(pings.first().is_some_and(|at| *at < woke + MS * 10), "a PING at the wake: {pings:?}");
    run.goes_on_and_ends().await;
}

#[tokio::test(start_paused = true)]
async fn a_host_that_wakes_to_a_dead_link_opens_a_spare_1_s_after_the_wake() {
    let mut run = Run::start(MS * 25).await;
    run.say(b"before").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The link dies in a sleep of the host, and nothing asks after it: the
    // application is idle.
    run.first.store(true, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(5)).await;
    let woke = Instant::now();
    let deadline = woke + Duration::from_secs(30);
    while !run.notes().iter().any(|(_, n)| matches!(n, Note::Resumed { .. })) {
        assert!(Instant::now() < deadline, "no resume: {:?}", run.notes());
        tokio::time::sleep(MS * 10).await;
    }
    let notes = run.notes();
    let spare = run.spare_at().expect("a spare link") - woke;
    assert!(spare >= SPARE_SOONEST && spare <= MS * 1200, "the spare opened {spare:?} after the wake: {notes:?}");
    run.goes_on_and_ends().await;
}
