//! The client's session across links (T-153, T-155). When a link is lost,
//! the caller gives a new one (a new relay connection, through any relay
//! host or road), the handshake proves the session's secret, and each side
//! sends again from the other's received offset. SSH above sees no gap.
//!
//! A `CLOSE` or a `REFUSE` ends the session; each other loss is resumed,
//! with a backoff between attempts, until the deadline. The caller decides,
//! from what the transport said (a relay's close code), whether a loss may
//! be resumed at all. A `CLOSE` that its link lost goes again on the next
//! (T-262).
//!
//! Before a link meets the relay's limits, the session moves: a new link is
//! opened, and its far end greets, while the old one still carries the
//! session; then the old one stops at a record boundary and says `RETIRE`,
//! and only then does the new link's handshake take the offsets. An offset
//! taken earlier could fall behind the acknowledgements that the old link
//! still carried, and ask for bytes that the other side no longer keeps
//! (T-262). A link that went silent gets a spare link beside it in the same
//! way, which takes the session when it greets first (T-305, `beside`).

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::beside::{self, failure, Beside, Plan};
use super::client::{self, Client, ClientError, Outcome};
use super::deadline::{away, client_wait, forgotten};
use super::decode::Decoder;
use super::handshake::{Ask, ClientHandshake, Established, HandshakeError};
use super::link::Link;
use super::pump::{self, Carry, End, Ended, Watch};
use super::record::{kind, RefuseCode};
use super::secret::{Entropy, Secret};
use super::Settings;

/// How long after a loss the session waits for a new link, at both ends:
/// the exit of M6 asks for a stall of 3 minutes to pass, and the backoff
/// adds up to 45 s (the decision of T-153).
pub const RESUME_DEADLINE: Duration = Duration::from_secs(600);
/// The bytes of a link, both ways, at which the session moves: 75 % of the
/// relay's 64 MiB, so the bytes in flight and a second try fit in the rest
/// (the decision of T-155).
pub const MOVE_BYTES: u64 = 48 << 20;
/// The age of a link at which the session moves: an hour under the relay's
/// 12 h.
pub const MOVE_AGE: Duration = Duration::from_secs(11 * 3600);
/// How long a `REFUSE` may take to go out before the link is dropped.
const REFUSE_WAIT: Duration = Duration::from_secs(5);

/// What the caller gives in place of a lost link, or for a move.
pub enum Next<L> {
    /// A new link to the far end, nothing read from it yet.
    Link(L),
    /// No link this time; the driver waits its backoff and asks again.
    Retry(String),
    /// The session must not resume, for this reason (a close that says so).
    Stop(String),
}

/// A step of the session across links, each worth one line to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// The link was lost; the session waits for a new one.
    Lost { why: String },
    /// An attempt failed; the next comes after `wait`.
    Retry { why: String, wait: Duration },
    /// A new link carries the session, `resent` bytes sent again.
    Resumed { resent: u64, after: Duration },
    /// Before the relay's limits, the session moved to a new link: the old
    /// one had carried `bytes` in `age`.
    Moved { bytes: u64, age: Duration, resent: u64 },
    /// A move failed; the old link goes on until it ends, then a resume.
    MoveFailed { why: String },
    /// The link said nothing for `quiet`: a spare link opens beside it
    /// (T-305).
    Spare { quiet: Duration },
    /// The spare link closed, as the old link spoke first, or it failed;
    /// the old link goes on.
    SpareClosed { why: String },
}

/// Why a resume on a new link failed.
#[derive(Debug)]
pub(super) enum Failed {
    /// Worth another attempt: the link failed, or took too long.
    Again(String),
    /// The far end cannot resume the session.
    Final(String),
    /// The far end does not know the session (any more): it ended there, or
    /// its deadline passed.
    Forgotten(String),
}

impl Failed {
    pub(super) fn reason(self) -> String {
        match self {
            Failed::Again(why) | Failed::Final(why) | Failed::Forgotten(why) => why,
        }
    }
}

/// A new link whose far end greeted: the bytes read so far, the `GREETING`
/// first.
pub(super) struct Greeted<L> {
    link: L,
    first: Vec<u8>,
}

/// A new link past its handshake, its bytes to send again not yet chosen.
struct Shaken<L> {
    link: L,
    decoder: Decoder,
    peer_received: u64,
}

/// What came of the resumes after a loss.
enum Resumed<L> {
    /// A new link carries the session.
    On(L, Decoder),
    /// The session is over, with this end.
    Over(End),
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Carry the session of `client` between `app` and its links until it ends.
/// `connect` is asked for a new link after each loss, with the end of the
/// lost one, and for a move or a spare link beside a silent one, with
/// [`End::Moving`]; `note` hears of each loss, attempt, resume, move and
/// spare. With no layer at the far end, the bytes pass as they are, on the
/// first link only.
pub async fn run<L, A, C, F, N>(
    client: Client<L>,
    mut app: A,
    mut connect: C,
    mut note: N,
    entropy: &mut (dyn Entropy + Send),
) -> Outcome
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
    A: AsyncRead + AsyncWrite + Unpin + Send,
    C: FnMut(&Ended) -> F,
    F: Future<Output = Next<L>>,
    N: FnMut(Note),
{
    let parts = client.into_parts();
    let Some((mut decoder, established)) = parts.layer else {
        return Client::from_parts(parts).run(app).await;
    };
    let settings = parts.settings;
    let hearing = parts.hearing;
    let mut link = parts.link;
    let mut carry = Carry::new(settings.link(&established)).with_hearing(hearing.clone());
    let moves = lock(&carry.state).moves();
    let heartbeat = lock(&carry.state).heartbeat();
    loop {
        let watch = Watch::moving_at(if moves { settings.move_bytes } else { 0 });
        let started = Instant::now();
        let state = carry.state.clone();
        // A session whose application ended is closing: its `CLOSE` goes on
        // the link that it has, with no new link beside it.
        let closing = carry.app_ended();
        // The steps of the watch beside the link, said as they come.
        let (said, mut steps) = mpsc::unbounded_channel();
        let (ended, greeted) = {
            let pump = pump::run(&mut app, link, decoder, &mut carry, &watch);
            // A new link beside this one, greeted while this one goes on: a
            // move before the relay's limits, or a spare when it went silent.
            let plan = Plan {
                moves,
                spares: settings.spare_links,
                heartbeat,
                move_at: started + settings.move_age,
                closing,
                watch: &watch,
                state: &state,
                hearing: &hearing,
                said: &said,
            };
            let beside = beside::next(plan, &mut connect);
            tokio::pin!(pump);
            tokio::pin!(beside);
            loop {
                tokio::select! {
                    ended = &mut pump => break (ended, None),
                    Some(step) = steps.recv() => note(step),
                    (why, greeted) = &mut beside => {
                        // The application ended while the new link greeted:
                        // the session closes on the old one.
                        if closing || watch.app_ended.load(Ordering::SeqCst) {
                            break ((&mut pump).await, None);
                        }
                        // The old link stops at a record boundary, and a move
                        // retires it; a spare's old link carries nothing to
                        // say it to. The new one's handshake then takes the
                        // offsets.
                        watch.retire.store(why == Beside::Move, Ordering::SeqCst);
                        watch.stop.notify_one();
                        break ((&mut pump).await, Some((why, greeted)));
                    }
                }
            }
        };
        while let Ok(step) = steps.try_recv() {
            note(step);
        }
        let bytes = watch.bytes.load(Ordering::Relaxed);
        // A spare that takes the session says the loss before its resume,
        // and a loss is said once.
        let mut lost_said = false;
        if let Some((why, greeted)) = greeted {
            if ended.end.resumable() {
                // A spare that takes the session is a resume after a loss.
                let lost = Instant::now();
                if let Beside::Spare(quiet) = why {
                    let why = format!("the link said nothing for {} s, and a spare link answered", quiet.as_secs());
                    note(Note::Lost { why });
                    lost_said = true;
                }
                let resumed = async {
                    let shaken = prove(greeted, &established, &carry.state, settings, entropy).await?;
                    resend(shaken, &mut carry).await
                };
                match tokio::time::timeout(client::HANDSHAKE_LIMIT, resumed).await {
                    Ok(Ok((new, new_decoder, resent))) => {
                        // The far end's `ACCEPT` answers each question.
                        hearing.heard();
                        note(match why {
                            Beside::Move => Note::Moved { bytes, age: started.elapsed(), resent },
                            Beside::Spare(_) => Note::Resumed { resent, after: lost.elapsed() },
                        });
                        link = new;
                        decoder = new_decoder;
                        continue;
                    }
                    // This side's application had ended, and the far end forgot
                    // the session: it had the `CLOSE`, and its answer was lost.
                    Ok(Err(Failed::Forgotten(_))) if carry.app_ended() => {
                        let _ = app.shutdown().await;
                        let end = End::LocalEnd;
                        return Outcome::Layer(Ended { end, received: ended.received, sent: ended.sent });
                    }
                    Ok(Err(failed @ (Failed::Final(_) | Failed::Forgotten(_)))) => {
                        return gave_up(&mut app, failed.reason(), &ended).await;
                    }
                    // The old link is gone: the session goes on as after a
                    // loss.
                    Ok(Err(Failed::Again(why_not))) => note(after_stop(why, why_not)),
                    Err(_) => note(after_stop(why, "the new link's handshake took too long".into())),
                }
            }
        }
        if !ended.end.resumable() {
            let _ = app.shutdown().await;
            return Outcome::Layer(ended);
        }
        // A resume is a question too: the far end is silent until a new
        // link carries its bytes (T-302).
        carry.hearing().asked();
        if !lost_said {
            note(Note::Lost { why: describe(&ended.end) });
        }
        match resume_loop(&ended, &established, &mut carry, settings, &mut connect, &mut note, entropy).await {
            Resumed::On(new, new_decoder) => {
                hearing.heard();
                link = new;
                decoder = new_decoder;
            }
            Resumed::Over(end) => {
                let _ = app.shutdown().await;
                return Outcome::Layer(Ended { end, received: ended.received, sent: ended.sent });
            }
        }
    }
}

/// The step that says that the new link beside the old one failed after the
/// old one stopped: a move's failure, or, for a spare, whose loss is said,
/// the next attempt, at once.
fn after_stop(why: Beside, why_not: String) -> Note {
    match why {
        Beside::Move => failure(why, why_not),
        Beside::Spare(_) => Note::Retry { why: why_not, wait: Duration::ZERO },
    }
}

async fn gave_up<A: AsyncWrite + Unpin>(app: &mut A, reason: String, ended: &Ended) -> Outcome {
    let _ = app.shutdown().await;
    Outcome::Layer(Ended { end: End::GaveUp(reason), received: ended.received, sent: ended.sent })
}

/// New links after a loss, with the backoff, until one resumes the session or
/// the deadline passes.
async fn resume_loop<L, C, F, N>(
    ended: &Ended,
    established: &Established,
    carry: &mut Carry,
    settings: Settings,
    connect: &mut C,
    note: &mut N,
    entropy: &mut (dyn Entropy + Send),
) -> Resumed<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
    C: FnMut(&Ended) -> F,
    F: Future<Output = Next<L>>,
    N: FnMut(Note),
{
    let lost = Instant::now();
    // The wall clock too: it counts a sleep of the host, which the monotonic
    // clock may not (T-306).
    let lost_wall = (settings.wall_clock)();
    // As long as the far end keeps the session, or less when the user asked.
    let wait = client_wait(&settings, established.peer_deadline);
    let deadline = lost + wait;
    let gave_up = |reason: String| Resumed::Over(End::GaveUp(reason));
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let why = match tokio::time::timeout_at(deadline, connect(ended)).await {
            Err(_) => return gave_up(format!("no new link within {} s", wait.as_secs())),
            Ok(Next::Stop(reason)) => return gave_up(reason),
            Ok(Next::Retry(why)) => why,
            Ok(Next::Link(new)) => {
                let limit = client::HANDSHAKE_LIMIT.min(deadline.saturating_duration_since(Instant::now()));
                let resumed = async {
                    let shaken = prove(greeted(new).await?, established, &carry.state, settings, entropy).await?;
                    resend(shaken, carry).await
                };
                match tokio::time::timeout(limit, resumed).await {
                    Ok(Ok((new, new_decoder, resent))) => {
                        note(Note::Resumed { resent, after: lost.elapsed() });
                        return Resumed::On(new, new_decoder);
                    }
                    // This side's application had ended, and the far end forgot
                    // the session: it had the `CLOSE`, and its answer was lost.
                    Ok(Err(Failed::Forgotten(_))) if carry.app_ended() => return Resumed::Over(End::LocalEnd),
                    // The far end's deadline passed while this side was away,
                    // longer than its own clock counted, as on a host that
                    // slept: the words say so, and how long by the wall clock.
                    Ok(Err(Failed::Forgotten(why))) => {
                        let kept = established.peer_deadline.unwrap_or(settings.resume_deadline);
                        let gone = away(lost_wall, (settings.wall_clock)(), lost.elapsed());
                        return gave_up(forgotten(&why, kept, &gone));
                    }
                    Ok(Err(failed @ Failed::Final(_))) => return gave_up(failed.reason()),
                    Ok(Err(Failed::Again(why))) => why,
                    Err(_) => format!("the handshake took more than {} s", limit.as_secs()),
                }
            }
        };
        let pause = crate::open::backoff(attempt);
        if Instant::now() + pause >= deadline {
            return gave_up(format!("no new link within {} s: {why}", wait.as_secs()));
        }
        note(Note::Retry { why, wait: pause });
        tokio::time::sleep(pause).await;
    }
}

/// A loss, in words.
fn describe(end: &End) -> String {
    match end {
        End::Lost(Some(e)) => format!("the link failed: {e}"),
        End::Lost(None) => "the link ended with no word from the far end".to_string(),
        End::Broken(e) => format!("the link broke: {e}"),
        End::Closing => "the link ended before the far end answered this side's CLOSE".to_string(),
        End::Stopped | End::Retired => "the link was replaced".to_string(),
        End::Moving => "the link nears the relay's limits".to_string(),
        End::LocalEnd | End::Closed(_) | End::GaveUp(_) => "the session ended".to_string(),
    }
}

/// The far end's first bytes on a new link: a `GREETING`, as on the first
/// link, else the far end no longer speaks the layer.
pub(super) async fn greeted<L>(mut link: L) -> Result<Greeted<L>, Failed>
where
    L: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let n = link.read(&mut buf).await.map_err(|e| Failed::Again(format!("the new link failed: {e}")))?;
    if n == 0 {
        return Err(Failed::Again("the new link ended before the far end greeted".into()));
    }
    if buf[0] != kind::GREETING {
        return Err(Failed::Final("the far end no longer offers the resumable layer".into()));
    }
    buf.truncate(n);
    Ok(Greeted { link, first: buf })
}

/// The resume's handshake on a greeted link: the received offset is taken
/// now, once no other link carries the session to this side, and the far
/// end proves the secret in turn.
async fn prove<L>(
    greeted: Greeted<L>,
    established: &Established,
    state: &Arc<Mutex<Link>>,
    settings: Settings,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Shaken<L>, Failed>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let Greeted { mut link, first } = greeted;
    let received = lock(state).received();
    let ask = Ask::Resume { id: established.id, secret: Secret::from_bytes(*established.secret.bytes()), received };
    let (handshake, open) = ClientHandshake::start(ask, settings.features, entropy)
        .map_err(|e| Failed::Final(format!("the resume could not start: {e}")))?;
    let mut decoder = Decoder::new();
    decoder.push(&first);
    let mut buf = vec![0u8; 64 * 1024];
    match client::shake(&mut link, &mut decoder, handshake, open, &mut buf).await {
        Ok(resumed) => Ok(Shaken { link, decoder, peer_received: resumed.peer_received }),
        Err(ClientError::Handshake(e @ HandshakeError::Refused { code: RefuseCode::UNKNOWN_SESSION, .. })) => {
            Err(Failed::Forgotten(format!("the far end did not resume the session: {e}")))
        }
        Err(ClientError::Handshake(e @ (HandshakeError::Refused { .. } | HandshakeError::BadProof))) => {
            Err(Failed::Final(format!("the far end did not resume the session: {e}")))
        }
        Err(e) => Err(Failed::Again(e.to_string())),
    }
}

/// The bytes from the far end's received offset on, for the new link to
/// send again, once no other link carries the session: the link, its
/// decoder, and the count to send again. The new link's pump sends them
/// while it reads, as the far end sends its own. An offset that this side
/// no longer keeps ends the session, and the far end hears why.
async fn resend<L>(shaken: Shaken<L>, carry: &mut Carry) -> Result<(L, Decoder, u64), Failed>
where
    L: AsyncWrite + Unpin,
{
    let Shaken { mut link, decoder, peer_received } = shaken;
    let mut again = Vec::new();
    let resent = lock(&carry.state).resume(peer_received, &mut again);
    match resent {
        Ok(resent) => {
            carry.send_again(again);
            Ok((link, decoder, resent))
        }
        Err(not_kept) => {
            let _ = tokio::time::timeout(REFUSE_WAIT, client::send(&mut link, &not_kept.refusal())).await;
            Err(Failed::Final(not_kept.to_string()))
        }
    }
}
