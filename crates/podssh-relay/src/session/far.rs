//! The far end of the layer over tokio streams: a node or `podssh serve`,
//! between a link from the relay and the target of the session.
//!
//! [`accept`] greets the client and runs the handshake, and only then does
//! the caller connect to the target, so that a link that never completes its
//! handshake costs no connection to sshd (T-164). [`serve`] is the whole of
//! one link of a far end that keeps its sessions: each road's far end (the
//! node of the reverse road, the iroh road) runs it.

use std::fmt;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// The budget's words, by another name than the `budget` of `serve`.
use super::budget as words;
use super::deadline;
use super::decode::{DecodeError, Decoder};
use super::handshake::{Established, FarHandshake, HandshakeError, Step};
use super::keep::{admitted_at_once, Admitted, Keeper};
use super::pump::{self, Carry, Ended};
use super::record::{Record, Role};
use super::secret::{Entropy, OsEntropy};
use super::sessions::Sessions;
use super::Settings;

/// How long the client may take to open or resume a session.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);
/// How long a new session's target may take to answer.
pub const TARGET_LIMIT: Duration = Duration::from_secs(10);
/// How long this side's last record on a link may take to go out.
const LAST_WORD_SEND: Duration = Duration::from_secs(5);
/// How long a link stays after this side's last record on it, for the client
/// to read the record and end the link: as long as a `CLOSE` waits for its
/// answer.
const LAST_WORD_WAIT: Duration = Duration::from_secs(10);

/// Why the far end could not accept the link.
#[derive(Debug)]
pub enum FarError {
    /// The link failed or ended in the handshake.
    Io(std::io::Error),
    /// The client sent bytes that are not records of the layer.
    Decode(DecodeError),
    /// The handshake failed; a `REFUSE` went out when it could.
    Handshake(HandshakeError),
    /// The handshake took longer than [`HANDSHAKE_LIMIT`].
    Timeout,
}

impl fmt::Display for FarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FarError::Io(e) => write!(f, "the link failed in the layer's handshake: {e}"),
            FarError::Decode(e) => write!(f, "the client sent {e} in the layer's handshake"),
            FarError::Handshake(e) => write!(f, "the layer's handshake failed: {e}"),
            FarError::Timeout => write!(f, "the layer's handshake took more than {} s", HANDSHAKE_LIMIT.as_secs()),
        }
    }
}

impl std::error::Error for FarError {}

/// A link whose client opened or resumed a session.
pub struct Accepted<L> {
    link: L,
    decoder: Decoder,
    established: Box<Established>,
    settings: Settings,
    /// A resume's number, in the order of the handshakes; 0 for a new
    /// session.
    resume: u64,
}

/// Greet the client on `link`, and accept the session that it opens or
/// resumes, by the sessions that this far end keeps.
pub async fn accept<L>(
    mut link: L,
    role: Role,
    settings: Settings,
    sessions: &Mutex<Sessions>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Accepted<L>, FarError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    // The `GREETING` names how long this far end keeps a lost session (T-306).
    let offered = deadline::offered(&settings);
    let named: Vec<&str> = offered.iter().map(String::as_str).collect();
    let (handshake, greeting) = FarHandshake::start(role, &named, entropy).map_err(FarError::Handshake)?;
    send(&mut link, &greeting).await?;
    let mut decoder = Decoder::new();
    let shaken = tokio::time::timeout(HANDSHAKE_LIMIT, shake(&mut link, &mut decoder, handshake, sessions, entropy));
    let (established, resume) = match shaken.await {
        Ok(result) => result?,
        Err(_) => return Err(FarError::Timeout),
    };
    Ok(Accepted { link, decoder, established, settings, resume })
}

async fn shake<L>(
    link: &mut L,
    decoder: &mut Decoder,
    mut handshake: FarHandshake,
    sessions: &Mutex<Sessions>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<(Box<Established>, u64), FarError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        while let Some(record) = decoder.next().map_err(FarError::Decode)? {
            let step = {
                let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
                handshake.handle(record, &mut sessions, entropy).map_err(FarError::Handshake)?
            };
            match step {
                Step::Send(record) => send(link, &record).await?,
                Step::Wait => {}
                Step::Established(accept, established) => {
                    // A resume's place is set before its answer goes out:
                    // the task that runs it may start late, after a newer
                    // resume of the same client.
                    let resume = if established.resumed {
                        sessions.lock().unwrap_or_else(|e| e.into_inner()).next_resume()
                    } else {
                        0
                    };
                    if let Some(accept) = accept {
                        send(link, &accept).await?;
                    }
                    return Ok((established, resume));
                }
                Step::Refuse(refusal, error) => {
                    // The client reads why before the link ends.
                    last_word(link, &refusal).await;
                    return Err(FarError::Handshake(error));
                }
            }
        }
        match link.read(&mut buf).await {
            Ok(0) => return Err(FarError::Io(std::io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) => return Err(FarError::Io(e)),
        }
    }
}

async fn send<L: AsyncWrite + Unpin>(link: &mut L, record: &Record) -> Result<(), FarError> {
    let bytes = record.to_bytes().map_err(|e| FarError::Io(std::io::Error::other(e)))?;
    link.write_all(&bytes).await.map_err(FarError::Io)?;
    link.flush().await.map_err(FarError::Io)
}

/// Write `record`, this side's last on `link`, then keep the link until the
/// client ends it or [`LAST_WORD_WAIT`] passes, reading what the client sends
/// meanwhile. The client writes on until it reads the record, and a relay
/// that ends both ways when one fails would drop the record, still on its
/// way, at the first write to a link that is gone (T-354).
pub(super) async fn last_word<L: AsyncRead + AsyncWrite + Unpin>(link: &mut L, record: &Record) {
    let written = async {
        let bytes = record.to_bytes().map_err(std::io::Error::other)?;
        link.write_all(&bytes).await?;
        link.flush().await
    };
    if !matches!(tokio::time::timeout(LAST_WORD_SEND, written).await, Ok(Ok(()))) {
        return;
    }
    let mut buf = vec![0u8; 16 * 1024];
    let until_ended = async { while matches!(link.read(&mut buf).await, Ok(n) if n > 0) {} };
    let _ = tokio::time::timeout(LAST_WORD_WAIT, until_ended).await;
}

/// One link of a far end that keeps its sessions in `keeper`: the layer's
/// handshake, then a resume goes on with the target that its session kept,
/// and a new session reaches its target with `open`. A new session that
/// would pass `budget` bytes of replay buffers, or whose target cannot be
/// reached, ends at once with the reason (T-153).
pub async fn serve<L, A, O, F>(link: L, role: Role, settings: Settings, keeper: &Keeper<A>, budget: usize, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AsyncRead + AsyncWrite + Unpin + Send,
    O: FnOnce() -> F,
    F: Future<Output = Result<A, String>>,
{
    serve_admitted(link, role, settings, keeper, budget, open, admitted_at_once()).await;
}

/// [`serve`] for a session whose client is let in above the layer, later,
/// with `admitted` (T-300): until then it takes nothing of `budget`, which
/// counts the sessions that were let in.
#[allow(clippy::too_many_arguments)]
pub async fn serve_admitted<L, A, O, F>(
    link: L,
    role: Role,
    settings: Settings,
    keeper: &Keeper<A>,
    budget: usize,
    open: O,
    admitted: Admitted,
) where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: AsyncRead + AsyncWrite + Unpin + Send,
    O: FnOnce() -> F,
    F: Future<Output = Result<A, String>>,
{
    let accepted = match accept(link, role, settings, &keeper.sessions, &mut OsEntropy).await {
        Ok(accepted) => accepted,
        // A link that never completed its handshake: nothing to keep.
        Err(_) => return,
    };
    if accepted.established().resumed {
        let _ = keeper.run_resumed(accepted).await;
        return;
    }
    // A new session holds a whole buffer's worth of the budget while its
    // buffer can fill, so the budget is a bound, not a hope; a closing one
    // holds what it keeps (T-586).
    let each = settings.replay_capacity;
    let census = keeper.census(each);
    if census.held.saturating_add(each) > budget {
        let reason = words::refusal(&census, budget);
        // The client hears it; the node's own log must too, seldom. The
        // lock goes before any await.
        let said = keeper.told().refusal(tokio::time::Instant::now());
        if said {
            words::say(&reason);
        }
        accepted.close(&reason, &keeper.sessions).await;
        return;
    }
    let after = census.with_one_more(each);
    let passed = keeper.told().level(after.held, budget);
    if passed {
        words::say(&words::filling(&after, budget));
    }
    match tokio::time::timeout(TARGET_LIMIT, open()).await {
        Ok(Ok(target)) => {
            keeper.run_new_admitted(accepted, target, admitted).await;
        }
        Ok(Err(why)) => {
            let reason = format!("the node could not reach its target: {why}");
            accepted.close(&reason, &keeper.sessions).await;
        }
        Err(_) => {
            let reason = format!("the node's target did not answer within {} s", TARGET_LIMIT.as_secs());
            accepted.close(&reason, &keeper.sessions).await;
        }
    }
}

impl<L> Accepted<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// The session that the link carries. Its secret is never for a message.
    pub fn established(&self) -> &Established {
        &self.established
    }

    pub(crate) fn into_parts(self) -> (L, Decoder, Box<Established>, Settings) {
        (self.link, self.decoder, self.established, self.settings)
    }

    /// The resume's number, in the order of the handshakes; 0 for a new
    /// session.
    pub(crate) fn resume(&self) -> u64 {
        self.resume
    }

    /// End the session at once, with `reason` in a `CLOSE` (its target could
    /// not be reached, or the far end keeps as many sessions as it can): the
    /// session is forgotten, and the client ends with the reason, which the
    /// link keeps until the client read it.
    pub async fn close(self, reason: &str, sessions: &Mutex<Sessions>) {
        let Accepted { mut link, established, .. } = self;
        sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&established.id);
        last_word(&mut link, &Record::Close { reason: super::record::cut_reason(reason) }).await;
    }

    /// Carry the session between the target `app` and the link until either
    /// ends. The far end's received offset goes back to `sessions`, for a
    /// resume.
    pub async fn run<A>(self, app: A, sessions: &Mutex<Sessions>) -> Ended
    where
        A: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Accepted { link, decoder, established, settings, .. } = self;
        let mut carry = Carry::new(settings.link(&established));
        let mut app = app;
        let watch = pump::Watch::far_end().within(settings.window);
        let ended = pump::run(&mut app, link, decoder, &mut carry, &watch).await;
        // The target learns that no more bytes come.
        let _ = app.shutdown().await;
        let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.set_received(&established.id, ended.received);
        ended
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::session::budget::{filling, left_words, refusal, Census, Told};

    const MIB: usize = 1 << 20;

    /// The node of GitHub #112, in the words of T-586: what holds the
    /// budget, and when room comes back.
    #[test]
    fn a_refusal_names_what_holds_the_budget_and_when_room_comes() {
        let census = Census { held: 64 * MIB, live: 3, waiting: 13, first_free: Some(Duration::from_secs(250)) };
        assert_eq!(
            refusal(&census, 64 * MIB),
            "this node keeps 16 resumable sessions (64 MiB of replay buffers): 3 with a link, 13 waiting for their \
             client, the first of them for 4 min 10 s more; --resume-deadline and PODSSH_REPLAY_BUFFER of the node \
             change it"
        );
    }

    #[test]
    fn a_refusal_counts_one_session_and_none_waiting_in_words() {
        let live = Census { held: 8 * MIB, live: 2, waiting: 0, first_free: None };
        let words = refusal(&live, 8 * MIB);
        let head = "this node keeps 2 resumable sessions (8 MiB of replay buffers): 2 with a link, none waiting for \
                    its client;";
        assert!(words.starts_with(head), "{words}");
        let one = Census { held: 4 * MIB, live: 0, waiting: 1, first_free: Some(Duration::from_millis(39_200)) };
        let words = refusal(&one, 4 * MIB);
        assert!(words.contains("keeps 1 resumable session (4 MiB"), "{words}");
        assert!(words.contains("0 with a link, 1 waiting for its client, for 40 s more;"), "{words}");
    }

    #[test]
    fn a_time_left_is_said_to_the_second_above_it() {
        assert_eq!(left_words(Duration::from_millis(39_200)), "40 s");
        assert_eq!(left_words(Duration::from_secs(60)), "1 min");
        assert_eq!(left_words(Duration::from_secs(250)), "4 min 10 s");
        assert_eq!(left_words(Duration::from_secs(3 * 3600 + 300)), "3 h 5 min");
    }

    /// A client that tries again each second does not fill the node's log.
    #[test]
    fn a_refusal_is_said_once_a_minute_at_most() {
        let mut told = Told::default();
        let start = tokio::time::Instant::now();
        assert!(told.refusal(start));
        assert!(!told.refusal(start + Duration::from_secs(59)));
        assert!(told.refusal(start + Duration::from_secs(60)));
    }

    #[test]
    fn three_quarters_are_said_once_until_the_budget_falls_to_half() {
        let (mut told, budget) = (Told::default(), 64 * MIB);
        assert!(!told.level(48 * MIB, budget), "at three quarters, not past them");
        assert!(told.level(52 * MIB, budget));
        assert!(!told.level(56 * MIB, budget));
        assert!(!told.level(40 * MIB, budget));
        assert!(!told.level(52 * MIB, budget), "above half since: said once");
        assert!(!told.level(32 * MIB, budget));
        assert!(told.level(52 * MIB, budget), "past them again after half");
        let census = Census { held: 52 * MIB, live: 9, waiting: 4, first_free: Some(Duration::from_secs(90)) };
        let line = filling(&census, budget);
        let head = "the resumable sessions hold 52 MiB of this node's 64 MiB of replay buffers: 9 with a link, 4 \
                    waiting for their client, the first of them for 1 min 30 s more;";
        assert!(line.starts_with(head), "{line}");
    }
}
