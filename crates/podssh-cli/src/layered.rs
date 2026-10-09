//! The client of a node's resumable layer, over the operator's leg of the
//! reverse road (T-153), for `podssh ssh node://NAME` and `podssh operator
//! NAME`. It sends nothing until the node's first byte: a node that greets
//! gets the layer, and a lost leg is then replaced by a new one, whose
//! handshake resumes the session where it was. A node with no layer gets the
//! bytes as they are, on one leg, as before.

use std::sync::Mutex;
use std::time::Duration;

use podssh_relay::reverse::closes::resumes;
use podssh_relay::reverse::{operator, OperatorConfig, Outcome as LegOutcome, RelayClose};
use podssh_relay::session::client::{self, Found, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{replay, Ask, End, Ended, OsEntropy, Settings};
use podssh_ws::client::ConnectError;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::task::JoinHandle;

/// Each direction of the pipe between the layer and a leg.
const PIPE: usize = 256 * 1024;
/// How long a lost leg may take to say why it ended.
const LEG_WAIT: Duration = Duration::from_secs(5);
/// How long the last leg may take to end after the session: its Close and
/// the relay's answer.
const LEG_END: Duration = Duration::from_secs(12);
/// How long before the pair's expiry the user hears of it: at the expiry
/// the relay ends each session of the pair (`1001 pair expired`), and no
/// resume can carry one on (T-155).
pub const EXPIRY_WARNING: Duration = Duration::from_secs(3600);

/// One line for the user: always, or only with `-v`.
pub enum Line {
    Always(String),
    Verbose(String),
}

/// How a session to a node ended.
pub struct Carried {
    /// What the layer says of a failure; `None` when the leg says more.
    pub why: Option<String>,
    /// How the last leg ended, if it did in time.
    pub leg: Option<LegOutcome>,
}

/// The layer's settings, with the replay buffer of `PODSSH_REPLAY_BUFFER`.
pub fn settings() -> Settings {
    let capacity = replay::capacity(std::env::var(replay::CAPACITY_ENV).ok().as_deref());
    Settings { replay_capacity: capacity, ..Settings::default() }
}

/// Carry `app` to the node: `link` is the pipe to `first`, a leg already
/// connected. Each lost leg is replaced, until the session ends or cannot
/// go on. `expires_ms`, the pair's expiry in milliseconds since the epoch,
/// gives a warning an hour before it.
pub async fn carry<A>(
    config: &OperatorConfig<'_>,
    link: DuplexStream,
    first: JoinHandle<LegOutcome>,
    app: A,
    expires_ms: Option<i64>,
    say: &(dyn Fn(Line) + Sync),
) -> Carried
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
{
    let legs = Mutex::new(Some(first));
    let client = match client::start(link, Ask::New, settings(), &mut OsEntropy).await {
        Ok(client) => client,
        Err(e) => return Carried { why: Some(e.to_string()), leg: last(&legs).await },
    };
    say(Line::Verbose(client.found().to_string()));
    if let Found::Layer { features, .. } = client.found() {
        say(Line::Verbose(format!("the layer's features: {}", features.join(", "))));
    }
    let legs_ref = &legs;
    let connect = |ended: &Ended| {
        // A move opens a new leg while the old one still carries the
        // session: there is no end of it to wait for.
        let previous = if matches!(ended.end, End::Moving) { None } else { lock(legs_ref).take() };
        async move { next_leg(config, legs_ref, previous).await }
    };
    let note = |note: Note| say(line_of(note));
    let mut entropy = OsEntropy;
    let session = resume::run(client, app, connect, note, &mut entropy);
    tokio::pin!(session);
    let outcome = tokio::select! {
        outcome = &mut session => outcome,
        () = warn_of_expiry(expires_ms, say) => session.await,
    };
    let why = match outcome {
        Outcome::Plain(_) => None,
        Outcome::Layer(ended) => match ended.end {
            End::Closed(reason) if !reason.is_empty() => {
                Some(format!("the far end ended the session: {}", podssh_ws::text::one_line(&reason)))
            }
            End::Broken(e) => Some(e.to_string()),
            End::GaveUp(reason) => Some(format!("the session could not go on: {}", podssh_ws::text::one_line(&reason))),
            // The leg's close code and reason say more of a lost link.
            End::Closed(_)
            | End::LocalEnd
            | End::Closing
            | End::Lost(_)
            | End::Stopped
            | End::Retired
            | End::Moving => None,
        },
    };
    Carried { why, leg: last(&legs).await }
}

/// How long to wait before the warning of a pair that expires at
/// `expires_ms`, at `now_ms`: none once the pair expired, as the relay then
/// says so itself.
pub fn expiry_wait(expires_ms: i64, now_ms: i64) -> Option<Duration> {
    let left = expires_ms.checked_sub(now_ms).filter(|left| *left > 0)?;
    let warning = EXPIRY_WARNING.as_millis() as i64;
    Some(Duration::from_millis(left.saturating_sub(warning).max(0) as u64))
}

/// One line an hour before the pair expires, or at once when less is left;
/// never, with no expiry or one that passed.
async fn warn_of_expiry(expires_ms: Option<i64>, say: &(dyn Fn(Line) + Sync)) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let Some(wait) = expires_ms.and_then(|expires| expiry_wait(expires, now_ms)) else {
        return std::future::pending().await;
    };
    tokio::time::sleep(wait).await;
    let left = expires_ms.unwrap_or(0).saturating_sub(now_ms).saturating_sub(wait.as_millis() as i64);
    say(Line::Always(format!(
        "the pair expires in {} min; the relay then ends this session, and a new pair (podssh relay pair) is \
         needed to go on",
        (left.max(0) / 60_000).max(1)
    )));
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The last leg's end, once it has sent its Close and the relay answered.
async fn last(legs: &Mutex<Option<JoinHandle<LegOutcome>>>) -> Option<LegOutcome> {
    let handle = lock(legs).take()?;
    tokio::time::timeout(LEG_END, handle).await.ok()?.ok()
}

/// A new leg in place of a lost one, unless the lost one ended with a close
/// that a new leg would only get again.
async fn next_leg(
    config: &OperatorConfig<'_>,
    legs: &Mutex<Option<JoinHandle<LegOutcome>>>,
    previous: Option<JoinHandle<LegOutcome>>,
) -> Next<DuplexStream> {
    if let Some(handle) = previous {
        if let Ok(Ok(outcome)) = tokio::time::timeout(LEG_WAIT, handle).await {
            if let Some(stop) = stops(&outcome) {
                return Next::Stop(stop);
            }
        }
    }
    let (link, leg_end) = tokio::io::duplex(PIPE);
    match operator::start(config, leg_end).await {
        Ok(handle) => {
            *lock(legs) = Some(handle);
            Next::Link(link)
        }
        Err(e) if is_final(&e) => Next::Stop(e.to_string()),
        Err(e) => Next::Retry(e.to_string()),
    }
}

/// A leg's end that a new leg would only repeat: a stopped or expired pair,
/// a fault of podssh's own bytes.
fn stops(outcome: &LegOutcome) -> Option<String> {
    let (code, reason) = match outcome {
        LegOutcome::Ended { code, reason } => (*code, reason.as_str()),
        LegOutcome::NeverReady { code: Some(code), reason } => (*code, reason.as_str()),
        LegOutcome::NeverReady { code: None, .. } | LegOutcome::LocalEnd => return None,
    };
    let close = RelayClose { code, reason: reason.to_string(), clean: true };
    (!resumes(&close)).then(|| crate::pairs::session_end(code, reason))
}

/// A refusal of the relay that a new leg would only get again: the pair or
/// its token is no longer good.
fn is_final(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Refused { status: 401 | 403 | 404 | 410, .. })
}

fn line_of(note: Note) -> Line {
    match note {
        Note::Lost { why } => Line::Always(format!("{why}; resuming the session")),
        Note::Retry { why, wait } => {
            Line::Verbose(format!("no new link yet ({why}); trying again in {:.1} s", wait.as_secs_f64()))
        }
        Note::Moved { bytes, age, resent } => Line::Verbose(format!(
            "the session moved to a new link before the relay's limits, after {} MiB in {} s ({resent} bytes \
             sent again)",
            bytes >> 20,
            age.as_secs()
        )),
        Note::MoveFailed { why } => Line::Verbose(format!("a move to a new link failed ({why}); the link goes on")),
        Note::Resumed { resent, after } => Line::Always(format!(
            "the session resumed after {:.1} s{}",
            after.as_secs_f64(),
            if resent > 0 { format!(", {resent} bytes sent again") } else { String::new() }
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3_600_000;

    #[test]
    fn the_warning_comes_an_hour_before_the_expiry() {
        assert_eq!(expiry_wait(10 * HOUR, 0), Some(Duration::from_millis(9 * HOUR as u64)));
        assert_eq!(expiry_wait(HOUR + 1, 1), Some(Duration::ZERO));
    }

    #[test]
    fn less_than_an_hour_left_is_said_at_once() {
        assert_eq!(expiry_wait(HOUR - 1, 0), Some(Duration::ZERO));
        assert_eq!(expiry_wait(5, 4), Some(Duration::ZERO));
    }

    #[test]
    fn a_pair_that_expired_gets_no_warning() {
        assert_eq!(expiry_wait(100, 100), None);
        assert_eq!(expiry_wait(100, 200), None);
        assert_eq!(expiry_wait(i64::MIN, i64::MAX), None);
    }
}
