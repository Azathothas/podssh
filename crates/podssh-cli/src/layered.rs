//! The client of a node's resumable layer, over the operator's leg of the
//! reverse road (T-153), for `podssh ssh node://NAME` and `podssh operator
//! NAME`. It sends nothing until the node's first byte: a node that greets
//! gets the layer, and a lost leg is then replaced by a new one, whose
//! handshake resumes the session where it was. A node with no layer gets the
//! bytes as they are, on one leg, as before.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::reverse::closes::resumes;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, RelayClose};
use podssh_relay::session::client::{self, Found, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{
    deadline, hearing, replay, Ask, End, Ended, Hearing, OsEntropy, Settings, KEEP, SHELL_FEATURES,
};
use podssh_ssh::keep::Offer;
use podssh_ssh::notice::Silence;
use podssh_ws::client::ConnectError;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::task::JoinHandle;

use crate::relay_settings::Refusal;

/// Each direction of the pipe between the layer and a leg.
const PIPE: usize = 256 * 1024;
/// How long a lost leg may take to say why it ended.
pub(crate) const LEG_WAIT: Duration = Duration::from_secs(5);
/// How long the last leg may take to end after the session: its Close and
/// the relay's answer.
const LEG_END: Duration = Duration::from_secs(12);
/// How long a leg of the layer waits, once the layer let it go, for the node
/// to end it: more than the far end's 30 s for a handshake (T-388).
const NODE_ENDS: Duration = Duration::from_secs(35);
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
    /// What the end-to-end channel says of its failure (T-088): a refused
    /// key, a changed node key, a message that failed its check. It says
    /// more than the layer and the leg.
    pub channel: Option<(crate::exitmap::Fault, String)>,
}

/// The deadlines of `--resume-deadline` (T-306): a node's, how long it keeps
/// a lost session; and a client's own, of `ssh` and `operator`, which only
/// shortens the far end's. A process runs one command, so one of each.
static FAR_DEADLINE: Mutex<Option<Duration>> = Mutex::new(None);
static OWN_DEADLINE: Mutex<Option<Duration>> = Mutex::new(None);
/// The shortest `--resume-deadline`: a silent link is found dead after
/// 30 s, and a resume needs the time after that.
pub const SHORTEST_DEADLINE: Duration = Duration::from_secs(60);

/// `no`: a client opens no spare link beside a silent one (T-305).
pub const SPARE_LINKS_ENV: &str = "PODSSH_SPARE_LINKS";

/// The layer's settings, with the replay buffer of `PODSSH_REPLAY_BUFFER`
/// and the deadlines of `--resume-deadline`; a client opens a spare link
/// beside a silent one (T-305), unless `PODSSH_SPARE_LINKS` is `no`.
pub fn settings() -> Settings {
    let capacity = replay::capacity(std::env::var(replay::CAPACITY_ENV).ok().as_deref());
    let defaults = Settings::default();
    let far = *lock(&FAR_DEADLINE);
    let own = *lock(&OWN_DEADLINE);
    let spare_links = !std::env::var(SPARE_LINKS_ENV).is_ok_and(|v| v.trim().eq_ignore_ascii_case("no"));
    Settings {
        replay_capacity: capacity,
        resume_deadline: far.unwrap_or(defaults.resume_deadline),
        client_deadline: own,
        spare_links,
        ..defaults
    }
}

/// The layer's settings on the iroh road, with its `features`: no spare
/// link. QUIC carries a session across a new address of the client by
/// itself, and a spare link there is a stream of the same connection, so
/// it can only add a resume: 3 resumes in 5 runs with spare links, none in
/// 5 with none (T-305).
pub fn iroh_settings(features: &'static [&'static str]) -> Settings {
    Settings { features, spare_links: false, ..settings() }
}

/// A time of `--resume-deadline`: a whole number, then s, m, h or d (none
/// is seconds), from 1 minute to 72 h, the longest life of a pair.
pub fn parse_deadline(text: &str) -> Result<Duration, String> {
    let bad = || format!("--resume-deadline {text:?}: a whole number, then s, m, h or d, as 90s, 30m or 8h");
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let scale: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(bad()),
    };
    let seconds = number.parse::<u64>().ok().and_then(|n| n.checked_mul(scale)).ok_or_else(bad)?;
    let time = Duration::from_secs(seconds);
    if time < SHORTEST_DEADLINE || time > deadline::LONGEST {
        return Err(format!("--resume-deadline {text:?}: from 1 minute to 72 h, the longest life of a pair"));
    }
    Ok(time)
}

/// A node's `--resume-deadline`, for each road that it serves.
pub fn set_far_deadline(time: Duration) {
    *lock(&FAR_DEADLINE) = Some(time);
}

/// A client's own `--resume-deadline`, when the command line gives one.
pub fn own_deadline(text: Option<&str>) -> Result<(), Refusal> {
    if let Some(text) = text {
        *lock(&OWN_DEADLINE) = Some(parse_deadline(text).map_err(Refusal::usage)?);
    }
    Ok(())
}

/// The layer's settings of `podssh ssh`: those of [`settings`], with
/// `keep.v1` named too, so that a far end that keeps shells says so (T-158).
pub fn ssh_settings() -> Settings {
    Settings { features: SHELL_FEATURES, ..settings() }
}

/// What the far end that `found` names says of its shells, into `offer`:
/// it keeps them when both sides named `keep.v1` (T-158).
pub fn learn(found: &Found, offer: &Offer) {
    if let Found::Layer { features, .. } = found {
        if features.iter().any(|name| name == KEEP) {
            offer.set();
        }
    }
}

/// What `podssh ssh` shares with the layer: whether the far end keeps
/// shells (T-158), and the far end's silence, for a notice (T-302).
#[derive(Clone, Copy)]
pub struct Shell<'a> {
    pub offer: &'a Offer,
    pub silence: &'a Silence,
}

/// The session of `client` tells `silence` how long the far end has been
/// silent while a question waits (T-302).
pub fn heard<L>(client: client::Client<L>, silence: &Silence) -> client::Client<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = Arc::new(Hearing::default());
    let read = shared.clone();
    silence.attach(move || read.silent(tokio::time::Instant::now(), hearing::WAIT));
    client.with_hearing(shared)
}

/// Whether a line of the layer is left out: a loss or a resume, while the
/// window's title shows the notice of silence, which tells as much and
/// writes nothing into the screen (T-302).
pub fn folded(note: &Note, silence: Option<&Silence>) -> bool {
    matches!(note, Note::Lost { .. } | Note::Resumed { .. }) && silence.is_some_and(Silence::titled)
}

/// Where the layer's client starts: on a leg whose far end has not spoken
/// yet, or already started on it, by a caller that read the far end's
/// greeting first (`podssh ssh --upgrade`, T-167).
pub enum Begin {
    Link(DuplexStream),
    Started(Box<client::Client<DuplexStream>>),
}

impl From<DuplexStream> for Begin {
    fn from(link: DuplexStream) -> Begin {
        Begin::Link(link)
    }
}

/// Carry `app` to the node: `link` is the pipe to `first`, a leg already
/// connected. Each lost leg is replaced, until the session ends or cannot
/// go on. `expires_ms`, the pair's expiry in milliseconds since the epoch,
/// gives a warning an hour before it. With `shell`, the client names
/// `keep.v1`, learns whether the far end keeps shells, and tells the far
/// end's silence for a notice (T-302).
pub async fn carry<A>(
    config: &OperatorConfig<'_>,
    link: impl Into<Begin>,
    first: JoinHandle<LegOutcome>,
    app: A,
    expires_ms: Option<i64>,
    say: &(dyn Fn(Line) + Sync),
    shell: Option<Shell<'_>>,
) -> Carried
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
{
    let legs = Mutex::new(Some(first));
    let layer = if shell.is_some() { ssh_settings() } else { settings() };
    let started = match link.into() {
        Begin::Started(client) => Ok(*client),
        Begin::Link(link) => client::start(link, Ask::New, layer, &mut OsEntropy).await,
    };
    let client = match started {
        Ok(client) => client,
        Err(e) => return Carried { why: Some(e.to_string()), leg: last(&legs).await, channel: None },
    };
    say(Line::Verbose(client.found().to_string()));
    if let Found::Layer { features, .. } = client.found() {
        say(Line::Verbose(format!("the layer's features: {}", features.join(", "))));
    }
    // How long the far end keeps the session after a loss (T-306).
    if let Some(kept) = client.established().and_then(|e| e.peer_deadline) {
        say(Line::Verbose(format!("the far end keeps the session {} after a loss", deadline::span(kept))));
    }
    let client = match shell {
        Some(shell) => {
            learn(client.found(), shell.offer);
            heard(client, shell.silence)
        }
        None => client,
    };
    let legs_ref = &legs;
    let connect = |ended: &Ended| {
        // A move opens a new leg while the old one still carries the
        // session: there is no end of it to wait for.
        let previous = if matches!(ended.end, End::Moving) { None } else { lock(legs_ref).take() };
        async move { next_leg(config, legs_ref, previous).await }
    };
    let silence = shell.map(|shell| shell.silence);
    let note = |note: Note| {
        if !folded(&note, silence) {
            say(line_of(note));
        }
    };
    let mut entropy = OsEntropy;
    let session = resume::run(client, app, connect, note, &mut entropy);
    tokio::pin!(session);
    let outcome = tokio::select! {
        outcome = &mut session => outcome,
        () = warn_of_expiry(expires_ms, say) => session.await,
    };
    Carried { why: why_ended(outcome), leg: last(&legs).await, channel: None }
}

/// [`carry`], with the end-to-end channel of T-088 around `app` (none with
/// `--no-e2e`): the channel's session runs beside the layer, and its
/// failure goes into [`Carried::channel`]. `pin_say` gets the line of a
/// node's key pinned at its first sight.
#[allow(clippy::too_many_arguments)]
pub async fn carry_through<A>(
    config: &OperatorConfig<'_>,
    link: impl Into<Begin>,
    first: JoinHandle<LegOutcome>,
    app: A,
    expires_ms: Option<i64>,
    say: &(dyn Fn(Line) + Sync),
    channel: Option<crate::channel::Operator>,
    pin_say: impl Fn(String) + Send + 'static,
) -> Carried
where
    A: crate::channel::Bytes + 'static,
{
    carry_keeping(config, link, first, app, expires_ms, say, channel, pin_say, None).await
}

/// [`carry_through`] for `podssh ssh`, which names `keep.v1`: `shell`
/// learns whether the far end keeps shells (T-158), and tells the far end's
/// silence (T-302).
#[allow(clippy::too_many_arguments)]
pub async fn carry_keeping<A>(
    config: &OperatorConfig<'_>,
    link: impl Into<Begin>,
    first: JoinHandle<LegOutcome>,
    app: A,
    expires_ms: Option<i64>,
    say: &(dyn Fn(Line) + Sync),
    channel: Option<crate::channel::Operator>,
    pin_say: impl Fn(String) + Send + 'static,
    shell: Option<Shell<'_>>,
) -> Carried
where
    A: crate::channel::Bytes + 'static,
{
    let me = channel.as_ref().map(|c| c.identity.clone());
    let (stream, session) = crate::channel::around(app, channel, pin_say);
    let Some(session) = session else { return carry(config, link, first, stream, expires_ms, say, shell).await };
    let (mut carried, outcome) = tokio::join!(carry(config, link, first, stream, expires_ms, say, shell), session);
    if let Err(e) = outcome {
        carried.channel = crate::channel::judged(&e, me.as_deref());
    }
    carried
}

/// What the layer says of a session that did not end well: `None` for a
/// good end, and for a lost link, of which the road says more.
pub(crate) fn why_ended(outcome: Outcome) -> Option<String> {
    match outcome {
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
    }
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

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The last leg's end, once it has sent its Close and the relay answered.
pub(crate) async fn last(legs: &Mutex<Option<JoinHandle<LegOutcome>>>) -> Option<LegOutcome> {
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
    // A leg of the layer: the node ends it (T-388).
    let config = OperatorConfig { limits: OperatorLimits { node_ends: Some(NODE_ENDS), ..config.limits }, ..*config };
    match operator::start(&config, leg_end).await {
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
pub(crate) fn stops(outcome: &LegOutcome) -> Option<String> {
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
pub(crate) fn is_final(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Refused { status: 401 | 403 | 404 | 410, .. })
}

/// The line of a step of the session across links.
pub(crate) fn line_of(note: Note) -> Line {
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
        Note::Spare { quiet } => Line::Verbose(format!(
            "the link said nothing for {:.1} s: a spare link opens beside it",
            quiet.as_secs_f64()
        )),
        Note::SpareClosed { why } => Line::Verbose(format!("the spare link closed ({why}); the link goes on")),
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

    /// `--resume-deadline` (T-306): a whole number and a unit, from 1 minute
    /// to the 72 h of a pair's life.
    #[test]
    fn a_resume_deadline_is_a_time_from_a_minute_to_72_h() {
        let secs = Duration::from_secs;
        assert_eq!(parse_deadline("90"), Ok(secs(90)));
        assert_eq!(parse_deadline("90s"), Ok(secs(90)));
        assert_eq!(parse_deadline("30m"), Ok(secs(1800)));
        assert_eq!(parse_deadline("8h"), Ok(secs(8 * 3600)));
        assert_eq!(parse_deadline("3d"), Ok(secs(72 * 3600)));
        for bad in ["", "h", "8 h", "+8h", "8x", "1.5h", "-1m", "99999999999999999999d"] {
            let why = parse_deadline(bad).unwrap_err();
            assert!(why.contains("a whole number, then s, m, h or d"), "{bad:?}: {why}");
        }
        for out in ["59", "0", "4d", "73h"] {
            let why = parse_deadline(out).unwrap_err();
            assert!(why.contains("from 1 minute to 72 h"), "{out:?}: {why}");
        }
    }
}
