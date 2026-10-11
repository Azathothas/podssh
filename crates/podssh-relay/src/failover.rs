//! The order in which the relay hosts of one run are tried (T-220). When the
//! hosts go one at a time, a first host that accepts TCP and then says
//! nothing costs a whole step, 20 s, before the next one starts. The
//! default, `staggered`, starts the next host when the attempt before it has
//! not opened within [`STAGGER`], or at once when it failed, and keeps the
//! first that opens; `parallel` starts each host at once; `serial` goes one
//! at a time. [`race`] runs any attempt, so that its tests drive attempts
//! that open, fail or stay silent on a paused clock; [`crate::open`] gives it
//! the relay's.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::Instant;

/// How long an attempt may go without opening before the next host starts
/// (`staggered`), and how long an attempt that opened waits for the hosts
/// before it in the list (`parallel`).
pub const STAGGER: Duration = Duration::from_secs(2);

/// The bound of each step of a host that has a successor, in `serial`; the
/// last host has the whole step.
pub const SERIAL_STEP: Duration = Duration::from_secs(5);

/// The setting of the mode; `--relay-failover` wins over it.
pub const MODE_ENV: &str = "PODSSH_RELAY_FAILOVER";

/// How the hosts of a run are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// The next host starts when the attempt before it has not opened within
    /// [`STAGGER`], or at once when it failed; the first that opens is kept,
    /// and of two that opened together, the earlier in the list.
    #[default]
    Staggered,
    /// Each host starts at once. An attempt that opens waits at most
    /// [`STAGGER`] for the hosts before it that still run; then the earliest
    /// in the list that opened is kept.
    Parallel,
    /// One host at a time, each step of a host that has a successor bounded
    /// by [`SERIAL_STEP`].
    Serial,
}

impl Mode {
    /// The names, as a refusal gives them.
    pub const NAMES: &'static str = "staggered, parallel or serial";

    pub fn name(self) -> &'static str {
        match self {
            Mode::Staggered => "staggered",
            Mode::Parallel => "parallel",
            Mode::Serial => "serial",
        }
    }

    /// The mode that `value` names; `None` for another word.
    pub fn parse(value: &str) -> Option<Mode> {
        match value {
            "staggered" => Some(Mode::Staggered),
            "parallel" => Some(Mode::Parallel),
            "serial" => Some(Mode::Serial),
            _ => None,
        }
    }

    /// The mode of [`MODE_ENV`] (`env`, its value), or the default when it is
    /// unset or empty; the refusal of another word.
    pub fn from_env(env: Option<String>) -> Result<Mode, String> {
        match env.as_deref().map(str::trim) {
            None | Some("") => Ok(Mode::default()),
            Some(value) => Mode::parse(value)
                .ok_or_else(|| format!("{MODE_ENV}: {value:?} is not a mode of failover: give {}", Mode::NAMES)),
        }
    }
}

/// What one attempt gave, with the notes that it kept for the user.
pub struct Attempt<T, E> {
    pub result: Result<T, E>,
    pub notes: Vec<String>,
}

/// How a race over the hosts of one round ended.
pub struct Raced<T, E> {
    /// The attempt kept, by its place in the list.
    pub kept: Option<(usize, T)>,
    /// Each attempt that failed, in the order of the list; an error that
    /// ended the round comes last.
    pub failed: Vec<(usize, E)>,
    /// Attempts that opened and were not kept, for the caller to close.
    pub dismissed: Vec<(usize, T)>,
    /// An error that every host would give ended the round.
    pub stopped: bool,
}

/// The notes of each attempt, given in the order of the list: those of an
/// attempt as soon as each attempt before it has ended.
struct Notes<'a> {
    out: &'a mut dyn FnMut(&str),
    ended: Vec<Option<Vec<String>>>,
    next: usize,
}

impl Notes<'_> {
    fn ended(&mut self, i: usize, notes: Vec<String>) {
        self.ended[i] = Some(notes);
        while let Some(Some(notes)) = self.ended.get_mut(self.next) {
            for note in std::mem::take(notes) {
                (self.out)(&note);
            }
            self.next += 1;
        }
    }

    /// The rest, in order: an attempt that never ended has none.
    fn flush(&mut self) {
        for i in self.next..self.ended.len() {
            for note in self.ended[i].take().unwrap_or_default() {
                (self.out)(&note);
            }
        }
        self.next = self.ended.len();
    }
}

/// Run the attempts of `n` hosts in `mode`: `start(i)` makes the attempt of
/// host `i`, and `stops(e)` says that an error is one that every host would
/// give, which ends the round and the attempts that still run. The notes of
/// each attempt go to `notes` in the order of the list.
pub async fn race<T, E, S, F>(
    n: usize,
    mode: Mode,
    mut start: S,
    stops: impl Fn(&E) -> bool,
    notes: &mut dyn FnMut(&str),
) -> Raced<T, E>
where
    S: FnMut(usize) -> F,
    F: Future<Output = Attempt<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let mut notes = Notes { out: notes, ended: (0..n).map(|_| None).collect(), next: 0 };
    let mut out = Raced { kept: None, failed: Vec::new(), dismissed: Vec::new(), stopped: false };
    if n == 0 {
        return out;
    }
    let mut set: JoinSet<(usize, Attempt<T, E>)> = JoinSet::new();
    let mut running = vec![false; n];
    let mut launch = |set: &mut JoinSet<(usize, Attempt<T, E>)>, running: &mut Vec<bool>, i: usize| {
        let attempt = start(i);
        running[i] = true;
        set.spawn(async move { (i, attempt.await) });
    };
    let mut next = 0;
    if mode == Mode::Parallel {
        while next < n {
            launch(&mut set, &mut running, next);
            next += 1;
        }
    } else {
        launch(&mut set, &mut running, 0);
        next = 1;
    }
    let mut stagger_at = Instant::now() + STAGGER;
    // The attempts that opened, and when the decision falls in `parallel`.
    let mut opened: Vec<(usize, T)> = Vec::new();
    let mut decide_at: Option<Instant> = None;
    let mut failures_seen = 0;
    // The attempt whose error ended the round.
    let mut stopper = None;
    loop {
        // Each attempt that ended in the same turn counts as opened together.
        while let Some(joined) = set.try_join_next() {
            stopper = stopper.or(take(joined, &mut running, &mut opened, &mut out, &stops, &mut notes));
        }
        if out.stopped {
            break;
        }
        if let Some(best) = opened.iter().map(|(i, _)| *i).min() {
            let earlier_runs = running[..best].iter().any(|r| *r);
            let decided = match mode {
                Mode::Staggered | Mode::Serial => true,
                Mode::Parallel => !earlier_runs || decide_at.is_some_and(|at| Instant::now() >= at),
            };
            if decided {
                break;
            }
            decide_at.get_or_insert(Instant::now() + STAGGER);
        }
        // Each failure starts the next host at once.
        while mode != Mode::Parallel && opened.is_empty() && failures_seen < out.failed.len() && next < n {
            failures_seen += 1;
            launch(&mut set, &mut running, next);
            next += 1;
            stagger_at = Instant::now() + STAGGER;
        }
        failures_seen = out.failed.len();
        if set.is_empty() {
            break;
        }
        let stagger = mode == Mode::Staggered && next < n && opened.is_empty();
        tokio::select! {
            joined = set.join_next() => {
                let joined = joined.expect("the set has an attempt");
                stopper = stopper.or(take(joined, &mut running, &mut opened, &mut out, &stops, &mut notes));
            }
            () = tokio::time::sleep_until(stagger_at), if stagger => {
                launch(&mut set, &mut running, next);
                next += 1;
                stagger_at = Instant::now() + STAGGER;
            }
            () = tokio::time::sleep_until(decide_at.unwrap_or_else(Instant::now)), if decide_at.is_some() => {}
        }
    }
    // The earliest in the list of those that opened is kept; the others that
    // opened are dismissed, and those that still run end here.
    // After an error that every host would give, none is kept.
    opened.sort_by_key(|(i, _)| *i);
    let mut opened = opened.into_iter();
    out.kept = if out.stopped { None } else { opened.next() };
    out.dismissed.extend(opened);
    set.abort_all();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((i, attempt)) => {
                running[i] = false;
                notes.ended(i, attempt.notes);
                match attempt.result {
                    Ok(t) => out.dismissed.push((i, t)),
                    Err(e) => out.failed.push((i, e)),
                }
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => {}
        }
    }
    out.failed.sort_by_key(|(i, _)| *i);
    if let Some(pos) = stopper.and_then(|s| out.failed.iter().position(|(i, _)| *i == s)) {
        let stop = out.failed.remove(pos);
        out.failed.push(stop);
    }
    notes.flush();
    out
}

/// Record an attempt that ended: its place when its error ends the round.
fn take<T, E>(
    joined: Result<(usize, Attempt<T, E>), tokio::task::JoinError>,
    running: &mut [bool],
    opened: &mut Vec<(usize, T)>,
    out: &mut Raced<T, E>,
    stops: &impl Fn(&E) -> bool,
    notes: &mut Notes<'_>,
) -> Option<usize> {
    let (i, attempt) = match joined {
        Ok(joined) => joined,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Only an abort cancels an attempt, after the race.
        Err(_) => return None,
    };
    running[i] = false;
    notes.ended(i, attempt.notes);
    match attempt.result {
        Ok(t) => {
            opened.push((i, t));
            None
        }
        Err(e) => {
            let stop = stops(&e);
            out.stopped |= stop;
            out.failed.push((i, e));
            stop.then_some(i)
        }
    }
}

/// One mint at a time for each relay deployment (T-220), keyed as the cache
/// keys its tokens: an attempt waits at most [`STAGGER`] for a mint that
/// another attempt has in flight, then reads the token that it cached, or
/// mints at its own host when the mint in flight is the silent one.
#[derive(Clone, Default)]
pub struct MintGate(Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>);

impl MintGate {
    /// The turn of `key`, within `wait`; `None` when another attempt still
    /// holds it then.
    pub async fn hold(&self, key: &str, wait: Duration) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let lock = self.0.lock().unwrap_or_else(|e| e.into_inner()).entry(key.to_string()).or_default().clone();
        tokio::time::timeout(wait, lock.lock_owned()).await.ok()
    }
}
