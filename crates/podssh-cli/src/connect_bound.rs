//! `--ConnectTimeout SECONDS` of `operator`, `proxy` and `pipe` (T-589): one
//! bound on the time from the start to the session's open, never on the
//! bytes after it, as a pipe may wait. Each step keeps its own limit too, and
//! the first limit to pass ends the wait. A watch on a thread of its own ends
//! the run once the bound passed with no session open: one line names the
//! step that waited, and the exit is 69, a far end out of reach. So no road
//! needs a bound of its own, and a session that opened is never cut. The
//! steps say where the open is ([`step`]), and the road says when it opened
//! ([`opened`]); with no watch, both do nothing. A process runs one command,
//! so one watch at a time. `--timeout DURATION` and `PODSSH_TIMEOUT` are
//! other names of the same bound (T-613, [`chosen`]), and the line past it
//! names the one that set it.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::non_interactive::TIMEOUT_ENV;
use crate::relay_settings::Refusal;

/// The longest bound, a day: a longer one bounds nothing that a person waits
/// for, and an `Instant` far ahead can overflow.
const LONGEST: u64 = 86_400;

/// The step after the layer when a channel follows it.
const CHANNEL_STEP: &str = "the end-to-end channel did not finish its handshake";

/// What the watch reads, and the steps write.
struct State {
    /// The run that the watch bounds; a later watch is another run.
    run: u64,
    /// The words of the step that waits, as "no relay host answered".
    step: String,
    /// An end-to-end channel follows the layer: the channel's check of the
    /// node's key opens the session.
    channel: bool,
    /// The session opened, or the run ended: nothing is bounded.
    done: bool,
    /// The bound passed: the watch ends the run, and no session opens.
    passed: bool,
}

impl State {
    const fn new() -> State {
        State { run: 0, step: String::new(), channel: false, done: true, passed: false }
    }

    /// A new run, whose first step is `first`: its number.
    fn start(&mut self, first: &str) -> u64 {
        *self = State { run: self.run + 1, step: first.to_string(), done: false, ..State::new() };
        self.run
    }

    fn step(&mut self, words: String) {
        if !self.done {
            self.step = words;
        }
    }

    /// The layer is up: whether the session opens with it, as no channel
    /// follows; else the channel's step.
    fn layer_up(&mut self) -> bool {
        if self.channel {
            self.step(CHANNEL_STEP.to_string());
        }
        !self.channel
    }

    /// The end of run `run`: by its open, or by its watch's drop.
    fn end(&mut self, run: u64) {
        if self.run == run {
            self.done = true;
        }
    }
}

static STATE: Mutex<State> = Mutex::new(State::new());
/// The watch's wake: a step that ended the bound.
static CHANGED: Condvar = Condvar::new();

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// What ends with the run when the bound gives up: the program that a
/// carrier started (`exec:`). The exit drops nothing, so a program left
/// running would outlive podssh and hold its stderr open.
type Stop = Box<dyn Fn() + Send>;
static STOPS: Mutex<Vec<Stop>> = Mutex::new(Vec::new());

/// Run `stop` if the bound ends the run before a session opened.
pub fn at_give_up(stop: Stop) {
    STOPS.lock().unwrap_or_else(|e| e.into_inner()).push(stop);
}

/// The bound of `--ConnectTimeout SECONDS`: whole seconds, an `s` after them
/// taken, as `ssh` reads its ConnectTimeout, from 1 to a day; 0 is refused,
/// as each wait would end at once (64).
pub fn parse(text: Option<&str>) -> Result<Option<Duration>, Refusal> {
    let Some(text) = text else { return Ok(None) };
    let trimmed = text.trim();
    let digits = trimmed.strip_suffix('s').unwrap_or(trimmed);
    match digits.parse::<u64>() {
        Ok(0) => Err(Refusal::usage(format!(
            "--ConnectTimeout {text}: 0 would end each wait at once; give 1 second or more"
        ))),
        Ok(seconds) if seconds <= LONGEST => Ok(Some(Duration::from_secs(seconds))),
        _ => Err(Refusal::usage(format!(
            "--ConnectTimeout {text:?}: a whole number of seconds, from 1 to {LONGEST}, as 25"
        ))),
    }
}

/// A bound on the open, and the name that set it, which the line past it
/// says: `--ConnectTimeout`, `--timeout` or `PODSSH_TIMEOUT` (T-613).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    pub limit: Duration,
    pub name: &'static str,
}

/// The bound of `--ConnectTimeout` alone, by its name.
pub fn of_connect_timeout(text: Option<&str>) -> Result<Option<Bound>, Refusal> {
    Ok(parse(text)?.map(|limit| Bound { limit, name: "--ConnectTimeout" }))
}

/// The bound of a run (T-613): `--ConnectTimeout`, else `--timeout`, else
/// `PODSSH_TIMEOUT` (`var` reads it, so that a test gives its own), three
/// names of one bound on the open, never of the bytes after it.
/// `--ConnectTimeout` wins as the more precise name; a bad `--timeout` beside
/// it is still refused, as a typo (64). `--timeout` and the variable are
/// durations, as the other commands take them (30s, 2m, 1h, 500ms), in whole
/// seconds rounded up. The flag takes a day at most, as `--ConnectTimeout`
/// does (64 past it); the variable, which bounds whole runs of other commands
/// too, is held to a day, and a bad one is a setting's fault (78).
pub fn chosen(
    connect: Option<&str>,
    timeout: Option<&str>,
    var: impl Fn(&str) -> Option<String>,
) -> Result<Option<Bound>, Refusal> {
    let connect = of_connect_timeout(connect)?;
    let timeout = timeout.map(flag_bound).transpose()?;
    if connect.is_some() || timeout.is_some() {
        return Ok(connect.or(timeout));
    }
    Ok(variable_bound(var)?.map(|limit| Bound { limit, name: TIMEOUT_ENV }))
}

/// `PODSSH_TIMEOUT` as a bound, held to a day: `None` when it is not set, or
/// empty, as each command reads it.
pub fn variable_bound(var: impl Fn(&str) -> Option<String>) -> Result<Option<Duration>, Refusal> {
    let Some(text) = var(TIMEOUT_ENV).filter(|v| !v.trim().is_empty()) else { return Ok(None) };
    let seconds = whole_seconds(TIMEOUT_ENV, &text).map_err(Refusal::config)?;
    Ok(Some(Duration::from_secs(seconds.min(LONGEST))))
}

/// `--timeout DURATION` as a bound: 1 s to a day.
fn flag_bound(text: &str) -> Result<Bound, Refusal> {
    let seconds = whole_seconds("--timeout", text).map_err(Refusal::usage)?;
    if seconds > LONGEST {
        return Err(Refusal::usage(format!(
            "--timeout {text}: a day at most ({LONGEST} s), as --ConnectTimeout takes it"
        )));
    }
    Ok(Bound { limit: Duration::from_secs(seconds), name: "--timeout" })
}

/// `text`, a duration of the other commands' `--timeout`, in whole seconds
/// rounded up; the words of a bad one name `name`.
fn whole_seconds(name: &str, text: &str) -> Result<u64, String> {
    let parsed = crate::non_interactive::parse_duration(name, text).map_err(|_| {
        format!(
            "{name} {text:?}: a whole duration above 0, as 30s, 2m or 1h (a bare 30 is 30 s); it bounds the \
             session's open, as --ConnectTimeout does"
        )
    })?;
    Ok(parsed.as_secs().saturating_add(u64::from(parsed.subsec_nanos() > 0)))
}

/// The watch of one run's bound. Its drop ends the bound: the run is over.
#[must_use = "the bound ends when the watch is dropped"]
pub struct Watch {
    run: Option<u64>,
}

/// Bound the open of this run by `bound`, from now: `verb` names the command
/// in the line, and `first` is the words of the first step. With no bound,
/// no watch: each step's own limit alone.
pub fn watch(bound: Option<Bound>, verb: &'static str, first: &str) -> Watch {
    let Some(Bound { limit, name }) = bound else { return Watch { run: None } };
    let run = state().start(first);
    let deadline = Instant::now() + limit;
    let thread = std::thread::Builder::new().name("connect-timeout".into());
    // With no thread, each step's own limit still ends its wait.
    if thread.spawn(move || end_at(run, deadline, limit, verb, name)).is_err() {
        podssh_ssh::err_line!("podssh {verb}: {name} has no thread to watch it; each step keeps its own limit");
    }
    Watch { run: Some(run) }
}

/// The watch's thread: once `deadline` passed with no session open, the line
/// of the step that waited, with the `name` of the bound, and the exit of a
/// far end out of reach.
fn end_at(run: u64, deadline: Instant, limit: Duration, verb: &'static str, name: &'static str) {
    let mut state = state();
    loop {
        if state.run != run || state.done {
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        state = match CHANGED.wait_timeout(state, deadline - now) {
            Ok((state, _)) => state,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
    // From here no session opens: `opened` waits for the exit.
    state.passed = true;
    let step = state.step.clone();
    drop(state);
    podssh_ssh::err_line!("podssh {verb}: {step} within {} s ({name})", limit.as_secs());
    for stop in STOPS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        stop();
    }
    std::process::exit(EX_UNAVAILABLE);
}

/// The words of the step that the open waits for now; nothing with no watch.
pub fn step(words: impl Into<String>) {
    state().step(words.into());
}

/// The session opened: the bound no longer applies. Once the bound passed,
/// the watch ends the run, and no byte of the session goes out first.
pub fn opened() {
    let mut state = state();
    if state.passed {
        drop(state);
        // The exit comes on the watch's thread.
        loop {
            std::thread::park();
        }
    }
    let run = state.run;
    state.end(run);
    CHANGED.notify_all();
}

/// The node answered `ready` (a hook of the operator's leg): its first bytes
/// come next, the greeting of its layer, or from a node of `--plain` its
/// TARGET's.
pub fn ready() {
    step("the node's first bytes did not come after its ready");
}

/// An end-to-end channel will follow the layer: the session opens with the
/// channel's check of the node's key.
pub fn channel_follows() {
    state().channel = true;
}

/// The layer is up, or the node's first bytes came with none: the session
/// opens here, unless a channel follows.
pub fn layer_up() {
    let opens = state().layer_up();
    if opens {
        opened();
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(run) = self.run {
            state().end(run);
            CHANGED.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_seconds_are_the_bound_and_zero_is_refused() {
        assert_eq!(parse(None).unwrap(), None);
        assert_eq!(parse(Some("25")).unwrap(), Some(Duration::from_secs(25)));
        assert_eq!(parse(Some("25s")).unwrap(), Some(Duration::from_secs(25)));
        for bad in ["0", "0s", "-1", "2.5", "soon", "", "86401"] {
            let refusal = parse(Some(bad)).unwrap_err();
            assert_eq!(refusal.code, 64, "{bad:?}");
            assert!(refusal.message.starts_with("--ConnectTimeout "), "{bad:?}: {}", refusal.message);
        }
    }

    /// `--timeout` and `PODSSH_TIMEOUT` (T-613): durations in whole seconds,
    /// rounded up; `--ConnectTimeout` first, then the flag, then the
    /// variable; the flag refused past a day (64), the variable held to one,
    /// and a bad variable a setting's fault (78), read only with no flag.
    #[test]
    fn timeout_and_the_variable_are_other_names_of_the_bound() {
        let none = |_: &str| None::<String>;
        let set = |value: &'static str| move |name: &str| (name == TIMEOUT_ENV).then(|| value.to_string());
        let bound = |limit: u64, name| Some(Bound { limit: Duration::from_secs(limit), name });
        assert_eq!(chosen(None, None, none).unwrap(), None);
        assert_eq!(chosen(None, Some("2"), none).unwrap(), bound(2, "--timeout"));
        assert_eq!(chosen(None, Some("2m"), none).unwrap(), bound(120, "--timeout"));
        assert_eq!(chosen(None, Some("1500ms"), none).unwrap(), bound(2, "--timeout"), "rounded up");
        assert_eq!(chosen(None, None, set("30s")).unwrap(), bound(30, TIMEOUT_ENV));
        assert_eq!(chosen(None, None, set("48h")).unwrap(), bound(LONGEST, TIMEOUT_ENV), "held to a day");
        assert_eq!(chosen(None, None, set(" ")).unwrap(), None, "an empty value is no value");
        assert_eq!(chosen(Some("5"), Some("2"), set("1h")).unwrap(), bound(5, "--ConnectTimeout"));
        assert_eq!(chosen(None, Some("7"), set("soon")).unwrap(), bound(7, "--timeout"), "the flag wins");
        for bad in ["0", "2x", "", "-1", "25h"] {
            let refusal = chosen(None, Some(bad), none).unwrap_err();
            assert_eq!(refusal.code, 64, "{bad:?}");
            assert!(refusal.message.starts_with("--timeout "), "{bad:?}: {}", refusal.message);
        }
        assert_eq!(chosen(Some("5"), Some("2x"), none).unwrap_err().code, 64, "a typo beside --ConnectTimeout");
        let refusal = chosen(None, None, set("soon")).unwrap_err();
        assert_eq!(refusal.code, 78);
        assert!(refusal.message.starts_with("PODSSH_TIMEOUT \"soon\""), "{}", refusal.message);
    }

    /// The steps of one run, on a state of the test's own: the layer opens
    /// the session with no channel, and names the channel's step with one; a
    /// run that ended takes no step, and an older run's end leaves the new.
    #[test]
    fn the_steps_of_a_run_and_its_end() {
        let mut state = State::new();
        let first = state.start("no relay host answered");
        state.step("the node did not answer ready".to_string());
        assert_eq!(state.step, "the node did not answer ready");
        assert!(state.layer_up(), "no channel: the layer opens the session");
        state.channel = true;
        assert!(!state.layer_up(), "a channel follows the layer");
        assert_eq!(state.step, CHANNEL_STEP);
        let second = state.start("the relay did not answer");
        assert!(!state.channel && !state.done, "a new run starts clean");
        state.end(first);
        assert!(!state.done, "the end of an older run");
        state.end(second);
        state.step("a step after the run".to_string());
        assert_eq!(state.step, "the relay did not answer", "a run that ended takes no step");
    }
}
