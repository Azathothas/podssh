//! What `podssh relay serve` gives up once its listener is bound (T-629,
//! GitHub #127). A port below 1024 needs a privilege for its bind alone: a
//! start as root, or a file capability on the binary. Nothing after the
//! bind needs one, so on Linux, after it and before the runtime starts its
//! threads, which take the sets of the thread that makes them: no new
//! privileges on an exec (`PR_SET_NO_NEW_PRIVS`), each capability of the
//! bounding set dropped where `CAP_SETPCAP` allows it, and the effective,
//! permitted and inheritable sets emptied (`capset`). Linux keeps these for
//! each thread, so the first thread of the process, which waits while this
//! one runs the command, does the same on itself (`crate::first_thread`);
//! then each thread is read again. The uid and the gid stay.
//!
//! A thread that holds no capability, the usual start, asks for no new
//! privileges alone, and nothing is said. Other systems have no such sets:
//! nothing is dropped there, and nothing is said.

// Elsewhere only the words of a plan are used, by its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::relay_settings::Refusal;

/// `CAP_SETPCAP`, which a drop from the bounding set needs.
pub const CAP_SETPCAP: u32 = 8;
/// The highest capability that a probe asks for: a kernel answers `EINVAL`
/// past its own last (`CAP_LAST_CAP`, 40 on Linux 6), so a newer kernel's
/// are dropped too.
pub const CAP_MOST: u32 = 63;
/// Linux's numbers of the two errors that a drop of the bounding set takes
/// as done; the same on each architecture.
pub const EPERM: i32 = 1;
pub const EINVAL: i32 = 22;
/// How long the first thread has to answer.
const FIRST_WAIT: Duration = Duration::from_secs(5);

/// Whether a capability was held and dropped, for a later line that cannot
/// read a file (`certs.rs`).
static DROPPED: AtomicBool = AtomicBool::new(false);

/// Whether this process gave up capabilities that it held.
pub fn dropped() -> bool {
    DROPPED.load(Ordering::Relaxed)
}

/// The capability sets of one thread, each a mask by capability number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sets {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

impl Sets {
    pub fn none(&self) -> bool {
        (self.effective | self.permitted | self.inheritable) == 0
    }
}

/// What one thread holds, as the probe read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Its sets, or why they could not be read.
    pub sets: Result<Sets, String>,
    /// The capabilities of its bounding set.
    pub bounding: u64,
}

impl Found {
    /// A capability is held for sure: each failed step then refuses.
    pub fn holds(&self) -> bool {
        matches!(&self.sets, Ok(sets) if !sets.none())
    }
}

/// One step of the drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    NoNewPrivs,
    Bound(u32),
    Clear,
}

/// The calls of the drop, on the calling thread; its tests replace them.
/// Each `Err` is an errno.
pub trait Calls {
    fn sets(&mut self) -> Result<Sets, i32>;
    /// Whether the bounding set holds `cap`: `EINVAL` past the kernel's last.
    fn bounded(&mut self, cap: u32) -> Result<bool, i32>;
    fn no_new_privs(&mut self) -> Result<(), i32>;
    fn bound_drop(&mut self, cap: u32) -> Result<(), i32>;
    /// `capset` with the three sets empty.
    fn clear(&mut self) -> Result<(), i32>;
}

/// The words of `errno`, as the system gives them.
pub fn errno_words(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// What this thread holds, by `calls`: probed first (rule 1 of `AGENTS.md`).
pub fn probe(calls: &mut dyn Calls) -> Found {
    let sets = calls.sets().map_err(|errno| format!("capget: {}", errno_words(errno)));
    let mut bounding = 0u64;
    for cap in 0..=CAP_MOST {
        match calls.bounded(cap) {
            Ok(true) => bounding |= 1u64 << cap,
            Ok(false) => {}
            // Past the kernel's last capability, or no such call.
            Err(_) => break,
        }
    }
    Found { sets, bounding }
}

/// The steps for what `found` holds: no new privileges always, as it costs
/// nothing; with a capability, the bounding set where `CAP_SETPCAP` is
/// effective, then the sets emptied; with sets that could not be read, each
/// step, as a capability may be held.
pub fn plan(found: &Found) -> Vec<Step> {
    let mut steps = vec![Step::NoNewPrivs];
    let bounding = (0..=CAP_MOST).filter(|cap| (found.bounding >> cap) & 1 == 1).map(Step::Bound);
    match &found.sets {
        Ok(sets) if sets.none() => {}
        Ok(sets) => {
            if (sets.effective >> CAP_SETPCAP) & 1 == 1 {
                steps.extend(bounding);
            }
            steps.push(Step::Clear);
        }
        Err(_) => {
            steps.extend(bounding);
            steps.push(Step::Clear);
        }
    }
    steps
}

/// Run `steps` by `calls`. With `strict` (the thread held a capability), a
/// step that fails refuses the start (78), as the role would serve with what
/// it says it gave up; but `EINVAL` (past the kernel's last capability) and
/// `EPERM` (no `CAP_SETPCAP`) of the bounding set are taken as done, and
/// `EINVAL` of `PR_SET_NO_NEW_PRIVS` (a kernel before 3.5) is a note. With
/// no capability for sure, each failure is a note. The notes, in order.
pub fn apply(steps: &[Step], strict: bool, calls: &mut dyn Calls) -> Result<Vec<String>, Refusal> {
    let mut notes = Vec::new();
    for step in steps {
        let (result, call) = match *step {
            Step::NoNewPrivs => (calls.no_new_privs(), "prctl(PR_SET_NO_NEW_PRIVS)".to_string()),
            Step::Bound(cap) => (calls.bound_drop(cap), format!("prctl(PR_CAPBSET_DROP, {cap})")),
            Step::Clear => (calls.clear(), "capset".to_string()),
        };
        let Err(errno) = result else { continue };
        match (*step, errno) {
            (Step::Bound(_), EINVAL | EPERM) => {}
            (Step::NoNewPrivs, EINVAL) => notes.push("this kernel has no PR_SET_NO_NEW_PRIVS".to_string()),
            _ if strict => {
                return Err(Refusal::config(format!(
                    "{call} after the bind: {}; the role does not serve with the capabilities of its start",
                    errno_words(errno)
                )));
            }
            _ => notes.push(format!("{call}: {}", errno_words(errno))),
        }
    }
    Ok(notes)
}

/// What the drop did on one thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub found: Found,
    pub steps: Vec<Step>,
    pub notes: Vec<String>,
}

/// The drop on the calling thread, by `calls`.
pub fn drop_with(calls: &mut dyn Calls) -> Result<Outcome, Refusal> {
    let found = probe(calls);
    let steps = plan(&found);
    let notes = apply(&steps, found.holds(), calls)?;
    Ok(Outcome { found, steps, notes })
}

/// The words of the first line after a drop: none where no thread held a
/// capability. `threads` is how many threads were read again, or why none
/// could be; `uid` the effective one, which stays.
pub fn words(here: &Outcome, first: Option<&Outcome>, threads: &Result<usize, String>, uid: u32) -> Option<String> {
    let outcomes = std::iter::once(here).chain(first);
    let held = outcomes.clone().any(|o| o.found.holds());
    let unread = outcomes.clone().find_map(|o| o.found.sets.as_ref().err().cloned());
    let bounding = outcomes.clone().any(|o| o.steps.iter().any(|s| matches!(s, Step::Bound(_))));
    let mut notes: Vec<String> = outcomes.flat_map(|o| o.notes.iter().cloned()).collect();
    notes.dedup();
    if let Err(why) = threads {
        notes.push(format!("its threads not read again ({why})"));
    }
    let mut line = match (held, unread) {
        (true, _) => {
            let each = match threads {
                Ok(1) => "on its one thread".to_string(),
                Ok(n) => format!("on each of its {n} threads"),
                Err(_) => "on this thread and the first".to_string(),
            };
            let bset = if bounding { ", and its bounding set" } else { "; its bounding set stays, as no CAP_SETPCAP" };
            format!(", the capabilities of its start dropped after the bind, {each}{bset}")
        }
        (false, Some(why)) => {
            format!(", the capabilities of its start not read ({why}), each asked to go after the bind")
        }
        (false, None) => return None,
    };
    if !notes.is_empty() {
        line.push_str(&format!(" ({})", notes.join("; ")));
    }
    if held && uid == 0 {
        line.push_str(
            "; it stays uid 0, which may still write each file that root owns: a user of its own with the file \
             capability cap_net_bind_service binds the port with none of root's",
        );
    }
    Some(line)
}

/// The value of `name` in a thread's `/proc/.../status`, in hex for the
/// sets (`CapEff`), in decimal for the flags (`NoNewPrivs`).
pub fn status_value(text: &str, name: &str, radix: u32) -> Option<u64> {
    let line = text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))?;
    u64::from_str_radix(line.trim(), radix).ok()
}

/// The three sets of a thread's `status`.
pub fn status_sets(text: &str) -> Option<Sets> {
    Some(Sets {
        effective: status_value(text, "CapEff", 16)?,
        permitted: status_value(text, "CapPrm", 16)?,
        inheritable: status_value(text, "CapInh", 16)?,
    })
}

/// The drop once the listener is bound (Linux): on this thread, then on the
/// first thread, then each thread read again; the first line's words, or
/// none where nothing was held. A thread that keeps a capability that was
/// held refuses the start (78).
#[cfg(target_os = "linux")]
pub fn give_up() -> Result<Option<String>, Refusal> {
    use super::harden_sys::{self, Sys};
    let here = drop_with(&mut Sys)?;
    let first = match crate::first_thread::on_first(|| drop_with(&mut Sys), FIRST_WAIT) {
        Some(outcome) => Some(outcome?),
        None if crate::first_thread::waits() && here.found.holds() => {
            return Err(Refusal::config(
                "the first thread of the process did not drop its capabilities within 5 s; the role does not serve \
                 with them",
            ));
        }
        None => None,
    };
    let held = here.found.holds() || first.as_ref().is_some_and(|o| o.found.holds());
    let threads = harden_sys::threads_holding();
    if let (true, Ok((_, holding))) = (held, &threads) {
        if !holding.is_empty() {
            return Err(Refusal::config(format!(
                "the threads {} of this process keep capabilities after the drop; the role does not serve with them",
                holding.join(", ")
            )));
        }
    }
    DROPPED.store(held, Ordering::Relaxed);
    let threads = threads.map(|(n, _)| n);
    Ok(words(&here, first.as_ref(), &threads, harden_sys::euid()))
}

/// No capability sets here: nothing to drop, and nothing said.
#[cfg(not(target_os = "linux"))]
pub fn give_up() -> Result<Option<String>, Refusal> {
    let _ = FIRST_WAIT;
    Ok(None)
}

#[cfg(test)]
#[path = "harden_tests.rs"]
mod tests;
