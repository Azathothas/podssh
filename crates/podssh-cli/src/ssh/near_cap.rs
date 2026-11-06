//! One line on stderr when a relay session of `podssh ssh` has carried the
//! budget of the relay's limits (T-461, GitHub #84): the relay ends the
//! session at its cap, and the output after the cut is lost, so the user
//! hears it first. Not with `-q`, as each line of podssh's at INFO.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::relay_stream::RelayStatus;
use podssh_ssh::Log;

/// How often the count is read: well under the time that a session takes
/// to carry the 4 MiB between the budget and the cap.
const EVERY: Duration = Duration::from_millis(250);

/// The line, for a budget and a cap in bytes.
pub fn line(budget: u64, cap: u64) -> String {
    format!(
        "this relay session has carried {} MiB, and the relay ends it at {} MiB; podssh cp copies more on new sessions",
        budget >> 20,
        cap >> 20
    )
}

/// The budget of this run's relay and its cap: the relay's limits, lowered
/// by `PODSSH_SESSION_BUDGET`, as `podssh cp` reads them (T-137, T-342).
pub fn limits() -> (u64, u64) {
    use podssh_relay::relay;
    let env = std::env::var(relay::SESSION_BUDGET_ENV).ok();
    let budget = relay::byte_budget(env.as_deref());
    let cap = podssh_relay::pool::in_use().max_session_bytes.unwrap_or(relay::session_byte_cap());
    (budget, cap.max(budget))
}

/// Until the payload that `bytes` counts reaches `budget`, then `say` the
/// line once; `bytes` gives `None` once the session ended, which ends this.
pub async fn watch(bytes: impl Fn() -> Option<u64>, budget: u64, cap: u64, say: impl FnOnce(&str)) {
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match bytes() {
            Some(carried) if carried >= budget => return say(&line(budget, cap)),
            Some(_) => {}
            None => return,
        }
    }
}

/// [`watch`] of a relay session, on a task of its own; the caller aborts it
/// when the run ends.
pub fn spawn(status: RelayStatus, log: Arc<Log>) -> tokio::task::JoinHandle<()> {
    let (budget, cap) = limits();
    tokio::spawn(async move {
        let counted = status.clone();
        let bytes = move || counted.get().is_none().then(|| counted.bytes());
        watch(bytes, budget, cap, |line| log.info(line)).await;
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn the_line_names_the_budget_and_the_cap() {
        assert_eq!(
            line(60 * MIB, 64 * MIB),
            "this relay session has carried 60 MiB, and the relay ends it at 64 MiB; podssh cp copies more on new sessions"
        );
    }

    /// Under the budget nothing is said; past it, the line once, and the
    /// watch ends.
    #[tokio::test(start_paused = true)]
    async fn the_line_comes_once_past_the_budget() {
        let carried = Arc::new(AtomicU64::new(0));
        let said = Arc::new(Mutex::new(Vec::new()));
        let (count, into) = (carried.clone(), said.clone());
        let watching = tokio::spawn(async move {
            let bytes = move || Some(count.load(Ordering::SeqCst));
            watch(bytes, 60 * MIB, 64 * MIB, |line| into.lock().unwrap().push(line.to_string())).await;
        });
        carried.store(59 * MIB, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(said.lock().unwrap().is_empty(), "nothing under the budget");
        carried.store(60 * MIB + 1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(watching.is_finished(), "the watch ends after its line");
        assert_eq!(said.lock().unwrap().as_slice(), [line(60 * MIB, 64 * MIB)]);
    }

    /// A session that ended under the budget ends the watch with no line.
    #[tokio::test(start_paused = true)]
    async fn an_ended_session_says_nothing() {
        let ended = Arc::new(AtomicU64::new(0));
        let said = Arc::new(Mutex::new(Vec::new()));
        let (flag, into) = (ended.clone(), said.clone());
        let watching = tokio::spawn(async move {
            let bytes = move || (flag.load(Ordering::SeqCst) == 0).then_some(MIB);
            watch(bytes, 60 * MIB, 64 * MIB, |line| into.lock().unwrap().push(line.to_string())).await;
        });
        ended.store(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(watching.is_finished());
        assert!(said.lock().unwrap().is_empty());
    }
}
