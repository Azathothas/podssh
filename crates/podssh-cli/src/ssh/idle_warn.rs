//! The warning before the relay's idle cut (T-463, GitHub #98), for a run of
//! `podssh ssh` on the relay's road and for `podssh proxy`, whose stderr its
//! OpenSSH client shows: once nothing has crossed the relay session for the
//! cut less the lead, one line, or the window's title where the session
//! shows T-302's notice there (`podssh_ssh::notice::idle`). Not on a road
//! with no idle cut of the relay: `node://` and the other roads of the
//! resumable layer keep their links busy with its heartbeat, and `--direct`
//! has no relay.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::notice::idle::{self, Crossed, Idle, Step};
use podssh_ssh::notice::Silence;
use podssh_ssh::relay_stream::RelayStatus;
use podssh_ssh::Log;

/// `--idle-warn SECONDS`: the lead, a whole number of seconds; 0 turns the
/// warning off. `None` with no flag, for the default lead.
pub fn lead_of(text: Option<&str>) -> Result<Option<Duration>, String> {
    let Some(text) = text else { return Ok(None) };
    match text.trim().parse::<u64>() {
        Ok(seconds) => Ok(Some(Duration::from_secs(seconds))),
        Err(_) => Err(format!(
            "--idle-warn {text:?}: give a whole number of seconds, as 30, the warning's lead before the relay's idle \
             cut; 0 turns it off"
        )),
    }
}

/// The relay's idle cut for this run: its limits, or the compiled-in one.
pub fn cut() -> Duration {
    Duration::from_secs(podssh_relay::relay::idle_secs(&podssh_relay::pool::in_use()))
}

/// The watch of a relay session of `podssh ssh`, on a task of its own: the
/// title through `silence` where the session shows it, else a line at INFO.
/// `None` with `-q` or a lead of 0; the caller aborts it when the run ends.
pub fn spawn(
    status: RelayStatus,
    silence: Silence,
    asked: Option<Duration>,
    log: Arc<Log>,
) -> Option<tokio::task::JoinHandle<()>> {
    if log.level() == podssh_ssh::LogLevel::Quiet {
        return None;
    }
    let cut = cut();
    let lead = idle::lead(cut, asked)?;
    Some(tokio::spawn(async move {
        let last = move || status.get().is_none().then(|| status.last_payload());
        idle::watch(last, Idle::new(cut, lead), |step| match step {
            Step::Warn { ends_in, .. } if silence.titled() => silence.set_idle(Some(idle::title(*ends_in))),
            Step::Warn { ends_in, quiet } => log.info(&idle::line(*ends_in, *quiet, cut)),
            Step::Crossed => silence.set_idle(None),
            Step::Wait(_) => {}
        })
        .await;
    }))
}

/// The watch of a relay session of `podssh proxy`: a line on stderr, as
/// its other lines go. `None` with a lead of 0.
pub fn spawn_proxy(crossed: Crossed, asked: Option<Duration>) -> Option<tokio::task::JoinHandle<()>> {
    let cut = cut();
    let lead = idle::lead(cut, asked)?;
    Some(tokio::spawn(async move {
        let last = move || Some(crossed.last());
        idle::watch(last, Idle::new(cut, lead), |step| {
            if let Step::Warn { ends_in, quiet } = step {
                let _ = writeln!(std::io::stderr(), "podssh: {}", idle::line(*ends_in, *quiet, cut));
            }
        })
        .await;
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole number of seconds; 0 turns the warning off; any other word
    /// is refused with the remedy.
    #[test]
    fn the_lead_is_whole_seconds() {
        assert_eq!(lead_of(None), Ok(None));
        assert_eq!(lead_of(Some("45")), Ok(Some(Duration::from_secs(45))));
        assert_eq!(lead_of(Some("0")), Ok(Some(Duration::ZERO)));
        for bad in ["30s", "-1", "", "x"] {
            let why = lead_of(Some(bad)).unwrap_err();
            assert!(why.contains("whole number of seconds") && why.contains("0 turns it off"), "{why}");
        }
    }

    /// With `-q`, or `--idle-warn 0`, no watch runs.
    #[tokio::test]
    async fn no_watch_with_q_or_0() {
        let quiet = Arc::new(Log::new(podssh_ssh::LogLevel::Quiet));
        assert!(spawn(RelayStatus::default(), Silence::default(), None, quiet).is_none());
        let info = Arc::new(Log::new(podssh_ssh::LogLevel::Info));
        assert!(spawn(RelayStatus::default(), Silence::default(), Some(Duration::ZERO), info.clone()).is_none());
        let watching = spawn(RelayStatus::default(), Silence::default(), None, info).expect("a watch");
        watching.abort();
        assert!(spawn_proxy(Crossed::default(), Some(Duration::ZERO)).is_none());
    }
}
