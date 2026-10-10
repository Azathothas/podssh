//! Whether a failed run may be tried again on a new connection (T-025):
//! only when nothing reached the destination yet, and only for a drop of the
//! relay that a new session may not meet. Only podssh knows whether the
//! request went out, so the try is podssh's, and the exit codes stay
//! OpenSSH's.

use std::sync::atomic::{AtomicU8, Ordering};

use podssh_ws::session::{forward_close, ForwardClose};
use podssh_ws::SessionError;

use crate::relay_stream::RelayEnd;

/// How far a run got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// The SSH handshake with a hop.
    Handshake,
    /// The login at a hop.
    Auth,
    /// Logged in at the destination, and nothing asked of it yet.
    Ready,
    /// A request went to the destination: a command, a shell, a subsystem,
    /// a connection of `-W`, a forward of `-R`, or the wait of `-N`.
    Requested,
}

/// How far the run of this process got. A process runs one chain of
/// connections at a time, as the handler's last disconnect assumes.
static PHASE: AtomicU8 = AtomicU8::new(0);

/// A new run starts at its handshake.
pub(crate) fn begin() {
    PHASE.store(Phase::Handshake as u8, Ordering::SeqCst);
}

/// The run got as far as `phase`; it never goes back.
pub(crate) fn reached(phase: Phase) {
    PHASE.fetch_max(phase as u8, Ordering::SeqCst);
}

/// How far the run of this process got.
pub fn phase() -> Phase {
    match PHASE.load(Ordering::SeqCst) {
        0 => Phase::Handshake,
        1 => Phase::Auth,
        2 => Phase::Ready,
        _ => Phase::Requested,
    }
}

/// What a new try may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// The link from podssh to the relay broke, or ended with no Close: the
    /// next relay host, as a failed upgrade goes to it.
    NextHost,
    /// The relay lost its link to the target: once more, then stop.
    Again,
}

/// Whether a run that failed at `phase`, with the relay leg's end `end`, may
/// be tried again, and how. Never once a request went out; never without a
/// drop of the relay (a refusal of the server, a host key, a login is no
/// drop); never at the relay's limits or for a backlog (1001, 1009, 1013).
pub fn retry_phase(phase: Phase, end: Option<&RelayEnd>) -> Option<Retry> {
    if phase >= Phase::Requested {
        return None;
    }
    match end? {
        // A frame that broke RFC 6455 is a defect, not a drop.
        RelayEnd::Failed(SessionError::Protocol(_) | SessionError::TooLarge(_)) => None,
        RelayEnd::Failed(_) => Some(Retry::NextHost),
        RelayEnd::Closed { code: Some(1001 | 1009 | 1013), .. } => None,
        RelayEnd::Closed { code, reason } => match forward_close(*code, reason) {
            ForwardClose::Client => Some(Retry::NextHost),
            ForwardClose::Target => Some(Retry::Again),
            ForwardClose::Normal | ForwardClose::Limit | ForwardClose::Unknown => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed(code: Option<u16>, reason: &str) -> RelayEnd {
        RelayEnd::Closed { code, reason: reason.into() }
    }

    /// Before the request, a drop of the link to the relay goes to the next
    /// host, and one of the link to the target tries once more.
    #[test]
    fn retry_phase_before_the_request_follows_the_close() {
        let lost = SessionError::Idle("the relay sent nothing for 40 s".into());
        for phase in [Phase::Handshake, Phase::Auth, Phase::Ready] {
            assert_eq!(retry_phase(phase, Some(&RelayEnd::Failed(lost.clone()))), Some(Retry::NextHost));
            assert_eq!(retry_phase(phase, Some(&closed(None, ""))), Some(Retry::NextHost), "no Close");
            assert_eq!(
                retry_phase(phase, Some(&closed(Some(1011), "client send failed: reset"))),
                Some(Retry::NextHost)
            );
            for reason in ["target closed before sending anything", "connect failed: refused", "write failed: x"] {
                assert_eq!(retry_phase(phase, Some(&closed(Some(1011), reason))), Some(Retry::Again), "{reason}");
            }
        }
    }

    /// Never once a request went out, never without a drop, never at the
    /// relay's limits or for a backlog, never for a close it does not explain.
    #[test]
    fn retry_phase_never_after_the_request_or_at_a_limit() {
        let drop = closed(Some(1011), "target closed before sending anything");
        assert_eq!(retry_phase(Phase::Requested, Some(&drop)), None);
        assert_eq!(retry_phase(Phase::Requested, Some(&closed(None, ""))), None);
        assert_eq!(retry_phase(Phase::Handshake, None), None, "no drop of the relay");
        let broken = RelayEnd::Failed(SessionError::Protocol("a masked frame".into()));
        assert_eq!(retry_phase(Phase::Handshake, Some(&broken)), None, "a defect, not a drop");
        for (code, reason) in [
            (1001, "idle timeout"),
            (1009, "session byte cap"),
            (1013, "target write backlog"),
            (1013, "client receive backlog"),
            (1000, "target closed"),
            (1011, "something new"),
            (4000, "a code of its own"),
        ] {
            assert_eq!(retry_phase(Phase::Ready, Some(&closed(Some(code), reason))), None, "{code} {reason}");
        }
    }

    /// The phase only goes forward, and a new run starts again.
    #[test]
    fn retry_phase_is_recorded_forward_only() {
        begin();
        reached(Phase::Ready);
        reached(Phase::Auth);
        assert_eq!(phase(), Phase::Ready);
        reached(Phase::Requested);
        assert_eq!(phase(), Phase::Requested);
        begin();
        assert_eq!(phase(), Phase::Handshake);
    }
}
