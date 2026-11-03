//! `--no-resume` (T-612) of `ssh`, `cp`, `mv`, `scp`, `sftp`, `proxy`,
//! `pipe` and `operator`: each session to a node asks the node to end it
//! with its link, so that the node keeps nothing of it after a loss and its
//! budget is free at once. The session has its first link alone: no resume,
//! no move before the relay's limits and no spare link, as with a node of
//! `--plain`, so the relay's limits end it too. A node that does not know the
//! ask keeps the session for its deadline, as before, and the client says
//! so. The layer's settings read the switch (`crate::layered::settings`), so
//! each road to a node takes it; a process runs one command, so one switch,
//! as the deadline of `--resume-deadline`.

use std::sync::atomic::{AtomicBool, Ordering};

use podssh_relay::session::client::{Found, Outcome};
use podssh_relay::session::{once, End};

static ASKED: AtomicBool = AtomicBool::new(false);

/// The command line gave `--no-resume`: each session of this run asks for
/// it. Never turned off again, as one run has one command line.
pub fn ask(asked: bool) {
    if asked {
        ASKED.store(true, Ordering::SeqCst);
    }
}

/// Whether this run asked for sessions that end with their link.
pub fn asked() -> bool {
    ASKED.load(Ordering::SeqCst)
}

/// What the client says of the far end that `found` names, when this run
/// asked: with `-v` that the far end ends the session with its link; always
/// that one which does not know the ask keeps it, as a user who asked would
/// count on its budget. `None` when this run did not ask, or with no layer.
pub fn heard(found: &Found) -> Option<(bool, String)> {
    heard_as(asked(), found)
}

fn heard_as(asked: bool, found: &Found) -> Option<(bool, String)> {
    let Found::Layer { features, .. } = found else { return None };
    match (asked, once::agreed(features)) {
        (false, _) => None,
        (true, true) => Some((false, "the far end ends the session with its link (--no-resume)".to_string())),
        (true, false) => Some((
            true,
            "the far end does not know --no-resume: it keeps the session after a loss for its deadline, as \
             before; this side does not resume it"
                .to_string(),
        )),
    }
}

/// The line of a link whose loss ended a session of `--no-resume`, which a
/// resume would have carried on; `None` for another end, or a run that did
/// not ask.
pub fn ended(outcome: &Outcome) -> Option<String> {
    ended_as(asked(), outcome)
}

fn ended_as(asked: bool, outcome: &Outcome) -> Option<String> {
    let Outcome::Layer(ended) = outcome else { return None };
    // A `CLOSE` that went out is this side's own end, whose answer the link
    // lost: no loss of the session.
    let lost = ended.end.resumable() && !matches!(ended.end, End::Closing);
    (asked && lost).then(|| format!("{}; with --no-resume the session ends with it", ended.end.loss()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::session::{Ended, Role, SessionId};

    fn layer(features: &[&str]) -> Found {
        let features = features.iter().map(|name| name.to_string()).collect();
        Found::Layer { id: SessionId([7; 16]), peer_role: Role::NODE, features, resumed: false }
    }

    #[test]
    fn the_far_end_s_answer_to_the_ask_is_said_and_an_old_one_always() {
        let agreed = layer(&["replay.v1", once::ONCE]);
        let old = layer(&["replay.v1", "heartbeat.v1"]);
        assert_eq!(heard_as(false, &agreed), None, "no ask, no line");
        assert_eq!(heard_as(false, &old), None);
        let (always, line) = heard_as(true, &agreed).unwrap();
        assert!(!always && line.contains("ends the session with its link"), "{line}");
        let (always, line) = heard_as(true, &old).unwrap();
        assert!(always && line.contains("does not know --no-resume"), "{line}");
        assert_eq!(heard_as(true, &Found::Plain { first: Some(b'S') }), None, "no layer, nothing to ask");
    }

    #[test]
    fn a_loss_that_ends_the_session_is_said_and_a_clean_end_is_not() {
        let of = |end: End| Outcome::Layer(Ended { end, received: 0, sent: 0 });
        let line = ended_as(true, &of(End::Lost(None))).unwrap();
        assert!(line.starts_with("the link ended with no word from the far end; with --no-resume"), "{line}");
        assert_eq!(ended_as(false, &of(End::Lost(None))), None, "a run that did not ask resumes instead");
        for end in [End::LocalEnd, End::Closing, End::Closed(String::new())] {
            assert_eq!(ended_as(true, &of(end)), None);
        }
        assert_eq!(ended_as(true, &Outcome::Plain(None)), None);
    }
}
