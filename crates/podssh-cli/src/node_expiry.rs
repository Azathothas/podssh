//! A pair's expiry, said before it comes, and the next pair taken at it
//! (T-395). A pair lives 72 h at most and the relay renews none, so a node of
//! the pair's road ends at a time that podssh knows in advance: the node
//! says it 24 h, 6 h and 1 h before, with the command that makes the next
//! pair, and at the expiry it goes on with a pair that was stored under its
//! label since, with no new start. A node whose pair came from
//! `--pair-file` has no label in the store: its line says so.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::{self, Pair};
use podssh_relay::reverse::node::RepairHook;

use crate::pairs::{now_ms, utc};

/// The times before an expiry at which a node says it, the longest first.
pub(crate) const WARN_BEFORE: [Duration; 3] =
    [Duration::from_secs(24 * 3600), Duration::from_secs(6 * 3600), Duration::from_secs(3600)];

/// The last part of a pair's life, in which `podssh relay pair NAME` makes
/// the next pair: the time of the first line, so that its command works.
pub(crate) const RENEW_WINDOW: Duration = WARN_BEFORE[0];

/// The longest sleep between two looks at the clock: the pair can change at
/// the expiry, and a host's clock can jump.
const LOOK: Duration = Duration::from_secs(600);

/// A line for the user, from any task of the node.
pub(crate) type Say = Arc<dyn Fn(String) + Send + Sync>;

/// `5 h 59 min`, `59 min`, or `less than a minute`.
pub(crate) fn left_words(left_ms: i64) -> String {
    let minutes = left_ms.max(0) / 60_000;
    match (minutes / 60, minutes % 60) {
        (0, 0) => "less than a minute".to_string(),
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// The line for a pair of `label` that expires at `expires_ms`; `stored`:
/// the pair is the label's in the store, whose next pair the node takes.
pub(crate) fn line(label: &str, expires_ms: i64, now: i64, stored: bool) -> String {
    let when = format!(
        "the pair expires in {}, at {}, and the relay renews none",
        left_words(expires_ms - now),
        utc(expires_ms)
    );
    if stored {
        format!(
            "{when}: `podssh relay pair {label} --operator-file FILE` makes the next one now, which this node takes \
             at the expiry; FILE goes to its operators"
        )
    } else {
        format!("{when}: the next pair needs a new --pair-file and a new start of this node")
    }
}

/// The part of [`WARN_BEFORE`] that `left` is in: the index of the shortest
/// time that is not shorter than `left`; none more than 24 h before.
pub(crate) fn band(left: Duration) -> Option<usize> {
    WARN_BEFORE.iter().rposition(|before| *before >= left)
}

/// When to look again: at the next time of [`WARN_BEFORE`], within [`LOOK`].
fn next_look(left: Duration) -> Duration {
    let edge = WARN_BEFORE.iter().find(|before| **before < left).map(|before| left - *before);
    edge.unwrap_or(LOOK).min(LOOK).max(Duration::from_secs(1))
}

/// The expiry of the pair that the node runs with, shared by its hook and
/// its lines.
#[derive(Clone)]
pub(crate) struct Current(Arc<AtomicI64>);

impl Current {
    pub(crate) fn of(pair: &Pair) -> Current {
        Current(Arc::new(AtomicI64::new(pair.expires_ms)))
    }

    fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Say each part of [`WARN_BEFORE`] once for each pair, the first at once
/// when the node starts within it; until the node ends, which aborts it.
pub(crate) async fn warn(label: String, current: Current, stored: bool, say: Say) {
    let mut said: Option<(i64, usize)> = None;
    loop {
        let (expires, now) = (current.get(), now_ms());
        let left = Duration::from_millis(u64::try_from(expires - now).unwrap_or(0));
        if !left.is_zero() {
            if let Some(part) = band(left) {
                let fresh = said.is_none_or(|(at, before)| at != expires || part > before);
                if fresh {
                    say(line(&label, expires, now, stored));
                    said = Some((expires, part));
                }
            }
        }
        let wait = if left.is_zero() { LOOK } else { next_look(left) };
        tokio::time::sleep(wait).await;
    }
}

/// The pair stored under `label` that the node takes at the expiry of the
/// one that ends: one that expires later, and has not expired.
pub(crate) fn next_pair(stored: Option<Pair>, ending_ms: i64, now: i64) -> Option<Pair> {
    stored.filter(|next| next.expires_ms > ending_ms && next.expires_ms > now)
}

/// The node's hook for an expired pair: the next pair under `label`, with
/// a line; none, and the node ends with 77 as before, when nobody made one.
pub(crate) fn hook(label: String, current: Current, say: Say) -> RepairHook {
    Arc::new(move || {
        let (label, current, say) = (label.clone(), current.clone(), say.clone());
        Box::pin(async move {
            let ending = current.get();
            let next = next_pair(pair::load(&label).ok().flatten(), ending, now_ms());
            match &next {
                Some(next) => {
                    current.0.store(next.expires_ms, Ordering::Relaxed);
                    say(format!(
                        "the pair expired; the next pair under {label:?}, which expires at {}, takes its place",
                        utc(next.expires_ms)
                    ));
                }
                None => say(format!("the pair expired, and no next pair is stored under {label:?}")),
            }
            next
        })
    })
}

/// The hook and the lines of a node's pair: the hook only for a pair of
/// the store, as the next one is looked for there. The task ends with the
/// node: the caller aborts it.
pub(crate) fn watch(
    label: &str,
    pair: &Pair,
    stored: bool,
    say: Say,
) -> (Option<RepairHook>, tokio::task::JoinHandle<()>) {
    let current = Current::of(pair);
    let lines = tokio::spawn(warn(label.to_string(), current.clone(), stored, say.clone()));
    (stored.then(|| hook(label.to_string(), current, say)), lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;

    #[test]
    fn each_part_before_the_expiry_is_found() {
        assert_eq!(band(Duration::from_secs(30 * H)), None);
        assert_eq!(band(Duration::from_secs(24 * H)), Some(0));
        assert_eq!(band(Duration::from_secs(7 * H)), Some(0));
        assert_eq!(band(Duration::from_secs(5 * H)), Some(1));
        assert_eq!(band(Duration::from_secs(H)), Some(2));
        assert_eq!(band(Duration::from_secs(60)), Some(2));
    }

    #[test]
    fn the_next_look_is_at_the_next_part_or_within_ten_minutes() {
        assert_eq!(next_look(Duration::from_secs(24 * H + 30)), Duration::from_secs(30));
        assert_eq!(next_look(Duration::from_secs(6 * H + 5)), Duration::from_secs(5));
        assert_eq!(next_look(Duration::from_secs(30 * H)), LOOK);
        // Past the last time, nothing more is said of this pair.
        assert_eq!(next_look(Duration::from_secs(120)), LOOK);
    }

    #[test]
    fn the_time_left_is_in_words() {
        assert_eq!(left_words(59_000), "less than a minute");
        assert_eq!(left_words(59 * 60_000), "59 min");
        assert_eq!(left_words(6 * 3_600_000), "6 h");
        assert_eq!(left_words(5 * 3_600_000 + 59 * 60_000), "5 h 59 min");
        assert_eq!(left_words(-5), "less than a minute");
    }

    #[test]
    fn the_line_names_the_command_or_the_pair_file() {
        let stored = line("lab", 7_200_000, 0, true);
        assert!(stored.contains("in 2 h") && stored.contains("podssh relay pair lab --operator-file FILE"), "{stored}");
        let carried = line("lab", 7_200_000, 0, false);
        assert!(carried.contains("--pair-file") && !carried.contains("relay pair"), "{carried}");
    }

    #[test]
    fn only_a_later_pair_that_lives_is_the_next_one() {
        let pair = |expires_ms| {
            let mut pair = any();
            pair.expires_ms = expires_ms;
            pair
        };
        assert!(next_pair(None, 100, 50).is_none());
        assert!(next_pair(Some(pair(100)), 100, 50).is_none(), "the same pair");
        assert!(next_pair(Some(pair(90)), 100, 50).is_none(), "an older pair");
        assert!(next_pair(Some(pair(200)), 100, 300).is_none(), "a later pair that expired too");
        assert_eq!(next_pair(Some(pair(200)), 100, 150).map(|p| p.expires_ms), Some(200));
    }

    /// A pair of the relay's shapes: a name of 34 characters, tokens of 64.
    fn any() -> Pair {
        let (name, token) = (format!("p-{}", "0".repeat(32)), "a".repeat(64));
        let body = format!(
            r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":3600000}}"#
        );
        let relay = podssh_relay::relay::Relay { host: "relay.test".into(), port: 443 };
        pair::parse(&relay, body.as_bytes(), 0).unwrap()
    }
}
