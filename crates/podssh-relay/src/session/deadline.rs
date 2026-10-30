//! How long a session waits for a new link after a loss (T-306).
//!
//! A far end keeps a session whose link is lost for its deadline, then
//! forgets it. It names that deadline in its `GREETING` as one more feature
//! name, `deadline.SECONDS`: a side that does not know the name ignores it,
//! as it ignores each name that it does not know, and with no name both
//! sides keep 10 minutes, as before. The client waits as long as the far end
//! keeps the session, or less when its user asks.
//!
//! A client counts its wait on a monotonic clock, which need not count the
//! time that its host slept (Rust's `Instant` does not say). A client that
//! wakes after the far end forgot its session tries a resume, and gets
//! `REFUSE` (1, an unknown session): it then says that the far end forgot
//! the session, and how long it was away by the wall clock, which counts
//! the sleep.

use std::time::{Duration, SystemTime};

use super::Settings;

/// The first part of the feature name that carries a far end's deadline.
pub const PREFIX: &str = "deadline.";
/// The longest deadline: a pair lives 72 h at most, and at its expiry the
/// relay ends each session of the pair, which no resume carries on.
pub const LONGEST: Duration = Duration::from_secs(72 * 3600);

/// The feature name of `deadline`, in whole seconds, 1 at least.
pub fn name(deadline: Duration) -> String {
    format!("{PREFIX}{}", deadline.as_secs().max(1))
}

/// The deadline that `features` name, held to [`LONGEST`]; `None` when they
/// name none, or none that is a number of seconds above 0.
pub fn of(features: &[String]) -> Option<Duration> {
    features.iter().find_map(|name| {
        let digits = name.strip_prefix(PREFIX)?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Only digits: a number too large for 64 bits is a long deadline.
        let seconds = digits.parse::<u64>().unwrap_or(u64::MAX);
        if seconds == 0 {
            return None;
        }
        Some(Duration::from_secs(seconds).min(LONGEST))
    })
}

/// The names that a far end gives in its `GREETING`: its features, then its
/// deadline.
pub fn offered(settings: &Settings) -> Vec<String> {
    let mut names: Vec<String> = settings.features.iter().map(|name| name.to_string()).collect();
    names.push(name(settings.resume_deadline));
    names
}

/// How long a client waits for a new link after a loss: as long as the far
/// end keeps the session (`told`, else the deadline of `settings`, which
/// each side keeps when the far end names none), and no longer than its own
/// deadline, when its user set one.
pub fn client_wait(settings: &Settings, told: Option<Duration>) -> Duration {
    let kept = told.unwrap_or(settings.resume_deadline);
    settings.client_deadline.map_or(kept, |own| own.min(kept))
}

/// A duration as a person reads it: `45 s`, `10 min`, `3 h`, `3 h 5 min`.
pub fn span(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    match seconds {
        0..=119 => format!("{seconds} s"),
        120..=7199 => format!("{} min", seconds / 60),
        _ if minutes == 0 => format!("{hours} h"),
        _ => format!("{hours} h {minutes} min"),
    }
}

/// How long this side was away since the loss: by the wall clock, which
/// counts the time that the host slept, from `lost_wall` to `now_wall`; by
/// the monotonic `lost_for` when the wall clock went back.
pub fn away(lost_wall: SystemTime, now_wall: SystemTime, lost_for: Duration) -> String {
    match now_wall.duration_since(lost_wall) {
        Ok(away) => format!("{} by the wall clock", span(away)),
        Err(_) => format!("{} by this host's clock, as the wall clock went back", span(lost_for)),
    }
}

/// What a client says when the far end no longer knew the session that it
/// resumed: `why`, the far end's refusal; `kept`, how long the far end keeps
/// a lost session; `away`, from [`away`].
pub fn forgotten(why: &str, kept: Duration, away: &str) -> String {
    format!(
        "{why}; the far end forgot the session: it keeps one {} after a loss, and this side was away for {away}",
        span(kept)
    )
}
