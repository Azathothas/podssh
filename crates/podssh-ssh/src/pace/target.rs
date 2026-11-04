//! The target of a channel's window (T-661), a pure function of what the
//! connection measured, whether a key was typed lately, and the road's cap.

use std::time::Duration;

/// The least window while a key waits: a few packets, so that a bulk
/// channel never stops, and its adjusts are no burden.
pub const FLOOR: u32 = 16 * 1024;

/// The window before anything was measured, as podssh gave each channel
/// before T-661: russh advertises it when a channel opens.
pub const START: u32 = crate::run::WINDOW;

/// While a key was typed lately: what a key may wait behind, beyond the
/// path's own round trip, as osewa holds its bulk data.
pub const TYPING_MARGIN: Duration = Duration::from_millis(40);

/// Idle: room for the rate to vary, and the wait of the first key after a
/// pause.
pub const IDLE_MARGIN: Duration = Duration::from_millis(200);

/// russh adjusts a window to its target once less than half of it is left,
/// so what is in flight averages three quarters of the target: the target
/// is that much larger, or a window that limits the rate would shrink with
/// the rate that it limits.
const SAWTOOTH: f64 = 4.0 / 3.0;

/// For the same reason half a target must hold the path's bytes of a round
/// trip, or the path runs dry before each adjust arrives: a target is twice
/// those at least. On a long path this, not the margin, bounds the queue,
/// to half a round trip on average.
const FULL: f64 = 2.0;

/// What a channel's target is made of.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Inputs {
    /// A key was typed in the last 2 s.
    pub typing: bool,
    /// The windows drain, so that the least round trip is timed afresh.
    pub draining: bool,
    /// The channel carries a `-J` hop's next connection.
    pub carrier: bool,
    /// The path's rate, bytes a second, when measured lately.
    pub rate: Option<u64>,
    /// The path's least round trip, when measured.
    pub rtt: Option<Duration>,
    /// The channels that share the rate now: 1 at least.
    pub sharing: u32,
    /// The most that the road takes for one channel.
    pub cap: u32,
}

/// The target of a channel's window.
///
/// - A carrier gets the cap: the connection inside it bounds its own
///   channels, and a smaller window would only queue at the hop.
/// - While the windows drain, [`FLOOR`].
/// - Unmeasured, [`START`] idle, [`FLOOR`] while a key waits.
/// - Else the path's rate times its least round trip plus the margin, and
///   twice the rate times the round trip at least, its share of it, at
///   least [`FLOOR`] and at most the cap.
pub fn of(i: &Inputs) -> u32 {
    let cap = i.cap.max(FLOOR);
    if i.carrier {
        return cap;
    }
    if i.draining {
        return FLOOR;
    }
    let (Some(rate), Some(rtt)) = (i.rate, i.rtt) else {
        return if i.typing { FLOOR } else { START.min(cap) };
    };
    let margin = if i.typing { TYPING_MARGIN } else { IDLE_MARGIN };
    let rate = rate as f64;
    let held = rate * (rtt + margin).as_secs_f64() * SAWTOOTH;
    let full = rate * rtt.as_secs_f64() * FULL;
    clamp(held.max(full) / f64::from(i.sharing.max(1)), cap)
}

/// `bytes`, within [`FLOOR`] and `cap`.
fn clamp(bytes: f64, cap: u32) -> u32 {
    if bytes.is_nan() || bytes <= f64::from(FLOOR) {
        FLOOR
    } else if bytes >= f64::from(cap) {
        cap
    } else {
        bytes as u32
    }
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
