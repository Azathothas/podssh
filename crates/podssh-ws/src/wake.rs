//! A check for a host that slept, or a process that stood still (T-663).
//!
//! A link can die while its host sleeps: a NAT's mapping or a proxy's
//! connection is gone when the host wakes. The timers do not tell: tokio's
//! clock is the monotonic clock, which stops while Linux or macOS sleeps, so
//! a timer fires on time after a wake, and the bounds of a link count from
//! before the sleep. So a tick each second reads two clocks: tokio's, on
//! which a tick comes late when the process stood still; and the time that
//! the host slept, where the platform tells it (on Linux, CLOCK_BOOTTIME
//! counts a suspend and CLOCK_MONOTONIC does not), else the wall clock past
//! tokio's. A tick more than 2 s late is a wake, and the caller asks its far
//! end at once. No privilege: reads of clocks, which every host gives.

use std::time::{Duration, SystemTime};

// tokio's clock, which a test can pause and move.
use tokio::time::Instant;

/// How often the clocks are read.
pub const TICK: Duration = Duration::from_secs(1);
/// How late a tick may come and be no wake: more than a busy host delays a
/// timer, less than a sleep that can cost a link.
pub const LATE: Duration = Duration::from_secs(2);

/// One reading of the clocks.
#[derive(Debug, Clone, Copy)]
pub struct Reading {
    /// tokio's clock, which the timers use.
    pub at: Instant,
    /// How long the host has slept since it booted, where the platform
    /// tells it ([`slept`]).
    pub slept: Option<Duration>,
    /// The wall clock, which counts a sleep, and steps with a correction.
    pub wall: SystemTime,
}

impl Reading {
    /// The clocks now.
    pub fn now() -> Reading {
        Reading { at: Instant::now(), slept: slept(), wall: SystemTime::now() }
    }
}

/// The tick: its last reading of the clocks.
#[derive(Debug, Clone, Copy)]
pub struct Wake {
    last: Reading,
}

impl Wake {
    /// A tick that starts at `reading`.
    pub fn new(reading: Reading) -> Wake {
        Wake { last: reading }
    }

    /// When the next tick is due.
    pub fn due(&self) -> Instant {
        self.last.at + TICK
    }

    /// The reading `now` at a tick: how late the tick came by tokio's clock,
    /// with the time that the host was away and tokio's clock did not count,
    /// when the two are more than [`LATE`]. `now` starts the next tick.
    pub fn tick(&mut self, now: Reading) -> Option<Duration> {
        let gone = now.at.saturating_duration_since(self.last.at);
        let late = gone.saturating_sub(TICK);
        let away = match (self.last.slept, now.slept) {
            // The host's own count of its sleeps, which no step of the wall
            // clock moves.
            (Some(before), Some(after)) => after.saturating_sub(before),
            // Else what the wall clock counted past tokio's; a step back is
            // no sleep.
            _ => now.wall.duration_since(self.last.wall).map_or(Duration::ZERO, |wall| wall.saturating_sub(gone)),
        };
        self.last = now;
        let woke = late.saturating_add(away);
        (woke > LATE).then_some(woke)
    }

    /// Until a tick comes more than [`LATE`] late: how late. The last reading
    /// stays in `self`, so a caller may drop this future and make it again.
    pub async fn woke(&mut self) -> Duration {
        loop {
            tokio::time::sleep_until(self.due()).await;
            if let Some(late) = self.tick(Reading::now()) {
                return late;
            }
        }
    }
}

/// How long the host has slept since it booted: CLOCK_BOOTTIME counts a
/// suspend and CLOCK_MONOTONIC does not, so their gap grows by each sleep.
/// `None` when a read fails, as on a kernel with no CLOCK_BOOTTIME.
#[cfg(target_os = "linux")]
pub fn slept() -> Option<Duration> {
    // The monotonic clock first: on a host that never slept the two are
    // equal, and the later read of the boot clock keeps the gap at 0 or more.
    let monotonic = read(libc::CLOCK_MONOTONIC)?;
    let boot = read(libc::CLOCK_BOOTTIME)?;
    Some(boot.saturating_sub(monotonic))
}

/// No such pair of clocks is read here: the wall clock stands in
/// ([`Wake::tick`]).
#[cfg(not(target_os = "linux"))]
pub fn slept() -> Option<Duration> {
    None
}

/// One clock of the kernel, or `None` when it has no such clock.
#[cfg(target_os = "linux")]
fn read(clock: libc::clockid_t) -> Option<Duration> {
    let mut at = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime writes one timespec into `at`, which lives here,
    // or fails with -1 and writes nothing.
    let rc = unsafe { libc::clock_gettime(clock, at.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: the call returned 0, so it wrote the whole timespec.
    let at = unsafe { at.assume_init() };
    Some(Duration::new(u64::try_from(at.tv_sec).ok()?, u32::try_from(at.tv_nsec).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reading `after` the first, by tokio's clock, with the host's sleep
    /// and the wall clock as given.
    fn reading(first: &Reading, after: Duration, slept: Option<Duration>, wall: SystemTime) -> Reading {
        Reading { at: first.at + after, slept, wall }
    }

    fn start(slept: Option<Duration>) -> Reading {
        Reading { at: Instant::now(), slept, wall: SystemTime::now() }
    }

    #[test]
    fn a_tick_on_time_is_no_wake_and_a_tick_late_by_more_than_2_s_is_one() {
        let first = start(Some(Duration::from_secs(7)));
        let mut wake = Wake::new(first);
        let on_time = reading(&first, TICK, first.slept, first.wall + TICK);
        assert_eq!(wake.tick(on_time), None);
        // 2 s late is still a busy host; 3 s is a wake.
        let busy = reading(&on_time, TICK + LATE, first.slept, on_time.wall + TICK + LATE);
        assert_eq!(wake.tick(busy), None);
        let stood_still = reading(&busy, Duration::from_secs(4), first.slept, busy.wall + Duration::from_secs(4));
        assert_eq!(wake.tick(stood_still), Some(Duration::from_secs(3)));
        assert_eq!(wake.due(), stood_still.at + TICK, "the late reading starts the next tick");
    }

    /// Linux: the monotonic clock stops in a suspend, so the timer comes on
    /// time; the gap of the boot-time clock tells the sleep.
    #[test]
    fn a_sleep_that_the_boot_clock_counts_is_a_wake_with_the_timer_on_time() {
        let first = start(Some(Duration::from_secs(100)));
        let mut wake = Wake::new(first);
        let slept = Some(Duration::from_secs(110));
        let woke = reading(&first, TICK, slept, first.wall + Duration::from_secs(11));
        assert_eq!(wake.tick(woke), Some(Duration::from_secs(10)));
    }

    /// Where the platform gives no such pair, the wall clock counts the sleep.
    #[test]
    fn with_no_boot_clock_the_wall_clock_counts_the_sleep() {
        let first = start(None);
        let mut wake = Wake::new(first);
        let woke = reading(&first, TICK, None, first.wall + Duration::from_secs(11));
        assert_eq!(wake.tick(woke), Some(Duration::from_secs(10)));
        // A wall clock set back is no sleep.
        let back = reading(&woke, TICK, None, woke.wall - Duration::from_secs(60));
        assert_eq!(wake.tick(back), None);
    }

    /// A step of the wall clock (an NTP correction) is no wake where the host
    /// counts its sleeps itself.
    #[test]
    fn the_boot_clock_wins_over_a_step_of_the_wall_clock() {
        let first = start(Some(Duration::ZERO));
        let mut wake = Wake::new(first);
        let stepped = reading(&first, TICK, Some(Duration::ZERO), first.wall + Duration::from_secs(60));
        assert_eq!(wake.tick(stepped), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tells_how_long_the_host_slept() {
        let before = slept().expect("CLOCK_BOOTTIME and CLOCK_MONOTONIC");
        let after = slept().expect("again");
        // No sleep between two reads; the clocks' own steps are small.
        assert!(after.saturating_sub(before) < LATE, "{before:?} then {after:?}");
    }
}
