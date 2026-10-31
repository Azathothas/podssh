//! The round trip of a link and its retransmission timeout, as RFC 6298
//! computes them for TCP: a smoothed time and its variation, from the
//! segments acknowledged after one send only (Karn's rule), and a timeout
//! that doubles at each expiry until a new measurement.

use std::time::Duration;

/// The timeout before the first measurement.
pub const INITIAL: Duration = Duration::from_secs(1);
/// The least timeout: a DERP server's round trip is tens to hundreds of
/// milliseconds, and a lower bound keeps a burst of late acknowledgements
/// from sending each segment again.
pub const MIN: Duration = Duration::from_millis(250);
/// The most: under the layer's 30 s of silence, so a link sends again a few
/// times before the layer takes it for dead.
pub const MAX: Duration = Duration::from_secs(8);

#[derive(Debug, Clone)]
pub struct Rtt {
    smoothed: Option<Duration>,
    variation: Duration,
    timeout: Duration,
}

impl Default for Rtt {
    fn default() -> Rtt {
        Rtt { smoothed: None, variation: Duration::ZERO, timeout: INITIAL }
    }
}

impl Rtt {
    /// One round trip measured.
    pub fn sample(&mut self, rtt: Duration) {
        match self.smoothed {
            None => {
                self.smoothed = Some(rtt);
                self.variation = rtt / 2;
            }
            Some(smoothed) => {
                let diff = smoothed.abs_diff(rtt);
                self.variation = (self.variation * 3 + diff) / 4;
                self.smoothed = Some((smoothed * 7 + rtt) / 8);
            }
        }
        let smoothed = self.smoothed.unwrap_or(rtt);
        self.timeout = (smoothed + (self.variation * 4).max(Duration::from_millis(10))).clamp(MIN, MAX);
    }

    /// The timeout expired: the next is twice as long, until a new
    /// measurement.
    pub fn back_off(&mut self) {
        self.timeout = (self.timeout * 2).min(MAX);
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The smoothed round trip, once one was measured.
    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timeout_follows_the_round_trip_within_its_bounds() {
        let mut rtt = Rtt::default();
        assert_eq!(rtt.timeout(), INITIAL);
        rtt.sample(Duration::from_millis(100));
        // 100 ms and four times 50 ms.
        assert_eq!(rtt.timeout(), Duration::from_millis(300));
        for _ in 0..50 {
            rtt.sample(Duration::from_millis(100));
        }
        assert_eq!(rtt.timeout(), MIN, "a steady round trip of 100 ms gives the least timeout");
        rtt.sample(Duration::from_secs(20));
        assert_eq!(rtt.timeout(), MAX);
    }

    #[test]
    fn each_expiry_doubles_the_timeout_up_to_its_most() {
        let mut rtt = Rtt::default();
        rtt.back_off();
        assert_eq!(rtt.timeout(), INITIAL * 2);
        for _ in 0..10 {
            rtt.back_off();
        }
        assert_eq!(rtt.timeout(), MAX);
        rtt.sample(Duration::from_millis(100));
        assert_eq!(rtt.timeout(), Duration::from_millis(300), "a new measurement ends the back-off");
    }
}
