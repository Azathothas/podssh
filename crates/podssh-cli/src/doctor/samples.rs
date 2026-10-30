//! Each probe that connects, several times (T-324): one time cannot tell a
//! path that refuses from one that was slow, nor a steady path from a lossy
//! one. The best time is the path's floor, the median its cost, the 95th
//! percentile what a keystroke sometimes pays, the jitter how much one try
//! differs from the next, and the loss the tries that timed out or broke,
//! counted apart. A refusal is no loss: the path answered.

use std::future::Future;
use std::time::Duration;

use podssh_ws::DialError;
use tokio::net::TcpStream;
// tokio's clock, which a test can pause.
use tokio::time::Instant;

/// The tries of each probe, [`SPREAD`] apart: over a second at least.
pub(super) const TRIES: usize = 9;
const SPREAD: Duration = Duration::from_millis(125);
/// The least bound of a try after the first: a lost SYN is sent again after
/// a second, and twice lost after three.
const LATER_LEAST: Duration = Duration::from_secs(3);
/// No try after the first starts that could end later than this after the
/// first began: a path that answers once and then times out must not hold
/// doctor for minutes.
const BUDGET: Duration = Duration::from_secs(10);

/// The tries of one probe.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Samples {
    /// The time of each try that connected, in milliseconds, in order.
    pub ms: Vec<u64>,
    pub timed_out: usize,
    pub broke: usize,
    pub refused: usize,
    pub tries: usize,
    /// Tries were left when [`BUDGET`] ran out.
    pub cut: bool,
}

impl Samples {
    /// The times, the loss and the refusals, for the line of the probe.
    pub(super) fn summary(&self) -> String {
        if self.tries == 1 && self.timed_out == 1 {
            return "tried once: a path that does not answer in time is not tried again".into();
        }
        if self.tries > 0 && self.refused == self.tries {
            return format!("refused at each of {} tries", self.tries);
        }
        let mut parts = Vec::new();
        let mut sorted = self.ms.clone();
        sorted.sort_unstable();
        if let Some(best) = sorted.first() {
            parts.push(format!(
                "best {best} ms, median {} ms, p95 {} ms, jitter {} ms",
                rank(&sorted, 50),
                rank(&sorted, 95),
                jitter(&self.ms)
            ));
        }
        let lost = self.timed_out + self.broke;
        let mut loss = format!("loss {lost} of {}", self.tries);
        if lost > 0 {
            let kinds: Vec<String> = [(self.timed_out, "timed out"), (self.broke, "broke")]
                .iter()
                .filter(|(n, _)| *n > 0)
                .map(|(n, what)| format!("{n} {what}"))
                .collect();
            loss.push_str(&format!(" ({} %: {})", lost * 100 / self.tries.max(1), kinds.join(", ")));
        }
        if self.cut {
            loss.push_str(&format!(", the other tries not made within {} s", BUDGET.as_secs()));
        }
        parts.push(loss);
        if self.refused > 0 {
            parts.push(format!("{} of {} refused", self.refused, self.tries));
        }
        parts.join("; ")
    }

    /// The same as numbers, for `doctor --json`.
    pub(super) fn json(&self) -> serde_json::Value {
        let mut sorted = self.ms.clone();
        sorted.sort_unstable();
        let some = !sorted.is_empty();
        serde_json::json!({
            "tries": self.tries,
            "connected": self.ms.len(),
            "best_ms": sorted.first(),
            "median_ms": some.then(|| rank(&sorted, 50)),
            "p95_ms": some.then(|| rank(&sorted, 95)),
            "jitter_ms": some.then(|| jitter(&self.ms)),
            "timed_out": self.timed_out,
            "broke": self.broke,
            "refused": self.refused,
            "ms": self.ms,
        })
    }
}

/// The nearest-rank percentile of times in order.
fn rank(sorted: &[u64], percent: usize) -> u64 {
    let at = (sorted.len() * percent).div_ceil(100).max(1) - 1;
    sorted[at.min(sorted.len() - 1)]
}

/// The median of the differences between one try and the next.
fn jitter(ms: &[u64]) -> u64 {
    let mut steps: Vec<u64> = ms.windows(2).map(|w| w[0].abs_diff(w[1])).collect();
    if steps.is_empty() {
        return 0;
    }
    steps.sort_unstable();
    rank(&steps, 50)
}

/// What the tries of one probe gave: the samples, the first stream that
/// connected, kept open for a check of what comes on it, and the error of
/// the last try that failed.
pub(super) struct Tried {
    pub samples: Samples,
    pub first: Option<TcpStream>,
    pub error: Option<DialError>,
}

/// Run `dial` up to [`TRIES`] times, each with the bound it is given: the
/// first `first_bound`, each later one four times the first try's time,
/// from [`LATER_LEAST`] to `first_bound`. A first try that timed out is the
/// probe's whole answer.
pub(super) async fn sample<F, Fut>(first_bound: Duration, mut dial: F) -> Tried
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = Result<TcpStream, DialError>>,
{
    let mut tried = Tried { samples: Samples::default(), first: None, error: None };
    let began = Instant::now();
    let mut bound = first_bound;
    for i in 0..TRIES {
        if i > 0 {
            if began.elapsed() + SPREAD + bound > BUDGET {
                tried.samples.cut = true;
                break;
            }
            tokio::time::sleep(SPREAD).await;
        }
        let started = Instant::now();
        let outcome = dial(bound).await;
        let took = started.elapsed();
        tried.samples.tries += 1;
        match outcome {
            Ok(stream) => {
                tried.samples.ms.push(took.as_millis() as u64);
                tried.first.get_or_insert(stream);
            }
            Err(e) => {
                match &e {
                    DialError::Timeout { .. } => tried.samples.timed_out += 1,
                    // An answer: the proxy's rules, or a port that says no.
                    DialError::ProxyRefused { .. } => tried.samples.refused += 1,
                    DialError::Connect { detail, .. } if detail.contains("refused") => tried.samples.refused += 1,
                    _ => tried.samples.broke += 1,
                }
                let first_timed_out = i == 0 && matches!(e, DialError::Timeout { .. });
                tried.error = Some(e);
                if first_timed_out {
                    break;
                }
            }
        }
        if i == 0 {
            bound = (took * 4).clamp(LATER_LEAST, first_bound.max(LATER_LEAST));
        }
    }
    tried
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(ms: &[u64], timed_out: usize, broke: usize) -> Samples {
        let tries = ms.len() + timed_out + broke;
        Samples { ms: ms.to_vec(), timed_out, broke, refused: 0, tries, cut: false }
    }

    #[test]
    fn the_floor_the_cost_and_the_tail_of_nine_tries() {
        let s = of(&[30, 10, 20, 40, 50, 60, 70, 80, 200], 0, 0);
        assert_eq!(s.summary(), "best 10 ms, median 50 ms, p95 200 ms, jitter 10 ms; loss 0 of 9");
        let j = s.json();
        let got = (j["best_ms"].as_u64(), j["median_ms"].as_u64(), j["p95_ms"].as_u64(), j["jitter_ms"].as_u64());
        assert_eq!(got, (Some(10), Some(50), Some(200), Some(10)));
        assert_eq!((j["tries"].as_u64(), j["connected"].as_u64()), (Some(9), Some(9)));
    }

    /// One try in three lost reads 33 %, each kind counted apart (#54).
    #[test]
    fn a_lossy_path_shows_its_loss() {
        let s = of(&[100, 100, 100, 100, 100, 100], 2, 1);
        assert!(s.summary().ends_with("loss 3 of 9 (33 %: 2 timed out, 1 broke)"), "{}", s.summary());
        assert_eq!((s.json()["timed_out"].as_u64(), s.json()["broke"].as_u64()), (Some(2), Some(1)));
    }

    #[test]
    fn refusals_are_answers_and_no_loss() {
        let mut s = of(&[40, 41, 42, 43, 44, 45], 0, 0);
        (s.refused, s.tries) = (3, 9);
        assert!(s.summary().ends_with("loss 0 of 9; 3 of 9 refused"), "{}", s.summary());
        let all = Samples { refused: 9, tries: 9, ..Samples::default() };
        assert_eq!(all.summary(), "refused at each of 9 tries");
        assert!(all.json()["best_ms"].is_null() && all.json()["median_ms"].is_null());
    }

    #[test]
    fn a_first_try_that_timed_out_is_said_and_one_try_has_no_jitter() {
        assert!(of(&[], 1, 0).summary().starts_with("tried once"));
        assert_eq!(of(&[42], 0, 0).summary(), "best 42 ms, median 42 ms, p95 42 ms, jitter 0 ms; loss 0 of 1");
        let mut cut = of(&[42, 43], 2, 0);
        cut.cut = true;
        assert!(cut.summary().ends_with("(50 %: 2 timed out), the other tries not made within 10 s"));
    }

    /// The tries, against a dialer that fails as it is told: a first timeout
    /// ends the probe; a later one is a loss among the others.
    #[tokio::test(start_paused = true)]
    async fn the_tries_stop_at_a_first_timeout_and_count_each_later_failure() {
        let timeout = || DialError::Timeout { step: "CONNECT".into(), after: Duration::from_secs(8) };
        let tried = sample(Duration::from_secs(8), |_| async { Err::<TcpStream, _>(timeout()) }).await;
        assert_eq!((tried.samples.tries, tried.samples.timed_out), (1, 1));
        let mut n = 0;
        let tried = sample(Duration::from_secs(8), |_| {
            n += 1;
            let e = match n % 3 {
                0 => timeout(),
                1 => {
                    DialError::ProxyRefused { proxy: "p".into(), target: "t".into(), status: 403, reason: "no".into() }
                }
                _ => DialError::ProxyProtocol { proxy: "p".into(), detail: "closed".into() },
            };
            async move { Err::<TcpStream, _>(e) }
        })
        .await;
        let s = &tried.samples;
        assert_eq!((s.tries, s.refused, s.broke, s.timed_out, s.cut), (9, 3, 3, 3, false), "{s:?}");
        assert!(tried.first.is_none() && tried.error.is_some());
    }

    /// After a first try that failed at once, each later one has 3 s; the
    /// tries that could end after 10 s are not made.
    #[tokio::test(start_paused = true)]
    async fn the_tries_end_within_the_budget() {
        let mut n = 0;
        let tried = sample(Duration::from_secs(8), |bound| {
            n += 1;
            let first = n == 1;
            async move {
                if first {
                    return Err::<TcpStream, _>(DialError::ProxyProtocol { proxy: "p".into(), detail: "reset".into() });
                }
                tokio::time::sleep(bound).await;
                Err(DialError::Timeout { step: "CONNECT".into(), after: bound })
            }
        })
        .await;
        let s = &tried.samples;
        assert_eq!((s.tries, s.broke, s.timed_out, s.cut), (4, 1, 3, true), "{s:?}");
    }
}
