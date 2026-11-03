//! The retries of the API (anomalyco/opentunnel:docs/protocol.md at v0.6.1,
//! "Retries and errors"): the hosted API sits behind Cloudflare, so a
//! request can fail before it reaches the server. Retry `n` (from 0) waits
//! a random time between half of and all of `min(250 ms × 2ⁿ, 8 s)`, or the
//! `Retry-After` seconds, at most 8 s, for at most 6 retries. A request that
//! may be repeated (a read, the bind of the CSR that the tunnel has) is
//! retried on any 429 or 5xx; one that must not be (the making of a tunnel)
//! only where it cannot have arrived. One change of podssh's: a 429 or a 503
//! whose `Retry-After` is longer than the 8 s that a retry waits is said at
//! once, with its wait, as no retry within the bound would pass.

use std::time::Duration;

use rand::RngExt;

/// The first wait, the longest, and the retries.
pub const BASE: Duration = Duration::from_millis(250);
pub const MAX: Duration = Duration::from_secs(8);
pub const RETRIES: u32 = 6;

/// How safely a request may be sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    /// Twice is once: retried on each passing failure.
    Idempotent,
    /// Retried only where it cannot have reached the API.
    Once,
}

/// Whether a response of `status` is a passing failure, worth a retry.
pub fn retryable(status: u16, repeat: Repeat) -> bool {
    match repeat {
        Repeat::Idempotent => status == 429 || (500..=599).contains(&status),
        // Rate limited, the API's own "unavailable", or Cloudflare did not
        // reach the server at all.
        Repeat::Once => matches!(status, 429 | 503 | 521 | 522 | 523 | 525),
    }
}

/// The seconds of a `Retry-After`, when it is a number of them.
pub fn retry_after_secs(value: Option<&str>) -> Option<u64> {
    value.and_then(|text| text.trim().parse::<u64>().ok())
}

/// The bounds of the wait before retry `attempt`, from 0.
pub fn bounds(attempt: u32, retry_after: Option<&str>) -> (Duration, Duration) {
    if let Some(secs) = retry_after_secs(retry_after) {
        let wait = Duration::from_secs(secs).min(MAX);
        return (wait, wait);
    }
    let wait = BASE.saturating_mul(1u32 << attempt.min(16)).min(MAX);
    (wait / 2, wait)
}

/// The wait before retry `attempt`: random within its [`bounds`].
pub fn wait(attempt: u32, retry_after: Option<&str>) -> Duration {
    let (low, high) = bounds(attempt, retry_after);
    if low >= high {
        return low;
    }
    let ms = rand::rng().random_range(low.as_millis() as u64..=high.as_millis() as u64);
    Duration::from_millis(ms)
}

/// Whether a refusal's `Retry-After` is longer than a retry waits: said at
/// once.
pub fn too_long(status: u16, retry_after: Option<&str>) -> bool {
    matches!(status, 429 | 503) && retry_after_secs(retry_after).is_some_and(|secs| Duration::from_secs(secs) > MAX)
}

/// What Cloudflare, in front of the hosted API, means by its own 52x.
pub fn cloudflare(status: u16) -> Option<&'static str> {
    Some(match status {
        520 => "the server returned an unknown error",
        521 => "the server refused the connection",
        522 => "the connection to the server timed out",
        523 => "the server is unreachable",
        524 => "the server did not answer in time",
        525 => "the SSL handshake with the server failed",
        526 => "the server's certificate is invalid",
        527 => "the connection to the server failed",
        _ => return None,
    })
}

/// The words of a response that failed with no error of the API's: the
/// status and Cloudflare's meaning of it, or the body's first 200
/// characters on one line.
pub fn status_words(status: u16, body: &str) -> String {
    if let Some(reason) = cloudflare(status) {
        return format!("Cloudflare {status}: {reason}");
    }
    let body = podssh_ws::text::one_line(body.trim());
    if body.is_empty() {
        format!("HTTP {status}")
    } else {
        body.chars().take(200).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `anomalyco/opentunnel:spec/vectors/api-retry.json` at v0.6.1.
    #[test]
    fn the_waits_follow_the_protocol_s_vectors() {
        let ms = |(low, high): (Duration, Duration)| (low.as_millis() as u64, high.as_millis() as u64);
        assert_eq!(ms(bounds(0, None)), (125, 250));
        assert_eq!(ms(bounds(1, None)), (250, 500));
        assert_eq!(ms(bounds(4, None)), (2000, 4000));
        assert_eq!(ms(bounds(5, None)), (4000, 8000));
        assert_eq!(ms(bounds(9, None)), (4000, 8000));
        assert_eq!(ms(bounds(0, Some("3"))), (3000, 3000));
        assert_eq!(ms(bounds(2, Some("120"))), (8000, 8000));
        assert_eq!(ms(bounds(1, Some("soon"))), (250, 500));
        for attempt in 0..10 {
            let (low, high) = bounds(attempt, None);
            let wait = wait(attempt, None);
            assert!(low <= wait && wait <= high, "{attempt}: {wait:?}");
        }
    }

    /// The statuses of the same vectors: retried for a request that may be
    /// repeated (`idempotent`), and for one that may not (`once`).
    #[test]
    fn the_statuses_retried_follow_the_protocol_s_vectors() {
        #[rustfmt::skip]
        let table: &[(u16, bool, bool)] = &[
            (200, false, false), (400, false, false), (401, false, false), (404, false, false),
            (409, false, false), (429, true, true), (500, true, false), (502, true, false),
            (503, true, true), (504, true, false), (520, true, false), (521, true, true),
            (522, true, true), (523, true, true), (524, true, false), (525, true, true),
            (526, true, false), (527, true, false),
        ];
        for &(status, idempotent, once) in table {
            assert_eq!(retryable(status, Repeat::Idempotent), idempotent, "{status}");
            assert_eq!(retryable(status, Repeat::Once), once, "{status}");
        }
    }

    #[test]
    fn a_failure_with_no_error_of_the_api_s_says_its_status_or_its_body() {
        assert_eq!(status_words(525, ""), "Cloudflare 525: the SSL handshake with the server failed");
        assert_eq!(status_words(502, ""), "HTTP 502");
        assert_eq!(status_words(503, "  upstream unavailable\n"), "upstream unavailable");
        assert!(too_long(429, Some("1800")) && too_long(503, Some("30")));
        assert!(!too_long(429, Some("3")) && !too_long(500, Some("1800")) && !too_long(429, None));
    }
}
