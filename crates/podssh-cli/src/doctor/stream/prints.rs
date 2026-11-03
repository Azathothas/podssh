//! The fingerprints of the probes (T-325): the documented defaults of the
//! products that often stand on a path, as `relay-facts.toml` holds the
//! facts of the relay's contract. A line names a product only as "looks
//! like": a default is a setting that its owner may change, and two
//! products can share one. Read from each product's documentation of its
//! default, 2026-11-03; none of them measured here.

use std::time::Duration;

/// What a fingerprint is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum What {
    /// A stream or a request that goes quiet is ended after this many ms.
    Quiet,
    /// A body of more than this many bytes is refused.
    Cap,
}

/// One product's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Print {
    pub(super) what: What,
    pub(super) value: u64,
    /// The status that it answers, when it can still answer one.
    pub(super) status: Option<u16>,
    /// The product and its setting, as a line names them.
    pub(super) words: &'static str,
}

/// The table, by what it is of and its value.
pub(super) const PRINTS: &[Print] = &[
    Print {
        what: What::Quiet,
        value: 30_000,
        status: None,
        words: "a Google Cloud load balancer's backend service timeout (30 s by default)",
    },
    Print {
        what: What::Quiet,
        value: 30_000,
        status: Some(503),
        words: "Heroku's router, which ends a request with no first byte of an answer in 30 s (H12)",
    },
    Print {
        what: What::Quiet,
        value: 60_000,
        status: Some(504),
        words: "nginx's proxy_read_timeout (60 s by default)",
    },
    Print {
        what: What::Quiet,
        value: 60_000,
        status: None,
        words: "an AWS Application Load Balancer's idle timeout (60 s by default)",
    },
    Print {
        what: What::Quiet,
        value: 125_000,
        status: Some(524),
        words: "Cloudflare's proxy read timeout (125 s by default, its 524)",
    },
    Print {
        what: What::Cap,
        value: 1 << 20,
        status: Some(413),
        words: "nginx's client_max_body_size (1 MiB by default)",
    },
];

/// The prints of a quiet stream that ended `after` its last bytes, with
/// `status` when the path could still answer one: the time within 2 s or
/// 5 %, whichever is more, and the status when both have one.
pub(super) fn quiet(after: Duration, status: Option<u16>) -> Vec<&'static Print> {
    let ms = after.as_millis() as u64;
    let near = |value: u64| ms.abs_diff(value) <= (value / 20).max(2_000);
    let same = |print: &Print| match (print.status, status) {
        (Some(theirs), Some(seen)) => theirs == seen,
        _ => true,
    };
    PRINTS.iter().filter(|p| p.what == What::Quiet && near(p.value) && same(p)).collect()
}

/// The prints of a cap that took `passed` bytes (none: no body passed) and
/// refused `refused` with `status`: a cap between the two.
pub(super) fn cap(passed: Option<u64>, refused: u64, status: u16) -> Vec<&'static Print> {
    let passed = passed.unwrap_or(0);
    let within = |p: &&Print| passed <= p.value && p.value < refused;
    let same = |p: &&Print| p.status.is_none_or(|theirs| theirs == status);
    PRINTS.iter().filter(|p| p.what == What::Cap).filter(within).filter(same).collect()
}

/// `; looks like A, or B` for the prints that match, or nothing.
pub(super) fn looks_like(prints: &[&Print]) -> String {
    match prints.is_empty() {
        true => String::new(),
        false => format!("; looks like {}", prints.iter().map(|p| p.words).collect::<Vec<_>>().join(", or ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cut near a default names it, and a status tells two of one time
    /// apart; a cut far from each names none.
    #[test]
    fn a_time_near_a_default_names_its_product() {
        let words = |p: Vec<&Print>| p.iter().map(|p| p.words).collect::<Vec<_>>();
        let nginx = words(quiet(Duration::from_millis(60_400), Some(504)));
        assert_eq!(nginx, ["nginx's proxy_read_timeout (60 s by default)", PRINTS[3].words]);
        let cut = words(quiet(Duration::from_millis(59_000), None));
        assert_eq!(cut.len(), 2, "both of 60 s, as a cut after the head has no status: {cut:?}");
        assert_eq!(words(quiet(Duration::from_secs(125), Some(524))), [PRINTS[4].words]);
        assert!(quiet(Duration::from_secs(3), None).is_empty());
        assert!(quiet(Duration::from_secs(90), None).is_empty());
        assert!(looks_like(&quiet(Duration::from_secs(60), Some(504))).starts_with("; looks like nginx's"));
        assert_eq!(looks_like(&[]), "");
    }

    /// nginx's 1 MiB is a cap that took 1 MiB and refused 2 MiB, not one
    /// that refused 1 MiB itself.
    #[test]
    fn a_cap_names_a_default_between_what_passed_and_what_was_refused() {
        assert_eq!(cap(Some(1 << 20), 2 << 20, 413).len(), 1);
        assert!(cap(Some(512 << 10), 1 << 20, 413).is_empty(), "1 MiB itself refused: not nginx's default");
        assert!(cap(Some(1 << 20), 2 << 20, 400).is_empty(), "another status");
        assert!(cap(None, 64 << 10, 413).is_empty());
        for print in PRINTS {
            assert!(print.value > 0 && !print.words.is_empty(), "{print:?}");
        }
    }
}
