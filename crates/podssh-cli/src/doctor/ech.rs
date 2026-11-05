//! The line `ech` (T-642), in the section relay, after `http2`: what
//! Encrypted Client Hello did for the host that `http2` names, at the
//! connection of its `/health` above, from what the process kept of it and
//! with no connection of its own: off, as by default; the name went sealed,
//! and whether with the server's retry configs; or why its hello named it
//! (no list, a read of its record that failed, a refusal, or the 5 minutes
//! after one).

use podssh_ws::ech::{self, Mode, Outcome};
use podssh_ws::Verdict;

use super::Report;

/// The line of the section relay, for `host`.
pub(super) fn check(report: &mut Report<'_>, host: &str) {
    report.line("ech", verdict(host, ech::mode(), ech::outcome(host)));
}

/// The verdict: `ok`, a fact, whatever ECH did, as a hello that names the
/// host reaches it as before; `????` where no connection to the host was
/// made; `FAIL` where `strict` sent no plain hello, so that no session
/// reaches the host.
pub(super) fn verdict(host: &str, mode: Mode, outcome: Option<Outcome>) -> Verdict {
    if mode == Mode::Off {
        return Verdict::Ok {
            detail: "off: each hello names its host; PODSSH_ECH=yes, or ECH yes in the settings file, seals a name \
                     that publishes a list in its HTTPS record"
                .into(),
        };
    }
    match outcome {
        None => Verdict::Unknown { why: format!("not measured: no connection to {host} was made") },
        Some(outcome @ Outcome::Strict(_)) => Verdict::Failed { detail: format!("{host}: {}", outcome.words()) },
        Some(outcome) => Verdict::Ok { detail: format!("{host}: {}", outcome.words()) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off is a fact that says how to ask; each outcome of a connection is a
    /// fact; none is not measured; `strict` with no plain hello fails.
    #[test]
    fn each_outcome_is_its_verdict() {
        let off = verdict("r.test", Mode::Off, Some(Outcome::Sealed { retried: false }));
        assert!(
            matches!(&off, Verdict::Ok { detail } if detail.starts_with("off: ") && detail.contains("PODSSH_ECH=yes"))
        );
        let sealed = verdict("r.test", Mode::On, Some(Outcome::Sealed { retried: true }));
        assert!(matches!(&sealed, Verdict::Ok { detail } if detail.starts_with("r.test: the name went sealed")));
        let plain = verdict("r.test", Mode::On, Some(Outcome::NotPublished));
        assert!(matches!(&plain, Verdict::Ok { detail } if detail.contains("publishes no list")), "{plain:?}");
        let unmeasured = verdict("r.test", Mode::On, None);
        assert!(matches!(&unmeasured, Verdict::Unknown { why } if why.contains("no connection to r.test")));
        let strict = verdict("r.test", Mode::Strict, Some(Outcome::Strict("r.test: a reset".into())));
        assert!(matches!(&strict, Verdict::Failed { detail } if detail.contains("PODSSH_ECH=strict")), "{strict:?}");
    }
}
