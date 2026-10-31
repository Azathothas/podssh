//! The quick tunnel's edge (T-339): the day that the first of cloudflared's
//! roots ends, the roots that `podssh node --quick-tunnel` trusts beside
//! podssh's own for the edge. A binary keeps the roots that it was built
//! with, as it keeps its compiled-in roots (`net.rs`): the day is said, not
//! failed, as podssh works until it comes.

use podssh_relay::quick::edge;

use super::Report;

/// The day that the first root ends, `end`, at `now` (seconds since the
/// epoch).
pub(super) fn roots_end(report: &mut Report<'_>, end: &str, now: i64) {
    let what = format!("cloudflared's roots for the quick tunnel's edge, the first ending on {end}");
    let Some(day) = super::clock::parse_day(end) else {
        report.unknown("quick tunnel roots", format!("{what}, a date that cannot be read"));
        return;
    };
    let days = day - now.div_euclid(86_400);
    let detail = if days < 0 {
        format!("{what}: it has ended, and the edge's chain to it with it; a newer podssh has newer roots")
    } else if days < 365 {
        format!("{what}, in {days} days: a newer podssh has the roots of a newer cloudflared")
    } else {
        format!("{what}, {days} days ahead")
    };
    report.ok("quick tunnel roots", detail);
}

/// [`roots_end`] for the roots built in, now.
pub(super) fn check(report: &mut Report<'_>) {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    roots_end(report, edge::ROOTS_FIRST_END, now);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The planted dates: years ahead, within the last year, and past.
    #[test]
    fn the_day_that_the_first_root_ends_is_said_with_how_near_it_is() {
        let end = "2029-08-15";
        let day = super::super::clock::parse_day(end).unwrap() * 86_400;
        let run = |now: i64| {
            let mut out: Vec<u8> = Vec::new();
            roots_end(&mut Report::new(&mut out), end, now);
            String::from_utf8(out).unwrap()
        };
        let far = run(day - 1000 * 86_400);
        assert!(far.contains("ok") && far.contains("1000 days ahead") && far.contains(end), "{far}");
        let near = run(day - 100 * 86_400);
        assert!(near.contains("in 100 days") && near.contains("a newer podssh"), "{near}");
        let past = run(day + 86_400);
        assert!(past.contains("it has ended"), "{past}");
        let unread = {
            let mut out: Vec<u8> = Vec::new();
            roots_end(&mut Report::new(&mut out), "not a day", day);
            String::from_utf8(out).unwrap()
        };
        assert!(unread.contains("????"), "{unread}");
    }
}
