//! HTTP dates (RFC 9110 IMF-fixdate, `Thu, 08 Oct 2026 06:29:49 GMT`), to
//! compare this host's clock with the relay's `Date` header. Certificates
//! and cached tokens are checked against this host's clock.

// The reading and writing of a date and its calendar are podssh-ws's, whose
// TLS errors give this host's clock in the same words (T-345), and whose
// reading the quick tunnel's Retry-After shares (T-401).
pub(super) use podssh_ws::clock::http_date as format_http_date;
pub(super) use podssh_ws::clock::parse_http_date;
use podssh_ws::clock::{civil_from_days, days_from_civil};

/// Days since the Unix epoch for a day written `YYYY-MM-DD`.
pub(super) fn parse_day(text: &str) -> Option<i64> {
    let mut parts = text.split('-').map(|n| n.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 1970 {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// `2026-10-12T08:10:00Z`, RFC 3339 in UTC, for seconds since the Unix epoch:
/// the expiry of a pair.
pub(crate) fn format_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_parses_to_the_days_python_gives() {
        // date(2026, 7, 18) - date(1970, 1, 1) in Python.
        assert_eq!(parse_day("2026-07-18"), Some(20_652));
        assert_eq!(parse_day("1970-01-01"), Some(0));
        for bad in ["", "2026-07", "2026-13-01", "2026-07-18-1", "26-07-18x"] {
            assert_eq!(parse_day(bad), None, "{bad:?}");
        }
    }

    // Expected values from Python's email.utils.parsedate and calendar.timegm.
    #[test]
    fn http_dates_parse_to_the_epoch_seconds_python_gives() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Thu, 08 Oct 2026 06:29:49 GMT"), Some(1_791_440_989));
        assert_eq!(parse_http_date("Tue, 29 Feb 2000 23:59:59 GMT"), Some(951_868_799));
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
    }

    #[test]
    fn anything_but_an_imf_fixdate_is_refused() {
        for bad in [
            "",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:49 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn formatting_is_the_inverse_of_parsing() {
        for secs in [0, 784_111_777, 951_868_799, 1_791_440_989, 4_102_444_800] {
            let text = format_http_date(secs);
            assert_eq!(parse_http_date(&text), Some(secs), "{text}");
        }
        assert_eq!(format_http_date(1_791_440_989), "Thu, 08 Oct 2026 06:29:49 GMT");
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
