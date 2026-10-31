//! This host's clock, in the words of a TLS failure (T-345). A certificate
//! that is expired, or not valid yet, at each host usually means that this
//! host's clock is wrong: certificates are checked against it, so the hint
//! gives its reading.

use std::time::{SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// The words for a certificate that this host's clock refused, with the
/// clock's reading `now`.
pub fn hint(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    format!("certificates are checked against this host's clock, which reads {}", http_date(secs))
}

/// An IMF-fixdate (RFC 9110, `Thu, 08 Oct 2026 06:29:49 GMT`) for seconds
/// since the Unix epoch.
pub fn http_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {d:02} {} {y} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The year, month and day of a count of days since 1970-01-01, proleptic
/// Gregorian (Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // The values of Python's email.utils.formatdate(usegmt=True).
    #[test]
    fn a_date_is_written_as_python_writes_it() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_791_440_989), "Thu, 08 Oct 2026 06:29:49 GMT");
        assert_eq!(http_date(951_868_799), "Tue, 29 Feb 2000 23:59:59 GMT");
    }

    #[test]
    fn the_hint_gives_the_clock_that_it_was_given() {
        let said = hint(UNIX_EPOCH + Duration::from_secs(1_791_440_989));
        assert_eq!(
            said,
            "certificates are checked against this host's clock, which reads Thu, 08 Oct 2026 06:29:49 GMT"
        );
    }
}
