//! The long line of `ls -l` for a file on the server, as OpenSSH's sftp makes
//! one (`ls_file` of `sftp-common.c`, with `strmode` and `fmt_scaled` of its
//! `openbsd-compat`; the same from OpenSSH 10.2p1 to 10.6p1, T-471): the mode
//! with the type letter of each kind and the set-id and sticky bits, `?` for
//! the link count (SFTP version 3 carries none), the owner and the group by
//! name or by number, each 8 wide at least, the size 8 wide, the time of
//! change in the local zone, then the name. A script that reads OpenSSH's
//! columns reads podssh's the same.

use chrono::{Local, TimeZone};

use super::FileAttributes;

/// Half of a year of 365 days, in seconds: a time of change within it, and
/// not in the future, shows the hour; else the year, as `ls` shows them.
pub const HALF_YEAR: i64 = 365 * 24 * 60 * 60 / 2;

/// The type letter and the nine bits of `mode`, as `strmode` writes them:
/// `s` or `S` for a set-id bit with or without the execute bit, `t` or `T`
/// for the sticky bit. A kind that `strmode` does not know is `?`.
pub fn mode_text(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o100_000 => '-',
        0o120_000 => 'l',
        0o140_000 => 's',
        0o010_000 => 'p',
        _ => '?',
    };
    let bit = |b: u32, c: char| if mode & b != 0 { c } else { '-' };
    // The execute bit and the special bit over it, in the one column.
    let exec = |x: u32, special: u32, both: char, alone: char| match (mode & x != 0, mode & special != 0) {
        (false, false) => '-',
        (true, false) => 'x',
        (false, true) => alone,
        (true, true) => both,
    };
    [
        kind,
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        exec(0o100, 0o4000, 's', 'S'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        exec(0o010, 0o2000, 's', 'S'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        exec(0o001, 0o1000, 't', 'T'),
    ]
    .iter()
    .collect()
}

/// A size as `fmt_scaled` writes it for `ls -lh`: bytes below 1024 (`512B`),
/// else one decimal in the unit of 1024 that keeps the number below 1024
/// (`1.5K`, `5.0M`), with no decimal from 100 on (`100K`). A size that a
/// `long long` cannot hold is `error`, as OpenSSH's own (`sftp-common.c`
/// 1.38, after 10.6p1) writes it; the releases before printed what their
/// buffer held.
pub fn scaled(size: u64) -> String {
    const UNITS: &[u8] = b"BKMGTPE";
    const FACTORS: [u64; 7] = [1, 1 << 10, 1 << 20, 1 << 30, 1 << 40, 1 << 50, 1 << 60];
    if size > i64::MAX as u64 {
        return "error".to_string();
    }
    let (mut unit, mut number, mut fract) = (0, size, 0);
    for (i, factor) in FACTORS.iter().enumerate() {
        if size / 1024 < *factor {
            unit = i;
            number = size / factor;
            // The remainder, in the unit below.
            fract = if i == 0 { 0 } else { size % factor / FACTORS[i - 1] };
            break;
        }
    }
    // Tenths, rounded; ten tenths are one more.
    fract = (10 * fract + 512) / 1024;
    if fract >= 10 {
        number += 1;
        fract = 0;
    }
    let letter = UNITS[unit] as char;
    if number == 0 {
        "0B".to_string()
    } else if unit == 0 || number >= 100 {
        if fract >= 5 {
            number += 1;
        }
        format!("{number}{letter}")
    } else {
        format!("{number}.{fract}{letter}")
    }
}

/// `text` and spaces after it, to `width` bytes, as printf's `%-*s` pads.
fn padded(text: &str, width: usize) -> String {
    format!("{text}{}", " ".repeat(width.saturating_sub(text.len())))
}

/// The long line of `name` in the local zone, at `now` (seconds since 1970).
pub fn long_line(
    name: &str,
    attrs: &FileAttributes,
    si: bool,
    user: Option<&str>,
    group: Option<&str>,
    now: i64,
) -> String {
    long_line_in(&Local, name, attrs, si, user, group, now)
}

/// [`long_line`] in the zone `zone`: the tests use UTC.
pub fn long_line_in<Z: TimeZone>(
    zone: &Z,
    name: &str,
    attrs: &FileAttributes,
    si: bool,
    user: Option<&str>,
    group: Option<&str>,
    now: i64,
) -> String
where
    Z::Offset: std::fmt::Display,
{
    // A field that the server did not send is 0, as `attrib_to_stat` leaves it.
    let uid = attrs.uid.unwrap_or(0).to_string();
    let gid = attrs.gid.unwrap_or(0).to_string();
    let user = user.unwrap_or(&uid);
    let group = group.unwrap_or(&gid);
    let mtime = i64::from(attrs.mtime.unwrap_or(0));
    let time = match zone.timestamp_opt(mtime, 0).single() {
        Some(at) if now - HALF_YEAR < mtime && now >= mtime => at.format("%b %e %H:%M").to_string(),
        Some(at) => at.format("%b %e  %Y").to_string(),
        None => String::new(),
    };
    let size = attrs.size.unwrap_or(0);
    let size = if si { scaled(size) } else { size.to_string() };
    let mode = mode_text(attrs.permissions.unwrap_or(0));
    let user = padded(user, user.len().max(8));
    let group = padded(group, group.len().max(8));
    // `%s %3s`: strmode's eleventh character is a space, where an ACL would
    // be marked, then the link count `?`, three wide.
    format!("{mode}    ? {user} {group} {size:>8} {time} {name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// 2026-11-02 12:00:00 UTC.
    const NOW: i64 = 1_793_620_800;

    fn attrs(mode: u32, size: u64, mtime: i64) -> FileAttributes {
        FileAttributes {
            size: Some(size),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(mode),
            mtime: Some(mtime as u32),
            atime: Some(mtime as u32),
            ..FileAttributes::default()
        }
    }

    fn line(name: &str, a: &FileAttributes, si: bool, user: Option<&str>, group: Option<&str>) -> String {
        long_line_in(&Utc, name, a, si, user, group, NOW)
    }

    #[test]
    fn a_file_and_a_directory_have_openssh_s_columns() {
        // A time of the last six months shows the hour.
        let file = attrs(0o100_644, 42, NOW - 3600);
        assert_eq!(
            line("notes.txt", &file, false, Some("podtest"), Some("podtest")),
            "-rw-r--r--    ? podtest  podtest        42 Nov  2 11:00 notes.txt"
        );
        let dir = attrs(0o040_755, 4096, NOW - 86_400 * 30);
        assert_eq!(
            line("sub", &dir, false, Some("root"), Some("wheel")),
            "drwxr-xr-x    ? root     wheel        4096 Oct  3 12:00 sub"
        );
        // Seven columns, the time of three words: the link count is the second.
        let text = line("f", &file, false, None, None);
        let words: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(words.len(), 9, "{words:?}");
        assert_eq!((words[1], words[2], words[3]), ("?", "1000", "100"), "numbers with no names");
    }

    #[test]
    fn each_kind_has_its_letter_and_the_special_bits_show() {
        assert_eq!(mode_text(0o120_777), "lrwxrwxrwx");
        assert_eq!(mode_text(0o010_644), "prw-r--r--");
        assert_eq!(mode_text(0o140_755), "srwxr-xr-x");
        assert_eq!(mode_text(0o020_620), "crw--w----");
        assert_eq!(mode_text(0o060_660), "brw-rw----");
        assert_eq!(mode_text(0o104_755), "-rwsr-xr-x");
        assert_eq!(mode_text(0o104_644), "-rwSr--r--");
        assert_eq!(mode_text(0o102_755), "-rwxr-sr-x");
        assert_eq!(mode_text(0o102_745), "-rwxr-Sr-x");
        assert_eq!(mode_text(0o041_777), "drwxrwxrwt");
        assert_eq!(mode_text(0o041_776), "drwxrwxrwT");
        // No mode sent: an unknown kind and no bit.
        assert_eq!(mode_text(0), "?---------");
    }

    #[test]
    fn an_older_time_and_a_future_one_show_the_year() {
        let old = line("old", &attrs(0o100_600, 7, NOW - HALF_YEAR - 1), false, None, None);
        assert!(old.ends_with(" May  3  2026 old"), "{old}");
        let future = line("new", &attrs(0o100_600, 7, NOW + 60), false, None, None);
        assert!(future.ends_with(" Nov  2  2026 new"), "{future}");
        // Just within the half year: the hour.
        let within = line("w", &attrs(0o100_600, 7, NOW - HALF_YEAR + 1), false, None, None);
        assert!(within.ends_with(" May  4 00:00 w"), "{within}");
    }

    #[test]
    fn a_long_owner_widens_its_column_and_a_short_one_is_padded_to_eight() {
        let a = attrs(0o100_644, 1, NOW);
        assert_eq!(
            line("f", &a, false, Some("averylongowner"), Some("g")),
            "-rw-r--r--    ? averylongowner g               1 Nov  2 12:00 f"
        );
        // The width counts bytes, as printf counts them.
        assert!(line("f", &a, false, Some("é"), Some("g")).contains("? é       g "));
    }

    #[test]
    fn h_scales_the_size_as_fmt_scaled_does() {
        for (size, want) in [
            (0, "0B"),
            (1, "1B"),
            (512, "512B"),
            (1023, "1023B"),
            (1024, "1.0K"),
            (1536, "1.5K"),
            (102_400, "100K"),
            (5 << 20, "5.0M"),
            (1_048_575, "1024K"),
            ((1 << 30) + (1 << 29), "1.5G"),
            (i64::MAX as u64, "8.0E"),
            (u64::MAX, "error"),
        ] {
            assert_eq!(scaled(size), want, "{size}");
        }
        let a = attrs(0o100_644, 1536, NOW);
        assert_eq!(
            line("f", &a, true, Some("u"), Some("g")),
            "-rw-r--r--    ? u        g            1.5K Nov  2 12:00 f"
        );
    }
}
