//! The journal's native protocol as pure functions (T-640): the priority of
//! a level, the bytes of one entry, and the stream that `JOURNAL_STREAM`
//! names.

use podssh_ssh::LogLevel;

/// The priority at which the journal files each line of a unit's stream
/// (`SyslogLevel=`, `info` unless the unit says otherwise): a copy of a
/// line at it, or below it, would say nothing that the stream does not.
pub const STREAM: u8 = 6;

/// The name that each entry is filed under, which `journalctl -t` reads.
pub const IDENTIFIER: &str = "podssh";

/// The syslog priority of `level`: fatal 2 (crit), error 3 (err), quiet and
/// info 6 (info), verbose and the debug levels 7 (debug).
pub fn priority(level: LogLevel) -> u8 {
    match level {
        LogLevel::Fatal => 2,
        LogLevel::Error => 3,
        LogLevel::Quiet | LogLevel::Info => 6,
        LogLevel::Verbose | LogLevel::Debug1 | LogLevel::Debug2 | LogLevel::Debug3 => 7,
    }
}

/// One entry: `PRIORITY` and `SYSLOG_IDENTIFIER` first, `MESSAGE` last. A
/// value with a line break takes the binary form (its name, a line break,
/// its length in 8 bytes little-endian, the value, a line break), so that a
/// message of many lines stays one entry.
pub fn entry(priority: u8, message: &str) -> Vec<u8> {
    // The two fields whose values never hold a line break, in one line each.
    let mut out = format!("PRIORITY={priority}\nSYSLOG_IDENTIFIER={IDENTIFIER}\n").into_bytes();
    field(&mut out, "MESSAGE", message.as_bytes());
    out
}

fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    if value.contains(&b'\n') {
        out.push(b'\n');
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    } else {
        out.push(b'=');
    }
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// The device and inode of `JOURNAL_STREAM`, which systemd writes in
/// decimal as `DEVICE:INODE`; `None` for any other text.
pub fn stream_of(value: &str) -> Option<(u64, u64)> {
    let (device, inode) = value.split_once(':')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(device) || !digits(inode) {
        return None;
    }
    Some((device.parse().ok()?, inode.parse().ok()?))
}
