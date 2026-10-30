//! The key of the emergency stop that the user chooses (T-322): `--stop-key
//! ^X`. On Unix the terminal's QUIT character becomes that key for the run,
//! so that the terminal still raises SIGQUIT at it and still drops the line
//! that is half typed ([`super::keys`] is unchanged); the old character
//! comes back on each way out. dtach and abduco take Ctrl-\ for their own
//! detach, which is why the key can move. On Windows the stop is
//! Ctrl-Break, which the console gives as an event and no setting changes.

/// The stop key of a run: the name that the banner and `:help` say, and on
/// Unix the character that the terminal takes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopKey {
    pub name: String,
    /// Read where the terminal's QUIT character is set, on Unix alone.
    #[cfg_attr(windows, allow(dead_code))]
    pub quit: Option<u8>,
}

/// The default key of each system.
pub const DEFAULT: &str = if cfg!(windows) { "Ctrl-Break" } else { "Ctrl-\\" };

/// The control characters that a terminal keeps for itself by default, as
/// POSIX gives them: a stop there would take the key from its work.
const KEPT: [(u8, &str); 7] = [
    (0x03, "INTR (Ctrl-C)"),
    (0x04, "EOF (Ctrl-D)"),
    (0x1a, "SUSP (Ctrl-Z)"),
    (0x7f, "ERASE (Ctrl-?)"),
    (0x08, "ERASE (Ctrl-H)"),
    (0x15, "KILL (Ctrl-U)"),
    (0x0a, "the end of a line (Ctrl-J)"),
];

impl StopKey {
    /// The key of `--stop-key`, or the default; a refusal (64) names why.
    pub fn from_arg(given: Option<&str>) -> Result<StopKey, String> {
        let Some(text) = given else { return Ok(StopKey { name: DEFAULT.into(), quit: None }) };
        if cfg!(windows) {
            return Err(format!(
                "--stop-key {text}: on Windows the stop is Ctrl-Break, which the console gives as a signal; \
                 no other key can stop the broadcast at once"
            ));
        }
        let byte = control_char(text).ok_or_else(|| {
            format!("--stop-key {text}: give one control key, as ^X or Ctrl-X (the letters, @, [, \\, ], ^, _ or ?)")
        })?;
        if byte == b'\r' {
            return Err(format!("--stop-key {text}: Ctrl-M is the end of a line"));
        }
        if let Some((_, what)) = KEPT.iter().find(|(c, _)| *c == byte) {
            return Err(format!("--stop-key {text}: the terminal keeps that key for {what}"));
        }
        Ok(StopKey { name: format!("Ctrl-{}", shown(byte)), quit: Some(byte) })
    }
}

/// `^X`, `Ctrl-X` or `C-x` as its control character: the letter's code less
/// 64, and `^?` for DEL.
fn control_char(text: &str) -> Option<u8> {
    let rest = text
        .strip_prefix('^')
        .or_else(|| text.get(..5).filter(|p| p.eq_ignore_ascii_case("ctrl-")).map(|_| &text[5..]))
        .or_else(|| text.get(..2).filter(|p| p.eq_ignore_ascii_case("c-")).map(|_| &text[2..]))?;
    let [c] = rest.as_bytes() else { return None };
    match c.to_ascii_uppercase() {
        b'?' => Some(0x7f),
        c @ b'@'..=b'_' => Some(c - b'@'),
        _ => None,
    }
}

/// The key of a control character, as the banner says it.
fn shown(byte: u8) -> char {
    if byte == 0x7f {
        '?'
    } else {
        (byte + b'@') as char
    }
}

/// The terminal's QUIT character, set to the stop key for the run and put
/// back when this drops. `None` when there is nothing to change: the default
/// key, or stdin that is not a terminal, where the stop is `kill -QUIT`.
#[cfg(unix)]
pub struct QuitGuard {
    old: libc::termios,
}

#[cfg(unix)]
impl QuitGuard {
    /// Set the QUIT character of the terminal on stdin; a key that the
    /// terminal uses now for another of its characters is refused (64).
    pub fn set(key: &StopKey) -> Result<Option<QuitGuard>, String> {
        let Some(byte) = key.quit else { return Ok(None) };
        let mut now = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr writes the termios of fd 0 into the buffer when
        // it returns 0, and only then is the buffer read.
        if unsafe { libc::tcgetattr(0, now.as_mut_ptr()) } != 0 {
            return Ok(None);
        }
        // SAFETY: tcgetattr returned 0, so it filled the struct.
        let old = unsafe { now.assume_init() };
        let used = [
            (libc::VINTR, "INTR"),
            (libc::VEOF, "EOF"),
            (libc::VSUSP, "SUSP"),
            (libc::VERASE, "ERASE"),
            (libc::VKILL, "KILL"),
            (libc::VEOL, "EOL"),
            (libc::VEOL2, "EOL2"),
        ];
        if let Some((_, what)) = used.iter().find(|(i, _)| old.c_cc[*i] == byte) {
            return Err(format!("--stop-key {}: this terminal uses that key for {what}", key.name));
        }
        let mut new = old;
        new.c_cc[libc::VQUIT] = byte;
        // SAFETY: a termios that tcgetattr gave, with one character changed.
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &new) } != 0 {
            return Err(format!(
                "--stop-key {}: the terminal refused it: {}",
                key.name,
                std::io::Error::last_os_error()
            ));
        }
        Ok(Some(QuitGuard { old }))
    }
}

#[cfg(unix)]
impl Drop for QuitGuard {
    fn drop(&mut self) {
        // SAFETY: the termios that tcgetattr gave at the start of the run.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.old) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_key_is_one_control_key_the_terminal_does_not_keep() {
        assert_eq!(StopKey::from_arg(None).unwrap(), StopKey { name: DEFAULT.into(), quit: None });
        if cfg!(windows) {
            assert!(StopKey::from_arg(Some("^X")).unwrap_err().contains("Ctrl-Break"));
            return;
        }
        for (given, byte, name) in
            [("^X", 0x18, "Ctrl-X"), ("ctrl-x", 0x18, "Ctrl-X"), ("C-]", 0x1d, "Ctrl-]"), ("^\\", 0x1c, "Ctrl-\\")]
        {
            assert_eq!(StopKey::from_arg(Some(given)).unwrap(), StopKey { name: name.into(), quit: Some(byte) });
        }
        for (given, why) in [
            ("^C", "INTR"),
            ("^d", "EOF"),
            ("Ctrl-Z", "SUSP"),
            ("^?", "ERASE"),
            ("^U", "KILL"),
            ("^J", "end of a line"),
            ("^M", "end of a line"),
            ("x", "one control key"),
            ("^XY", "one control key"),
            ("^1", "one control key"),
            ("Ctrl-", "one control key"),
        ] {
            let refused = StopKey::from_arg(Some(given)).unwrap_err();
            assert!(refused.contains(why), "{given}: {refused}");
        }
    }
}
