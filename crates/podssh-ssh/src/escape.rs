//! The escape character of an interactive session (ssh(1), ESCAPE
//! CHARACTERS): recognised only at the start of a line, and only when a pty
//! was allocated. podssh implements `~.` (disconnect), `~R` (re-key), `~?`
//! (help) and `~~` (a literal `~`); any other character after `~` is sent as
//! typed, with the `~`.

/// Something the user asked for with an escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Disconnect,
    Rekey,
    Help,
}

/// The escape state across reads from stdin.
#[derive(Debug, Clone)]
pub struct Escapes {
    escape: u8,
    at_line_start: bool,
    pending: bool,
}

impl Escapes {
    pub fn new(escape: u8) -> Self {
        Escapes { escape, at_line_start: true, pending: false }
    }

    /// Filter one read: returns the bytes to send and the commands found, in
    /// order. A `~.` ends the input there; nothing after it is sent.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<Command>) {
        let mut out = Vec::with_capacity(input.len());
        let mut commands = Vec::new();
        for &b in input {
            if self.pending {
                self.pending = false;
                match b {
                    b'.' => {
                        commands.push(Command::Disconnect);
                        return (out, commands);
                    }
                    b'R' => {
                        commands.push(Command::Rekey);
                        continue;
                    }
                    b'?' => {
                        commands.push(Command::Help);
                        continue;
                    }
                    b if b == self.escape => {
                        out.push(b);
                        self.at_line_start = false;
                        continue;
                    }
                    other => {
                        out.push(self.escape);
                        out.push(other);
                        self.at_line_start = other == b'\r' || other == b'\n';
                        continue;
                    }
                }
            }
            if self.at_line_start && b == self.escape {
                self.pending = true;
                continue;
            }
            out.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        (out, commands)
    }

    /// The text `~?` prints.
    pub fn help(&self) -> String {
        let e = self.escape as char;
        format!(
            "Supported escape sequences:\n {e}.   - terminate connection\n {e}R   - request rekey\n \
             {e}?   - this message\n {e}{e}   - send the escape character by typing it twice\n\
             (Note that escapes are only recognized immediately after newline.)\n"
        )
    }
}

/// `EscapeChar`: `none`, a single character, or `^X` for a control character.
pub fn parse_escape_char(value: &str) -> Option<Option<u8>> {
    if value.eq_ignore_ascii_case("none") {
        return Some(None);
    }
    let bytes = value.as_bytes();
    match bytes {
        [c] if c.is_ascii() => Some(Some(*c)),
        [b'^', c] if c.is_ascii_alphabetic() || b"@[\\]^_".contains(c) => Some(Some(c.to_ascii_uppercase() & 0x1f)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_dot_at_line_start_disconnects_and_drops_the_rest() {
        let mut e = Escapes::new(b'~');
        let (out, cmds) = e.feed(b"~.ls\r");
        assert!(out.is_empty());
        assert_eq!(cmds, vec![Command::Disconnect]);
    }

    #[test]
    fn tilde_is_only_special_after_a_newline() {
        let mut e = Escapes::new(b'~');
        let (out, cmds) = e.feed(b"echo ~.\r");
        assert_eq!(out, b"echo ~.\r");
        assert!(cmds.is_empty());
        let (out, cmds) = e.feed(b"~.");
        assert!(out.is_empty());
        assert_eq!(cmds, vec![Command::Disconnect]);
    }

    #[test]
    fn a_doubled_tilde_sends_one_and_other_characters_pass_with_it() {
        let mut e = Escapes::new(b'~');
        assert_eq!(e.feed(b"~~x").0, b"~x");
        let mut e = Escapes::new(b'~');
        assert_eq!(e.feed(b"~x").0, b"~x");
        // Split across reads: the pending tilde waits for the next byte.
        let mut e = Escapes::new(b'~');
        assert_eq!(e.feed(b"~").0, b"");
        assert_eq!(e.feed(b"/tmp").0, b"~/tmp");
    }

    #[test]
    fn help_and_rekey_are_commands_not_bytes() {
        let mut e = Escapes::new(b'~');
        let (out, cmds) = e.feed(b"~?~R");
        assert!(out.is_empty());
        // `~?` leaves the line start state alone, so `~R` after it is an
        // escape too (OpenSSH behaves the same way).
        assert_eq!(cmds, vec![Command::Help, Command::Rekey]);
    }

    #[test]
    fn escape_char_values_parse_as_openssh_spells_them() {
        assert_eq!(parse_escape_char("none"), Some(None));
        assert_eq!(parse_escape_char("~"), Some(Some(b'~')));
        assert_eq!(parse_escape_char("^]"), Some(Some(0x1d)));
        assert_eq!(parse_escape_char("^a"), Some(Some(0x01)));
        assert_eq!(parse_escape_char("ab"), None);
    }
}
