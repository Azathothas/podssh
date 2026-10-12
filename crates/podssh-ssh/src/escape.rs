//! The escape character of an interactive session (ssh(1), ESCAPE
//! CHARACTERS): recognised only at the start of a line, and only when a pty
//! was allocated. podssh implements `~.` (disconnect), `~R` (re-key), `~#`
//! (the forwards and their counts, T-041), `~?` (help) and `~~` (a literal
//! `~`); any other character after `~` is sent as typed, with the `~`.
//! `~d` (detach, T-158) is an escape only when the far end keeps shells,
//! which the road learns; elsewhere it is sent as typed.

/// Something the user asked for with an escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Disconnect,
    Rekey,
    /// `~#`: the forwards of the session, with what each carried.
    List,
    /// `~d`: the far end keeps the shell, and this client leaves it.
    Detach,
    Help,
}

/// Each escape, after the escape character: its key, what it asks, and its
/// words in the help of `~?`, which are OpenSSH's. The input, the help and
/// the manual's note of the terminal (T-130) read this table, and no other
/// list of escapes.
pub const ESCAPES: &[(u8, Command, &str)] = &[
    (b'.', Command::Disconnect, "terminate connection"),
    (b'R', Command::Rekey, "request rekey"),
    (b'#', Command::List, "list forwarded connections"),
    // Not OpenSSH's: podssh's own, for a far end that keeps shells (T-158).
    (b'd', Command::Detach, "detach: the far end keeps the shell"),
    (b'?', Command::Help, "this message"),
];

/// The escape state across reads from stdin.
#[derive(Debug, Clone)]
pub struct Escapes {
    escape: u8,
    at_line_start: bool,
    pending: bool,
    /// Whether `~d` detaches: only when the far end keeps shells.
    detach: bool,
}

impl Escapes {
    pub fn new(escape: u8) -> Self {
        Escapes { escape, at_line_start: true, pending: false, detach: false }
    }

    /// With `~d` as an escape, when `offered`: the far end keeps shells
    /// (T-158). Without it, `~d` goes to the server as two bytes.
    pub fn with_detach(mut self, offered: bool) -> Self {
        self.detach = offered;
        self
    }

    /// Whether `command` is an escape of this session.
    fn offers(&self, command: Command) -> bool {
        command != Command::Detach || self.detach
    }

    /// Filter one read: returns the bytes to send and the commands found, in
    /// order. A `~.` or a `~d` ends the input there; nothing after it is sent.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<Command>) {
        let mut out = Vec::with_capacity(input.len());
        let mut commands = Vec::new();
        for &b in input {
            if self.pending {
                self.pending = false;
                let escape = ESCAPES.iter().find(|(key, command, _)| *key == b && self.offers(*command));
                if let Some(&(_, command, _)) = escape {
                    commands.push(command);
                    // Nothing after ~. or ~d is sent: the session ends there.
                    if matches!(command, Command::Disconnect | Command::Detach) {
                        return (out, commands);
                    }
                    continue;
                }
                match b {
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

    /// The text `~?` prints, in OpenSSH's words; `~d` only when it detaches.
    pub fn help(&self) -> String {
        let e = self.escape as char;
        let mut text = String::from("Supported escape sequences:\n");
        for (key, _, words) in ESCAPES.iter().filter(|(_, command, _)| self.offers(*command)) {
            text.push_str(&format!(" {e}{}   - {words}\n", *key as char));
        }
        text.push_str(&format!(" {e}{e}   - send the escape character by typing it twice\n"));
        text.push_str("(Note that escapes are only recognized immediately after newline.)\n");
        text
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

    /// `~?` lists each escape of the table, in OpenSSH's words.
    #[test]
    fn the_help_lists_each_escape_in_openssh_s_words() {
        let help = Escapes::new(b'~').help();
        let want = "Supported escape sequences:\n ~.   - terminate connection\n ~R   - request rekey\n \
                    ~#   - list forwarded connections\n ~?   - this message\n ~~   - send the escape \
                    character by typing it twice\n(Note that escapes are only recognized immediately after \
                    newline.)\n";
        assert_eq!(help, want);
        // `~d` too, where the far end keeps shells.
        let mut e = Escapes::new(b'~').with_detach(true);
        for (key, command, _) in ESCAPES {
            assert_eq!(e.feed(&[b'~', *key]).1, vec![*command], "~{}", *key as char);
            e = Escapes::new(b'~').with_detach(true);
        }
    }

    /// `~d` detaches only when the far end keeps shells (T-158), and ends
    /// the input there; elsewhere it is two bytes, as each other key.
    #[test]
    fn tilde_d_detaches_only_when_the_far_end_keeps_shells() {
        let mut e = Escapes::new(b'~');
        let (out, cmds) = e.feed(b"~d\r");
        assert_eq!(out, b"~d\r");
        assert!(cmds.is_empty());
        let mut e = Escapes::new(b'~').with_detach(true);
        let (out, cmds) = e.feed(b"MARK=kept\r~dexit\r");
        assert_eq!(out, b"MARK=kept\r");
        assert_eq!(cmds, vec![Command::Detach]);
        // At the start of a line only, and split across reads.
        let mut e = Escapes::new(b'~').with_detach(true);
        let (out, cmds) = e.feed(b"echo ~d\r~");
        assert_eq!(out, b"echo ~d\r");
        assert!(cmds.is_empty());
        assert_eq!(e.feed(b"d"), (Vec::new(), vec![Command::Detach]));
        // `~~d` sends `~d` either way.
        let mut e = Escapes::new(b'~').with_detach(true);
        assert_eq!(e.feed(b"~~d").0, b"~d");
    }

    /// `~?` names `~d` only where it detaches.
    #[test]
    fn the_help_names_tilde_d_only_where_it_detaches() {
        assert!(!Escapes::new(b'~').help().contains("~d"));
        let help = Escapes::new(b'~').with_detach(true).help();
        assert!(help.contains(" ~d   - detach: the far end keeps the shell\n"), "{help}");
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
