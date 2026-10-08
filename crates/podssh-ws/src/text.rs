//! Text that came from a peer, made safe to print on a terminal.
//!
//! A relay's error body, a WebSocket close reason, a proxy's status line or an
//! SSH banner can carry ESC, BEL or a bare CR, which repaint the line, ring the
//! bell or overwrite what the user is reading. Everything podssh prints from a
//! peer goes through one of these two functions, so there is one definition of
//! "safe" (a sibling project ended up with two that disagreed).

/// For a one-line message: control characters (C0, DEL, C1) and bidirectional
/// formatting characters are dropped, and every run of whitespace, line breaks
/// included, becomes one space. Leading and trailing whitespace is removed.
pub fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = true;
        } else if c.is_control() || is_bidi_control(c) {
            continue;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// For text that is meant to span lines (an SSH banner, a keyboard-interactive
/// instruction): CR LF and a lone CR become LF, tabs stay, and every other
/// control or bidirectional formatting character is dropped.
pub fn multi_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_bidi_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Characters that reorder how a terminal displays the text around them
/// (the "Trojan Source" set), plus the Arabic letter mark.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(one_line("403 missing or wrong token"), "403 missing or wrong token");
        assert_eq!(multi_line("Welcome.\nNo shell here.\n"), "Welcome.\nNo shell here.\n");
        assert_eq!(one_line("naïve — ok"), "naïve — ok");
    }

    #[test]
    fn terminal_controls_are_removed() {
        // ESC sequences, BEL, a bare CR that would overwrite the line, and the
        // 8-bit CSI (U+009B). The CR is whitespace, so one line shows a space.
        let hostile = "ok\x1b[2J\x1b]0;title\x07\rFAKE\u{9b}31m";
        assert_eq!(one_line(hostile), "ok[2J]0;title FAKE31m");
        assert!(!multi_line(hostile).contains('\x1b'));
        assert!(!multi_line(hostile).contains('\x07'));
        assert!(!multi_line(hostile).contains('\u{9b}'));
    }

    #[test]
    fn bidirectional_overrides_are_removed() {
        assert_eq!(one_line("abc\u{202E}fed\u{202C}"), "abcfed");
        assert_eq!(multi_line("a\u{2066}b\u{2069}c"), "abc");
    }

    #[test]
    fn one_line_folds_whitespace_and_line_breaks() {
        assert_eq!(one_line("  a \r\n\t b\n\nc  "), "a b c");
        assert_eq!(one_line("\n\n"), "");
    }

    #[test]
    fn multi_line_normalises_line_breaks() {
        assert_eq!(multi_line("a\r\nb\rc\nd\te"), "a\nb\nc\nd\te");
    }
}
