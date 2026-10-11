//! What more than one fuzz target checks (T-198).

/// Whether `text` is safe on one line of a terminal, as
/// `podssh_ws::text::one_line` promises (`SECURITY.md`): no control
/// character, no bidirectional formatting character, and no whitespace but
/// single spaces between words, none at the ends.
pub fn is_one_line(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || is_bidi_control(c) || (c.is_whitespace() && c != ' '))
        && !text.starts_with(' ')
        && !text.ends_with(' ')
        && !text.contains("  ")
}

/// Unicode's bidirectional formatting characters, which reorder what a
/// terminal shows. A list of its own, so that the check does not trust the
/// code that it checks.
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The input as text, or nothing: the parsers of text take `&str`.
pub fn text(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok()
}
