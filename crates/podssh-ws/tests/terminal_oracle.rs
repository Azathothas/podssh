//! Text from a peer as a terminal shows it, after the sanitizer (T-200):
//! hostile text through `one_line` stays on its one row, after what podssh
//! printed before it; the cursor moves by the width of what is left and no
//! further, and no cell takes a color or an attribute. Through
//! `multi_line`, each line is a row of its own, and nothing else moves.
//! The model of the terminal is the one of podssh-terminal's tests
//! (`tests/screen/`), which the gate calibrates against tmux.

#[path = "../../podssh-terminal/tests/screen/mod.rs"]
mod screen;
use screen::Screen;

use podssh_ws::text::{multi_line, one_line};
use unicode_width::UnicodeWidthStr;

/// Hostile text, each with its name: sequences that clear, move, color,
/// retitle, switch screens and reset; C1 controls; BEL, BS, CR, LF, VT, FF,
/// DEL and NUL; and the bidirectional controls of "Trojan Source".
const HOSTILE: &[(&str, &str)] = &[
    ("a clear of the screen", "ok\x1b[2J\x1b[Hdone"),
    ("motions of the cursor", "a\x1b[10;10Hb\x1b[5Ac\x1b[99Dd\x1b7e\x1b8f"),
    ("a color that blinks", "\x1b[1;5;31mred\x1b[0m text"),
    ("a title", "\x1b]0;owned\x07title\x1b]2;again\x1b\\"),
    ("the other screen", "\x1b[?1049hhidden\x1b[?1049l"),
    ("a reset", "\x1bcreset"),
    ("C1 controls", "a\u{9b}31mb\u{9d}0;t\u{9c}c\u{90}d\u{85}e"),
    ("bells and backspaces", "bell\x07\x07 back\x08\x08\x08space"),
    ("a carriage return", "visible\rFAKE"),
    ("line breaks", "one\ntwo\r\nthree\x0bfour\x0cfive"),
    ("tabs and runs of spaces", "a\t\tb   c \t d"),
    ("DEL and NUL", "a\x7fb\0c"),
    ("bidirectional controls", "abc\u{202E}fed\u{202C} \u{2066}x\u{2069} \u{200E}y\u{200F}\u{061C}"),
    ("text of other scripts", "na\u{ef}ve \u{4e2d}\u{6587} ok"),
    ("space at both ends", "  \r\n padded \t "),
    ("nothing but controls", "\x1b\x07\x08\r\n"),
];

/// What podssh prints before a peer's text, as `Log` does.
const PREFIX: &str = "podssh: ";

#[test]
fn hostile_text_through_one_line_stays_on_its_row() {
    for (name, text) in HOSTILE {
        let safe = one_line(text);
        let screen = Screen::of(24, 200, format!("{PREFIX}{safe}").as_bytes());
        let shown = format!("{PREFIX}{safe}").trim_end().to_string();
        assert_eq!(screen.text(), [shown], "{name}: {safe:?}\n{}", screen.show());
        let column = (PREFIX.len() + safe.width()) as u16;
        assert_eq!(screen.cursor(), (0, column), "{name}: {safe:?}\n{}", screen.show());
        assert!(screen.styled().is_empty(), "{name}: {safe:?} took attributes at {:?}", screen.styled());
        assert!(!screen.alternate(), "{name}: {safe:?} moved to the other screen");
    }
}

#[test]
fn a_hostile_banner_through_multi_line_shows_its_lines_as_rows() {
    // Each line of the banner a row, written with CR LF, as a terminal's
    // ONLCR writes them; the clears, colors and the title did nothing.
    let banner = "Welcome\x1b[2J\r\nto \x1b[31mthe\x1b[0m host\rline three\x07\x1b]0;t\x07\n\u{202E}last\x1b[5A";
    let safe = multi_line(banner);
    let screen = Screen::of(24, 80, safe.replace('\n', "\r\n").as_bytes());
    let rows: Vec<String> = safe.lines().map(|line| line.trim_end().to_string()).collect();
    assert_eq!(rows.len(), 4, "{safe:?}");
    assert_eq!(screen.text(), rows, "{safe:?}\n{}", screen.show());
    assert_eq!(screen.cursor(), (3, rows[3].width() as u16), "{}", screen.show());
    assert!(screen.styled().is_empty(), "{safe:?} took attributes at {:?}", screen.styled());
}

#[test]
fn the_model_shows_what_the_sanitizer_prevents() {
    // The control: the same text, not made safe, does on the model what
    // each check above would see. A CR writes over the line, a color takes
    // the cells, the other screen hides the text, and a bare LF steps down.
    let screen = Screen::of(24, 80, b"visible\rFAKE");
    assert_eq!(screen.text(), ["FAKEble"], "{}", screen.show());
    let screen = Screen::of(24, 80, b"\x1b[1;5;31mred\x1b[0m text");
    assert!(!screen.styled().is_empty(), "{}", screen.show());
    let screen = Screen::of(24, 80, b"\x1b[?1049hhidden");
    assert!(screen.alternate(), "{}", screen.show());
    let screen = Screen::of(24, 80, b"one\ntwo");
    assert_eq!(screen.text(), ["one", "   two"], "{}", screen.show());
}
