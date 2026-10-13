//! What podssh says on a terminal in raw mode, as the terminal shows it
//! (T-200): each line of a message and of the help of `~?` starts at the
//! first column. A terminal in raw mode does not turn LF into CR LF, so a
//! text that kept a bare LF would step down the screen like stairs. The
//! model of the terminal is the one of podssh-terminal's tests
//! (`tests/screen/`), a terminal in raw mode, which the gate calibrates
//! against tmux.

#[path = "../../podssh-terminal/tests/screen/mod.rs"]
mod screen;
use screen::Screen;

use podssh_ssh::escape::Escapes;
use podssh_ssh::log::message_text;

/// The lines of `text`, each as it must show on a row of its own.
fn lines(text: &str) -> Vec<String> {
    text.lines().map(|line| line.trim_end().to_string()).collect()
}

#[test]
fn the_help_of_tilde_question_shows_each_line_from_the_first_column() {
    // The help with and without `~d`, and with another escape character,
    // as `Log::banner` writes it in raw mode.
    for escapes in [Escapes::new(b'~'), Escapes::new(b'~').with_detach(true), Escapes::new(b'%')] {
        let help = escapes.help();
        let screen = Screen::of(24, 80, message_text(&help, false, true).as_bytes());
        assert_eq!(screen.text(), lines(&help), "{}", screen.show());
        assert_eq!(screen.cursor(), (lines(&help).len() as u16, 0), "{}", screen.show());
    }
}

#[test]
fn a_message_of_several_lines_shows_each_from_the_first_column() {
    // A message with a bare LF, with CR LF, and with no line break at its
    // end: `podssh: ` and three rows, and the cursor on the next.
    let text = message_text("first\nsecond\r\nthird", true, true);
    let screen = Screen::of(24, 80, text.as_bytes());
    assert_eq!(screen.text(), ["podssh: first", "second", "third"], "{}", screen.show());
    assert_eq!(screen.cursor(), (3, 0), "{}", screen.show());
}

#[test]
fn after_the_server_s_output_a_message_and_the_help_start_on_rows_of_their_own() {
    // The server's output ended its row with CR LF, as a remote pty writes
    // it; a message and the help after it each start at the first column,
    // and the output above them stays.
    let mut screen = Screen::new(24, 80);
    screen.feed(b"$ ls\r\nfile\r\n");
    screen.feed(message_text("rekeying", true, true).as_bytes());
    let help = Escapes::new(b'~').help();
    screen.feed(message_text(&help, false, true).as_bytes());
    let mut want = vec!["$ ls".to_string(), "file".into(), "podssh: rekeying".into()];
    want.extend(lines(&help));
    assert_eq!(screen.text(), want, "{}", screen.show());
}

#[test]
fn without_raw_mode_the_text_keeps_its_line_feeds_which_a_raw_terminal_shows_as_stairs() {
    // The control: the text for a terminal that is not raw, or for a file,
    // keeps LF, which such a terminal turns into CR LF itself. The model is
    // raw, and shows the stairs that the conversion prevents: the check
    // above would see them.
    let text = message_text("first\nsecond", true, false);
    assert_eq!(text, "podssh: first\nsecond\n");
    let screen = Screen::of(24, 80, text.as_bytes());
    assert_eq!(screen.text(), ["podssh: first", "             second"], "{}", screen.show());
    let help = Escapes::new(b'~').help();
    let stairs = Screen::of(24, 80, message_text(&help, false, false).as_bytes());
    assert_ne!(stairs.text(), lines(&help), "{}", stairs.show());
}
