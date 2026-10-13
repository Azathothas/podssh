use super::*;

fn ground_after(pieces: &[&[u8]]) -> Vec<bool> {
    let mut boundary = Boundary::default();
    pieces
        .iter()
        .map(|piece| {
            boundary.feed(piece);
            boundary.at_ground()
        })
        .collect()
}

#[test]
fn the_boundary_is_at_the_end_of_each_sequence_and_character() {
    // A control sequence, cut and whole.
    assert_eq!(ground_after(&[b"\x1b[3", b"1m", b"text"]), [false, true, true]);
    // An OSC that BEL ends, and one that ST ends, cut inside ST.
    assert_eq!(ground_after(&[b"\x1b]2;a title", b"\x07"]), [false, true]);
    assert_eq!(ground_after(&[b"\x1b]2;a title\x1b", b"\\"]), [false, true]);
    // A DCS ends at ST only, not at BEL.
    assert_eq!(ground_after(&[b"\x1bPq\x07", b"\x1b\\"]), [false, true]);
    // A UTF-8 character of 2, 3 and 4 bytes, each cut before its last byte.
    let characters: [&[u8]; 6] = [b"\xc3", b"\xa9", b"\xe2\x82", b"\xac", b"\xf0\x9f\x98", b"\x80"];
    assert_eq!(ground_after(&characters), [false, true, false, true, false, true]);
    // An escape with an intermediate (a character set), and a lone ESC.
    assert_eq!(ground_after(&[b"\x1b(", b"B", b"\x1b", b"7"]), [false, true, false, true]);
    // CAN ends each sequence; ESC starts a new one inside another.
    assert_eq!(ground_after(&[b"\x1b[12;\x18", b"\x1b]2;x\x1b[1", b"m"]), [true, false, true]);
    // A control byte inside a sequence leaves it open.
    assert_eq!(ground_after(&[b"\x1b[1\r", b"m"]), [false, true]);
}

#[test]
fn a_notice_shows_on_a_terminal_and_nowhere_else() {
    let titled = Facts { raw: true, pty: true, stdout_terminal: true, stack: true, ..Facts::default() };
    assert_eq!(titled.place(), Some(Place::Title));
    // A terminal in raw mode that keeps no known stack: no notice, and the
    // road's lines stay.
    assert_eq!(Facts { stack: false, ..titled }.place(), None);
    assert_eq!(Facts { stdout_terminal: false, ..titled }.place(), None);
    assert_eq!(Facts { quiet: true, ..titled }.place(), None);
    assert_eq!(Facts { sink: true, ..titled }.place(), None);
    // No pty: a line, where stderr is a terminal.
    let line = Facts { stderr_terminal: true, ..Facts::default() };
    assert_eq!(line.place(), Some(Place::Line));
    assert_eq!(Facts { stderr_terminal: false, ..line }.place(), None);
    // A pty with keys from a pipe (-tt): no raw mode, and no line in the
    // program's screen either.
    assert_eq!(Facts { pty: true, ..line }.place(), None);
}

#[test]
fn a_stack_of_titles_is_known_by_the_terminal_s_environment() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
    };
    assert_eq!(title::known_stack(env(&[("XTERM_VERSION", "XTerm(390)")])), Some("xterm"));
    assert_eq!(title::known_stack(env(&[("VTE_VERSION", "7600")])), Some("VTE"));
    // A terminal that the list does not name, as Windows Terminal: none.
    assert_eq!(title::known_stack(env(&[("TERM", "xterm-256color")])), None);
    // Inside tmux or screen, the outer terminal's variables do not count.
    assert_eq!(title::known_stack(env(&[("VTE_VERSION", "7600"), ("TMUX", "/tmp/x,1,0")])), None);
    assert_eq!(title::known_stack(env(&[("XTERM_VERSION", "XTerm(390)"), ("TERM", "screen-256color")])), None);
    // The user's word wins either way.
    assert_eq!(title::known_stack(env(&[("PODSSH_TITLE_STACK", "yes")])), Some(title::TITLE_STACK_ENV));
    assert_eq!(title::known_stack(env(&[("PODSSH_TITLE_STACK", "no"), ("XTERM_VERSION", "x")])), None);
}

#[test]
fn a_title_holds_no_control_character_and_no_semicolon() {
    assert_eq!(title::set("a;b\x07c\x1bd"), b"\x1b]2;abcd\x07".to_vec());
}

#[test]
fn the_silence_of_a_road_is_read_through_its_handle() {
    let silence = Silence::default();
    assert!(!silence.attached());
    assert_eq!(silence.silent(), None);
    let shared = silence.clone();
    shared.attach(|| Some(Duration::from_secs(3)));
    assert!(silence.attached());
    assert_eq!(silence.silent(), Some(Duration::from_secs(3)));
    let notice = Notice::new(Place::Title, &silence, "h", None);
    assert!(shared.titled());
    drop(notice);
    assert!(!shared.titled(), "the road's lines come back with the session's end");
}
