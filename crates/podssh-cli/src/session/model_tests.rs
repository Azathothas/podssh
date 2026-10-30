//! The tests of what a session's daemon keeps of its output (T-186).

use super::*;

fn text_of(chunks: &[&[u8]]) -> Vec<u8> {
    let mut plain = Plain::default();
    let mut out = Vec::new();
    for chunk in chunks {
        plain.feed(chunk, &mut out);
    }
    out
}

/// A match reads text: colours, a title, a cursor move and the control
/// bytes go, also when a sequence is cut between two chunks.
#[test]
fn the_text_of_a_match_has_no_sequence_in_it() {
    assert_eq!(text_of(&[b"\x1b[1;32mgreen\x1b[0m text\r\n"]), b"green text\n");
    assert_eq!(text_of(&[b"\x1b]0;a title\x07after"]), b"after");
    assert_eq!(text_of(&[b"\x1b]2;a title\x1b\\after"]), b"after");
    assert_eq!(text_of(&[b"\x1bPq#0;2;0;0;0\x1b\\x"]), b"x");
    assert_eq!(text_of(&[b"a\x1b[", b"10;20", b"Hb"]), b"ab");
    assert_eq!(text_of(&[b"a\x1b(Bb\x1b=c"]), b"abc");
    assert_eq!(text_of(&[b"tab\there\x07\x08"]), b"tab\there");
    // CAN ends a sequence, and the text goes on.
    assert_eq!(text_of(&[b"\x1b[12\x18ok"]), b"ok");
    assert_eq!(text_of(&["caf\u{e9}".as_bytes()]), "caf\u{e9}".as_bytes());
}

#[test]
fn a_match_reads_only_what_came_after_the_last_send() {
    let now = Instant::now();
    let mut model = Model::new(24, 80, now);
    model.output(b"$ old-marker\r\n", now);
    assert!(model.matched(b"old-marker"));
    model.sent(now);
    assert!(!model.matched(b"old-marker"), "a send starts the text of a match again");
    model.output(b"\x1b[32mnew\x1b[0m-marker\r\n", now);
    assert!(model.matched(b"new-marker"));
    assert!(!model.matched(b""));
}

/// The plant of the wait: quiet counts from the later of the last output
/// and the last send, so that a wait just after a send waits for what the
/// send brings.
#[test]
fn quiet_counts_from_the_last_output_or_the_last_send() {
    let start = Instant::now();
    let idle = Duration::from_secs(2);
    let mut model = Model::new(24, 80, start);
    assert_eq!(model.idle_left(idle, start), idle, "nothing came yet: quiet from the start");
    assert_eq!(model.idle_left(idle, start + Duration::from_secs(3)), Duration::ZERO);
    model.output(b"hi\r\n", start + Duration::from_secs(3));
    assert_eq!(model.idle_left(idle, start + Duration::from_secs(4)), Duration::from_secs(1));
    // A send after a long quiet: the wait starts again from the send.
    model.sent(start + Duration::from_secs(10));
    assert_eq!(model.idle_left(idle, start + Duration::from_secs(10)), idle);
    assert_eq!(model.idle_left(idle, start + Duration::from_secs(12)), Duration::ZERO);
}

/// Output that pauses inside a sequence has not stopped: the wait goes on
/// until the grammar calls the sequence broken.
#[test]
fn output_that_pauses_inside_a_sequence_has_not_stopped() {
    let start = Instant::now();
    let idle = Duration::from_secs(2);
    let mut model = Model::new(24, 80, start);
    model.output(b"text\x1b]0;a title that goes on", start);
    let later = start + Duration::from_secs(3);
    assert_eq!(model.idle_left(idle, later), BROKEN_AFTER - Duration::from_secs(3));
    assert_eq!(model.idle_left(idle, start + BROKEN_AFTER), Duration::ZERO);
    model.output(b"\x07$ ", later);
    assert_eq!(model.idle_left(idle, later + idle), Duration::ZERO, "the title ended");
}

/// The screen is a terminal's: a line drawn over, a cleared screen and a
/// moved cursor show what a person would see, with no blank at the ends.
#[test]
fn the_screen_is_what_a_terminal_shows() {
    let now = Instant::now();
    let mut model = Model::new(5, 20, now);
    model.output(b"echo hi\r\nhi\r\n$ ", now);
    assert_eq!(model.screen(), "echo hi\nhi\n$\n");
    assert_eq!(model.cursor(), (2, 2));
    assert_eq!(model.size(), (5, 20));
    // A progress line drawn over itself, then a clear and a write at row 3.
    model.output(b"\r10%\r99%\x1b[2J\x1b[3;5Hthere", now);
    assert_eq!(model.screen(), "\n\n    there\n");
    // The raw bytes keep each sequence, as they came.
    assert!(model.raw().ends_with(b"\x1b[2J\x1b[3;5Hthere"));
    assert!(model.raw().starts_with(b"echo hi"));
}

/// The raw bytes are the last 64 KiB, from a clean place: a cut never
/// starts inside a title.
#[test]
fn the_raw_bytes_are_the_last_from_a_clean_place() {
    let now = Instant::now();
    let mut model = Model::new(24, 80, now);
    let mut long = b"\x1b]0;".to_vec();
    long.extend(std::iter::repeat_n(b't', KEPT));
    long.extend(b"\x07after the title");
    model.output(&long, now);
    let raw = model.raw();
    assert!(raw.len() <= KEPT, "{} bytes", raw.len());
    assert_eq!(raw, b"after the title");
}
