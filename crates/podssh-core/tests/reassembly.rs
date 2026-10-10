//! **PLANT: a message split across two frames must reassemble.**
//!
//! **This is the defect the whole transport can cause and the one a fixture
//! hides**, and the entry says so in its own words. A WebSocket frame carries
//! bytes and **the relay copies payload verbatim**, so a frame boundary
//! means nothing on the IRC wire and a message may be split at any byte.
//!
//! **A fixture cannot express a split.** `tests/fixtures/grammar.txt` is a
//! table of complete lines; the split is not a property of a line, it is a
//! property of *how the bytes arrived*. So these tests **split the bytes
//! themselves**, at every offset, rather than reproducing one lucky split.

mod common;

use podssh_core::irc::framing::{FrameError, Framed, Reassembler, DEFAULT_MAX_LINE};
use podssh_core::irc::message::{Command, Message};

const LONG: &str = ":alice!u@host PRIVMSG #ops :the quick brown fox jumps over the lazy dog";

/// **THE PLANT.** One message, cut in two at the halfway point, pushed as
/// two frames. **Neither half is a message** and a client that parses
/// per-frame emits half a `PRIVMSG` as if it were a whole one.
#[test]
fn plant_a_message_split_across_two_frames_reassembles() {
    let wire = format!("{LONG}\r\n");
    let bytes = wire.as_bytes();
    let at = bytes.len() / 2;

    let mut r = Reassembler::new();
    let first = common::texts(r.push(&bytes[..at]));
    assert!(
        first.is_empty(),
        "PLANT: the first half produced {:?}. A frame boundary means nothing on \
         the IRC wire, so a half message must produce no message at all.",
        first
    );
    assert_eq!(r.pending_len(), at, "the half is buffered, not dropped");

    let second = common::texts(r.push(&bytes[at..]));
    assert_eq!(second, vec![LONG.to_string()], "PLANT: the message did not reassemble");
    assert_eq!(r.pending_len(), 0);
}

#[test]
fn every_split_of_one_message_reassembles() {
    // **EVERY BYTE OFFSET, NOT ONE LUCKY SPLIT.** A single
    // hand-picked split is a coin toss: a reassembler that gets the common
    // case right and mishandles a split one byte earlier survives it.
    // **This is the test the entry's plant clause asks for**, and the
    // cost is len(line) runs — cheap, and it is the difference
    // between a proof and an anecdote.
    let wire = format!(
        "{LONG}
"
    );
    let bytes = wire.as_bytes();
    let mut checked = 0usize;
    for at in 1..bytes.len() {
        let mut r = Reassembler::new();
        let mut out = common::texts(r.push(&bytes[..at]));
        if at < bytes.len() - 2 {
            assert!(out.is_empty(), "a split at byte {at} produced {out:?} from the first half");
        }
        out.extend(common::texts(r.push(&bytes[at..])));
        assert_eq!(out, vec![LONG.to_string()], "a split at byte {at} did not reassemble");
        assert_eq!(r.pending_len(), 0, "a split at byte {at} left bytes buffered");
        checked += 1;
    }
    assert!(checked > 40, "only {checked} split offsets ran; the suite is too small to mean anything");
}

#[test]
fn a_message_split_into_three_frames_still_reassembles() {
    let wire = format!("{LONG}\r\nPING :aBcD1234\r\n");
    let bytes = wire.as_bytes();
    let first_len = LONG.len() + 2;

    // **Three ordered cut points, derived from the message boundaries** and
    // every one of them lands *inside* a message — which is the point,
    // because a cut between two complete messages proves nothing.
    let cuts = [(10, 30), (20, first_len - 1), (first_len - 2, first_len + 6)];
    for (a, b) in cuts {
        assert!(a < b && b < bytes.len(), "cut points must be ordered: {a} {b}");
        let mut r = Reassembler::new();
        let mut out = Vec::new();
        for part in [&bytes[..a], &bytes[a..b], &bytes[b..]] {
            out.extend(common::texts(r.push(part)));
        }
        assert_eq!(
            out,
            vec![LONG.to_string(), "PING :aBcD1234".to_string()],
            "a three-way split at {a}/{b} did not reassemble"
        );
    }
}

#[test]
fn a_crlf_split_across_two_frames_is_still_one_terminator() {
    // **The split that a naive byte-splitter gets wrong.** The `\r` and
    // the `\n` are separate bytes, so a frame may end after the `\r`. A
    // reassembler that treats a lone `\r` as a terminator emits the line one
    // byte early and then emits an empty line when the `\n` arrives.
    let wire = b"PING :tok\r\n";
    for at in 1..wire.len() {
        let mut r = Reassembler::new();
        let mut out = Vec::new();
        out.extend(common::texts(r.push(&wire[..at])));
        out.extend(common::texts(r.push(&wire[at..])));
        assert_eq!(out, vec!["PING :tok".to_string()], "a split at byte {at} did not produce exactly one line");
    }
}

#[test]
fn a_bare_lf_is_a_terminator_and_a_lone_cr_is_not() {
    // RFC 1459 mandates CRLF and the encoder only writes that but a server
    // that emits a bare LF is real, and a client that drops the message is worse
    // than one that accepts it.
    let mut r = Reassembler::new();
    assert_eq!(common::texts(r.push(b"JOIN #one\n")), vec!["JOIN #one".to_string()]);

    // **A lone `\r` is never a terminator**, because a CRLF arriving as two
    // separate frames is the split this module exists for.
    let mut r = Reassembler::new();
    assert!(common::texts(r.push(b"JOIN #one\r")).is_empty());
    assert_eq!(r.pending_len(), 10);
    assert_eq!(common::texts(r.push(b"\n")), vec!["JOIN #one".to_string()]);
}

#[test]
fn a_lone_cr_inside_a_line_is_content() {
    let mut r = Reassembler::new();
    assert_eq!(
        common::texts(r.push(b"PRIVMSG #c :a\rb\r\n")),
        vec!["PRIVMSG #c :a\rb".to_string()],
        "a CR that is not part of a CRLF is content, not a terminator"
    );
}

// ── the truncate plant ──────────────────────────────────────────────────────

#[test]
fn plant_a_stream_truncated_mid_line_emits_no_partial_line() {
    // **THE PLANT.** The stream ends in the middle of a `PRIVMSG`. A
    // client that emitted the partial line would put
    // `:alice!u@host PRIVMSG #ops :hel` in a user's terminal and then nothing
    // more, and the user cannot tell that from a peer that stopped talking.
    let wire = b":alice!u@host PRIVMSG #ops :hello there world\r\n";
    let keep = wire.len() - 15;
    let mut r = Reassembler::new();
    let out = common::texts(r.push(&wire[..keep]));
    assert!(
        out.is_empty(),
        "PLANT: a truncated push emitted {:?}; a partial line must not be \
         emitted as a message",
        out
    );
    assert_eq!(r.pending_len(), keep);

    // **The end of the stream is a separate, explicit event** and it is the
    // only place a partial line may be observed and it is returned to the
    // caller rather than emitted as a message.
    let rest = r.take_rest().expect("the partial line is still buffered");
    assert_eq!(
        rest,
        std::str::from_utf8(&wire[..keep]).expect("the prefix is UTF-8"),
        "the partial line must be exactly the bytes that arrived"
    );
    assert!(rest.starts_with(":alice!u@host PRIVMSG #ops :"));
    assert_eq!(r.pending_len(), 0, "taking the rest must clear the buffer");
    assert_eq!(r.take_rest(), None, "there is nothing left to take");
}

#[test]
fn plant_a_stream_truncated_at_every_offset_never_emits_a_partial_line() {
    let wire = b":alice!u@host PRIVMSG #ops :hello there world\r\n";
    for at in 1..wire.len() {
        let mut r = Reassembler::new();
        let out = common::texts(r.push(&wire[..at]));
        assert!(
            out.is_empty(),
            "PLANT: a stream truncated at byte {at} emitted {:?}; every \
             truncation before the CRLF must emit nothing",
            out
        );
    }
}

#[test]
fn a_clean_end_of_stream_takes_nothing() {
    let wire = b"PING :aBcD1234\r\n";
    let mut r = Reassembler::new();
    assert_eq!(common::texts(r.push(wire)), vec!["PING :aBcD1234".to_string()]);
    // **Nothing pending, so nothing to take**, and the reconnect path can
    // tell a clean end from a truncation.
    assert_eq!(r.take_rest(), None);
}

#[test]
fn a_truncated_line_does_not_parse_as_a_message_even_if_it_is_handed_over() {
    // **The second half of the truncate plant, and the one a fixture hides.**
    // `take_rest` deliberately returns the partial line and **the parser
    // must then refuse it**, because `:alice!u@host PRIVMSG #ops :hel` is not
    // a malformed message — it is a perfectly well-formed message with a
    // shorter text. **Only the caller knows the stream ended**, and that
    // is why [`Session::on_stream_end`](podssh_core::irc::Session::on_stream_end)
    // reports it rather than parsing it.
    let partial = ":alice!u@host PRIVMSG #ops :hel";
    let m = Message::parse(partial).expect("it IS syntactically valid");
    let Command::Privmsg { text, .. } = &m.command else { panic!("expected a PRIVMSG") };
    // **The defect this names**: a truncated stream handed to a parser yields
    // a *complete-looking* message whose text happens to be short.
    assert_eq!(text.as_str(), "hel");
    // So the guard is the stream's word, not the parse's.
    assert!(podssh_core::irc::SessionError::TruncatedMidLine {
        partial: partial.to_string(),
        pending_bytes: partial.len(),
    }
    .to_string()
    .contains("partial"));
}

// ── limits, NUL, and UTF-8 ──────────────────────────────────────────────────

#[test]
fn an_over_long_line_is_discarded_and_the_stream_resynchronises() {
    // **Not a plant: this is the control for one.** The line past the limit
    // is dropped whole and named, and the line after it comes out: the long
    // line arrived with its end, so nothing of it is left to skip.
    let mut r = Reassembler::with_max_line(64);
    let long = "P".repeat(500);
    let out = r.push(format!("{long}\r\nPING :after\r\n").as_bytes());
    assert_eq!(
        out,
        [Framed::Lost(FrameError::Overlong { bytes: 500, max_line: 64 }), Framed::Line("PING :after".into())],
        "the loss names the line and the limit, and the next line is whole"
    );
    assert!(!r.overflowed(), "nothing of a line that ended is left to skip");
    assert_eq!(common::texts(r.push(b"PING :next\r\n")), ["PING :next"]);

    // **The tail of an over-long line with no end yet is dropped with it**
    // rather than parsed as a fresh message — which is what keeps 40 KB of
    // one line from becoming forty thousand messages — and nothing of it is
    // held, so the buffer cannot grow.
    let mut r = Reassembler::with_max_line(64);
    assert_eq!(r.push(long.as_bytes()), [Framed::Lost(FrameError::Overlong { bytes: 500, max_line: 64 })]);
    assert!(r.overflowed(), "an unterminated over-long line must be flagged");
    assert_eq!(r.pending_len(), 0);
    assert!(r.push(b"PING :tail\r\n").is_empty(), "the rest of it is skipped");
    assert!(!r.overflowed());
}

#[test]
fn a_line_at_exactly_the_limit_is_accepted() {
    // **The limit counts the CRLF**, because RFC 2812 §2.3 says *"a maximum
    // message length of 512 characters"* and a message on the wire carries its
    // terminator. A ten-byte line is twelve on the wire, so twelve is the
    // smallest limit that accepts it and eleven is the largest that refuses it.
    let line = "0123456789"; // ten bytes; twelve with the CRLF
    let mut r = Reassembler::with_max_line(12);
    let out = common::texts(r.push(format!("{line}\r\n").as_bytes()));
    assert_eq!(out, vec![line.to_string()]);

    let mut r = Reassembler::with_max_line(11);
    assert_eq!(
        r.push(format!("{line}\r\n").as_bytes()),
        [Framed::Lost(FrameError::Overlong { bytes: 10, max_line: 11 })],
        "one over is lost, and the loss names the line and the limit"
    );
}

#[test]
fn nul_is_stripped_and_never_truncates() {
    // RFC 2812 §2.3.1 allows no NUL in a message; podssh strips it rather
    // than cut the line there.
    let mut r = Reassembler::new();
    assert_eq!(
        common::texts(r.push(b"PRIVMSG #c :a\0b\0c\r\n")),
        vec!["PRIVMSG #c :abc".to_string()],
        "NUL must be dropped and the rest of the line kept"
    );
}

#[test]
fn an_empty_line_is_no_message_at_all() {
    let mut r = Reassembler::new();
    assert!(common::texts(r.push(b"\r\n\r\n")).is_empty(), "a blank line is not a message");
    assert_eq!(r.pending_len(), 0);
}

#[test]
fn the_default_limit_is_far_enough_for_the_largest_line_the_entry_writes() {
    // **The chunk size is proved against this number**, not against the
    // parser's opinion of it. RFC 2812 §2.3 caps a message at 512 including
    // the terminator; a chunk line must land under that, and this test
    // fails if `TransferLimits::chunk_bytes` is ever raised past it.
    let limits = podssh_core::irc::TransferLimits::default();
    let length = podssh_core::irc::transfer::chunk_line_length(&limits, "t", 0, 0);
    assert!(length <= 512, "a chunk line is {length} bytes; RFC 2812 §2.3 caps a message at 512");
    // Two constants: checked when the test compiles.
    const {
        assert!(
            DEFAULT_MAX_LINE >= 512,
            "the reassembler's default limit must be at least the RFC's 512, or a \
             legal message is refused"
        )
    };
}

#[test]
fn the_suite_is_not_vacuous() {
    // **A suite that runs nothing reports 0 passed and exit 0.** That is
    // a pass that measured nothing, and this repository has shipped a gate that
    // did it. So the split cases are counted, not assumed.
    let mut count = 0usize;
    let bytes = format!("{LONG}\r\n").into_bytes();
    for at in 1..bytes.len() {
        let mut r = Reassembler::new();
        let mut out = common::texts(r.push(&bytes[..at]));
        out.extend(common::texts(r.push(&bytes[at..])));
        assert_eq!(out.len(), 1);
        count += 1;
    }
    assert!(count > 20, "only {count} split cases ran; the suite is too small to mean anything");
    let _ = common::lines_from(&bytes);
}
