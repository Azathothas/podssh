//! The tracker's own tests: each state, the bytes that end it, and the rule
//! of a broken sequence. The tests against captured sessions and a terminal
//! parser of another project are `tests/grammar_boundary.rs`.

use super::*;

/// The offsets where a cut is clean, the chunks read at one time.
fn clean_in(chunks: &[&[u8]]) -> Vec<u64> {
    let mut tracker = Tracker::new();
    let now = Instant::now();
    let mut found = Vec::new();
    for chunk in chunks {
        tracker.feed(chunk, now, |b| found.push(b.at));
    }
    found
}

fn clean(bytes: &[u8]) -> Vec<u64> {
    clean_in(&[bytes])
}

/// The boundaries of chunks that came at these times.
fn timed(chunks: &[(&[u8], Duration)]) -> Vec<Boundary> {
    let mut tracker = Tracker::new();
    let t0 = Instant::now();
    let mut found = Vec::new();
    for (chunk, at) in chunks {
        tracker.feed(chunk, t0 + *at, |b| found.push(b));
    }
    found
}

#[test]
fn text_is_a_boundary_at_each_byte() {
    assert_eq!(clean(b"ab\r\n"), [0, 1, 2, 3]);
}

#[test]
fn a_utf8_continuation_byte_is_never_a_boundary() {
    // a, then é (2 bytes), the euro sign (3) and an emoji (4), then b.
    assert_eq!(clean("a\u{e9}\u{20ac}\u{1f600}b".as_bytes()), [0, 1, 3, 6, 10]);
    // A stray continuation byte starts nothing, and the text after it does.
    assert_eq!(clean(b"a\x80b"), [0, 2]);
}

#[test]
fn the_byte_that_cuts_a_character_short_starts_no_boundary() {
    // vte drops the `a`; a terminal that reads it shows it.
    assert_eq!(clean(b"\xc3a b"), [0, 2, 3]);
    // An ESC there still starts a sequence.
    assert_eq!(clean(b"\xc3\x1b[mz"), [0, 4]);
}

#[test]
fn a_csi_ends_at_its_final_byte() {
    assert_eq!(clean(b"\x1b[?1049hx"), [0, 8]);
    assert_eq!(clean(b"\x1b[>4;2mx"), [0, 7]);
    // A control byte inside it is acted on, and the CSI goes on.
    assert_eq!(clean(b"\x1b[1\r;2Hx"), [0, 7]);
}

#[test]
fn an_escape_and_one_byte_or_intermediates_is_a_sequence() {
    // `ESC =`, then `ESC ( B` with an intermediate.
    assert_eq!(clean(b"\x1b=a\x1b(Bb"), [0, 2, 3, 6]);
}

#[test]
fn an_osc_ends_with_bel_or_st() {
    // A title by BEL, then one in UTF-8 by ST (`ESC \`).
    let bytes = b"\x1b]0;t\x07a\x1b]2;\xc3\xa9\x1b\\b";
    assert_eq!(clean(bytes), [0, 6, 7, 15]);
}

#[test]
fn a_dcs_sos_pm_and_apc_end_with_st_alone() {
    // BEL inside a DCS is data, not its end.
    assert_eq!(clean(b"\x1bPq#0;2\x07x\x1b\\y"), [0, 11]);
    for intro in *b"X^_" {
        let mut bytes = vec![0x1b, intro];
        bytes.extend_from_slice(b"data\x07more\x1b\\z");
        assert_eq!(clean(&bytes), [0, 13], "ESC {}", intro as char);
    }
    // 0x9C, the 8-bit ST, ends no string.
    assert_eq!(clean(b"\x1bPq\x9cx\x1b\\y"), [0, 7]);
}

#[test]
fn can_and_sub_end_each_sequence() {
    assert_eq!(clean(b"\x1b]0;t\x18a"), [0, 6]);
    assert_eq!(clean(b"\x1b[12\x1ab"), [0, 5]);
    assert_eq!(clean(b"\x1bPq\x18c"), [0, 4]);
    assert_eq!(clean(b"\xe2\x82\x18d"), [0, 3]);
}

#[test]
fn an_escape_inside_a_sequence_starts_a_new_one() {
    assert_eq!(clean(b"\x1b]0;t\x1b[mz"), [0, 8]);
    assert_eq!(clean(b"\x1b[1;\x1b[2Jz"), [0, 8]);
}

#[test]
fn the_boundaries_do_not_depend_on_where_the_chunks_end() {
    let bytes = "a\u{e9}\x1b]0;t\u{20ac}\x07\x1b[1;31m\u{1f600}\x1bPq\x1b\\\x1b(Bz\r\n".as_bytes();
    let whole = clean(bytes);
    for cut in 0..=bytes.len() {
        let (a, b) = bytes.split_at(cut);
        assert_eq!(clean_in(&[a, b]), whole, "cut at {cut}");
    }
    assert_eq!(clean_in(&bytes.chunks(1).collect::<Vec<_>>()), whole);
}

#[test]
fn a_sequence_with_no_byte_for_10_s_starts_again_after_the_next_newline() {
    let found = timed(&[(b"a\x1b]0;tit", Duration::ZERO), (b"le\x07x\nnext", BROKEN_AFTER)]);
    // The BEL, which would have ended the title, comes after the break and
    // means nothing; the stream starts again after the newline, at `next`.
    let restart = Boundary { at: 13, restart: true };
    assert_eq!(found[..3], [Boundary { at: 0, restart: false }, Boundary { at: 1, restart: false }, restart]);
    assert_eq!(found.iter().filter(|b| b.restart).count(), 1);
    assert_eq!(found.last().map(|b| b.at), Some(16));
}

#[test]
fn a_sequence_quiet_for_less_than_10_s_goes_on() {
    let quiet = BROKEN_AFTER - Duration::from_millis(100);
    let found = timed(&[(b"a\x1b]0;tit", Duration::ZERO), (b"le\x07x\nnext", quiet)]);
    let at: Vec<u64> = found.iter().map(|b| b.at).collect();
    // The BEL ends the title, and each byte after it starts clean.
    assert_eq!(at, [0, 1, 11, 12, 13, 14, 15, 16]);
    assert!(found.iter().all(|b| !b.restart));
}

#[test]
fn text_quiet_for_an_hour_is_not_broken() {
    let found = timed(&[(b"ab", Duration::ZERO), (b"cd", Duration::from_secs(3600))]);
    assert_eq!(found.iter().map(|b| b.at).collect::<Vec<_>>(), [0, 1, 2, 3]);
    assert!(found.iter().all(|b| !b.restart));
}

#[test]
fn a_broken_sequence_starts_again_at_a_full_repaint() {
    for repaint in REPAINTS {
        let mut after = b"junk\x1b[2K\x1b".to_vec();
        after.extend_from_slice(repaint);
        after.extend_from_slice(b"hi");
        let found = timed(&[(b"\x1b[38;5", Duration::ZERO), (&after, BROKEN_AFTER + Duration::from_secs(1))]);
        // The repaint's ESC is the 6 bytes of the first chunk, `junk`, and
        // `ESC [ 2 K`, which is no repaint, in.
        let esc = 6 + 4 + 4;
        assert_eq!(found[0], Boundary { at: 0, restart: false });
        assert_eq!(found[1], Boundary { at: esc, restart: true }, "ESC {}", String::from_utf8_lossy(repaint));
        let end = esc + 1 + repaint.len() as u64;
        assert_eq!(found[2..].iter().map(|b| b.at).collect::<Vec<_>>(), [end, end + 1]);
    }
}

#[test]
fn a_broken_utf8_character_breaks_too() {
    // The euro sign waits 10 s for its last byte, which then means nothing.
    let found = timed(&[(b"a\xe2\x82", Duration::ZERO), (b"\xacb\nc", BROKEN_AFTER)]);
    let plain = |at| Boundary { at, restart: false };
    assert_eq!(found, [plain(0), plain(1), Boundary { at: 6, restart: true }]);
}
