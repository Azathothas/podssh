//! Properties of the line discipline (T-202, with T-125 to T-129), each
//! checked on the inputs that proptest makes, 256 by default, and shrunk to
//! the smallest that fails: keys cut into reads at any points give the same
//! events as the keys read one at a time; and after any keys, the cursor is
//! within the line and, with IUTF8, between characters of a line of UTF-8;
//! each line sent ends with its one LF; the history holds no empty line and
//! no repeat of the line before. What the screen shows is the terminal
//! oracle's (`tests/oracle.rs`, T-200).
//!
//! A property that fails writes its input to
//! `tests/properties.proptest-regressions`, committed with the repair:
//! proptest tries those inputs first at each run.

use podssh_terminal::echo::{Discipline, Event, HISTORY_CAP};
use podssh_terminal::session::{Facts, Session};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::FileFailurePersistence;

/// proptest's settings, 256 inputs unless `PROPTEST_CASES` says otherwise,
/// and a failing input kept beside this file.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

/// Keys as a terminal sends them: letters, characters of several bytes and
/// an accent, each editing key in a form a terminal sends, Enter, and a
/// lone Escape. A table: one kind of key to a row (rustfmt::skip).
#[rustfmt::skip]
const KEYS: &[&[u8]] = &[
    b"a", b"b", b" ", b"x", "\u{e9}".as_bytes(), "\u{4e2d}".as_bytes(), "\u{301}".as_bytes(),
    b"\x7f", b"\x08", b"\x15", b"\x17", b"\x01", b"\x05", b"\x04", b"\x03", b"\r", b"\n",
    b"\x1b[D", b"\x1b[C", b"\x1b[A", b"\x1b[B", b"\x1b[H", b"\x1bOF", b"\x1b[3~",
    b"\x1b[5~", b"\x1bOj", b"\x1bOM", b"\x1b",
];

/// Runs of whole keys.
fn keys() -> impl Strategy<Value = Vec<u8>> {
    vec(prop::sample::select(KEYS), 0..80).prop_map(|keys| keys.concat())
}

/// Runs of whole keys, and of any byte among them: a lone byte of a
/// character, a control byte, a byte that starts a sequence.
fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        6 => prop::sample::select(KEYS).prop_map(<[u8]>::to_vec),
        1 => any::<u8>().prop_map(|b| vec![b]),
    ];
    vec(piece, 0..80).prop_map(|pieces| pieces.concat())
}

/// The facts of a session that selected the discipline, with nothing below.
fn selected() -> Facts {
    Facts { selected: true, ..Default::default() }
}

/// `bytes` cut at `cuts`, each taken modulo its length plus one.
fn pieces<'a>(bytes: &'a [u8], cuts: &[Index]) -> Vec<&'a [u8]> {
    let mut at: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
    at.extend([0, bytes.len()]);
    at.sort_unstable();
    at.dedup();
    at.windows(2).map(|pair| &bytes[pair[0]..pair[1]]).collect()
}

/// The events of `reads`, read in turn by a session, until input ends.
fn events_of(reads: &[&[u8]], utf8: bool) -> Vec<Event> {
    let mut session = Session::with_utf8(selected(), utf8);
    let mut out = Vec::new();
    for read in reads {
        if session.ended() {
            break;
        }
        out.extend(session.on_local_bytes(read));
    }
    out
}

proptest! {
    #![proptest_config(config())]

    /// Keys cut into reads at any points give the same events as the
    /// keys read one byte at a time, an end of input included.
    #[test]
    fn keys_cut_anywhere_give_the_same_events(
        bytes in any_bytes(),
        cuts in vec(any::<Index>(), 0..12),
        utf8 in any::<bool>(),
    ) {
        let one_at_a_time: Vec<&[u8]> = bytes.chunks(1).collect();
        prop_assert_eq!(events_of(&pieces(&bytes, &cuts), utf8), events_of(&one_at_a_time, utf8));
    }

    /// After each byte the cursor is within the line; each line sent ends
    /// with its one LF and holds no CR; the history keeps at most its cap,
    /// with no empty line and no line twice in a row.
    #[test]
    fn after_any_bytes_the_line_and_the_history_hold(bytes in any_bytes(), utf8 in any::<bool>()) {
        let mut d = Discipline::with_utf8(utf8);
        for b in &bytes {
            for event in d.key(*b) {
                if let Event::ToRemote(line) = event {
                    prop_assert_eq!(line.last(), Some(&b'\n'), "{:?}", line);
                    prop_assert!(!line[..line.len() - 1].contains(&b'\n') && !line.contains(&b'\r'), "{:?}", line);
                }
            }
            prop_assert!(d.cursor() <= d.line().len(), "the cursor at {} of {:?}", d.cursor(), d.line());
            let history = d.history();
            prop_assert!(history.len() <= HISTORY_CAP);
            prop_assert!(history.iter().all(|h| !h.is_empty()), "{:?}", history);
            prop_assert!(history.windows(2).all(|pair| pair[0] != pair[1]), "{:?}", history);
        }
    }

    /// With IUTF8, after each whole key the line is UTF-8 and the cursor
    /// stands between two of its characters. A lone byte of a character,
    /// which a terminal of UTF-8 never sends alone, is left out.
    #[test]
    fn with_iutf8_the_cursor_stays_between_characters(bytes in keys()) {
        let mut d = Discipline::with_utf8(true);
        for b in &bytes {
            d.key(*b);
            if d.waiting() {
                continue;
            }
            let text = std::str::from_utf8(d.line()).map_err(|e| TestCaseError::fail(format!("{e}: {:?}", d.line())))?;
            prop_assert!(text.is_char_boundary(d.cursor()), "the cursor at {} of {:?}", d.cursor(), text);
        }
    }
}
