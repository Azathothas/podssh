//! Properties of the IRC line framing (T-202, with T-096), each checked on
//! the inputs that proptest makes, 256 by default, and shrunk to the
//! smallest that fails: the lines of a stream cut into frames at any points
//! are the lines of the whole stream; a stream of lines within the limit
//! loses none; and the bytes held for a line with no end stay under the
//! limit after each frame.
//!
//! What a stream loses is the same line wherever it is cut; how much of it
//! a loss names depends on the cut (T-198), so the losses are not compared.
//!
//! A property that fails writes its input to
//! `tests/properties.proptest-regressions`, committed with the repair:
//! proptest tries those inputs first at each run.

use podssh_core::irc::framing::{Framed, Reassembler};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::FileFailurePersistence;

/// A small limit, so that lines past it cost little to make.
const MAX_LINE: usize = 64;

/// proptest's settings, 256 inputs unless `PROPTEST_CASES` says otherwise,
/// and a failing input kept beside this file.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    }
}

/// A stream of lines, each ended by CR LF or a bare LF: lines of any bytes
/// but LF up to `longest`, and, when `over`, now and then a line near and
/// past the limit; and a last line with no end, or none.
fn stream(longest: usize, over: bool) -> impl Strategy<Value = Vec<u8>> {
    let short = vec(any::<u8>().prop_filter("no LF", |b| *b != b'\n'), 0..=longest);
    let long = (MAX_LINE - 4..MAX_LINE + 8).prop_map(|n| vec![b'a'; n]);
    let line = if over { prop_oneof![8 => short, 1 => long].boxed() } else { short.boxed() };
    let end = prop::sample::select(vec![&b"\r\n"[..], &b"\n"[..]]);
    let rest = vec(any::<u8>().prop_filter("no LF", |b| *b != b'\n'), 0..8);
    (vec((line, end), 0..12), rest).prop_map(|(lines, rest)| {
        let mut out = Vec::new();
        for (line, end) in lines {
            out.extend(line);
            out.extend_from_slice(end);
        }
        out.extend(rest);
        out
    })
}

/// `bytes` cut at `cuts`, each taken modulo its length plus one.
fn pieces<'a>(bytes: &'a [u8], cuts: &[Index]) -> Vec<&'a [u8]> {
    let mut at: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
    at.extend([0, bytes.len()]);
    at.sort_unstable();
    at.dedup();
    at.windows(2).map(|pair| &bytes[pair[0]..pair[1]]).collect()
}

/// The lines that came out of `frames`, losses left out, and whether any
/// line was lost; the bytes held after each frame stay under the limit.
fn lines(frames: &[&[u8]]) -> Result<(Vec<Framed>, bool), TestCaseError> {
    let mut r = Reassembler::with_max_line(MAX_LINE);
    let (mut out, mut lost) = (Vec::new(), false);
    for frame in frames {
        for framed in r.push(frame) {
            match framed {
                Framed::Lost(_) => lost = true,
                line => out.push(line),
            }
        }
        prop_assert!(r.pending_len() < MAX_LINE, "{} bytes held after {:?}", r.pending_len(), frames);
    }
    Ok((out, lost))
}

proptest! {
    #![proptest_config(config())]

    /// The lines of a stream cut at any points are the lines of the whole
    /// stream, lines past the limit among them.
    #[test]
    fn a_stream_cut_anywhere_gives_the_same_lines(bytes in stream(40, true), cuts in vec(any::<Index>(), 0..10)) {
        let (whole, _) = lines(&[bytes.as_slice()])?;
        let (cut, _) = lines(&pieces(&bytes, &cuts))?;
        prop_assert_eq!(cut, whole);
    }

    /// A stream whose lines are within the limit loses none, wherever it is
    /// cut, and gives the same lines.
    #[test]
    fn a_stream_of_lines_within_the_limit_loses_none(
        bytes in stream(MAX_LINE - 2, false),
        cuts in vec(any::<Index>(), 0..10),
    ) {
        let (whole, lost) = lines(&[bytes.as_slice()])?;
        prop_assert!(!lost, "{:?}", bytes);
        let (cut, lost) = lines(&pieces(&bytes, &cuts))?;
        prop_assert!(!lost, "{:?}", bytes);
        prop_assert_eq!(cut, whole);
    }

    /// Bytes of a peer, any of them and cut anywhere, never make the
    /// reassembler hold the limit or more.
    #[test]
    fn any_bytes_cut_anywhere_stay_under_the_limit(bytes in vec(any::<u8>(), 0..400), cuts in vec(any::<Index>(), 0..10)) {
        lines(&pieces(&bytes, &cuts))?;
    }
}
