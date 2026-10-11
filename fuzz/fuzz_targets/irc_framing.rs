//! The lines of an IRC stream (`podssh_core::irc::framing::Reassembler`), as
//! the relay hands its frames over: the same bytes in one frame or split
//! anywhere into two give the same lines and the same losses, and no line is
//! longer than the limit (T-096).
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_core::irc::framing::{Framed, Reassembler};

const MAX_LINE: usize = 64;

/// What `frames`, pushed in turn, became: each line, and each loss as a
/// loss. How many bytes a loss had seen when it was dropped depends on where
/// the frames were cut, so that count is not compared.
fn run(frames: &[&[u8]]) -> Vec<Option<Framed>> {
    let mut reassembler = Reassembler::with_max_line(MAX_LINE);
    frames
        .iter()
        .flat_map(|frame| reassembler.push(frame))
        .map(|framed| match framed {
            Framed::Lost(_) => None,
            line => Some(line),
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, input)) = data.split_first() else { return };
    let whole = run(&[input]);
    for framed in whole.iter().flatten() {
        // A Latin-1 line is one character for each byte that came, and two
        // bytes of UTF-8 for each above 0x7f.
        let came = match framed {
            Framed::Line(line) => line.len(),
            Framed::Latin1(line) => line.chars().count(),
            Framed::Lost(_) => 0,
        };
        assert!(came <= MAX_LINE, "{came} bytes: {framed:?}");
    }
    let (a, b) = input.split_at(usize::from(cut).min(input.len()));
    assert_eq!(run(&[a, b]), whole, "split at {}", a.len());
});
