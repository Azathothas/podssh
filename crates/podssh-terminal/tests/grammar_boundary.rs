//! Where a stream of terminal output may start (T-221), against bytes that
//! real programs wrote and a terminal's parser of another project.
//!
//! The captures in `fixtures/` are what each program wrote for a terminal
//! (`TERM=xterm-256color`), unchanged:
//!
//! - `vi.bin`: vim 9.2 drawing 60 lines of UTF-8 text in 24 rows and 80
//!   columns: the alternate screen, a title by OSC 2, colours, a search,
//!   line numbers and a split, then its exit.
//! - `prompt.bin`: bash 5 run interactive, whose prompt sets the title by
//!   OSC 0 and has colours, with `ls --color=always` and UTF-8 text from
//!   `cat` and `printf`.
//!
//! Both come from Git for Windows (MSYS2), with output to a file. less and
//! top write their screens only to a terminal, so
//! `scripts/capture-terminal.py` captured them in a pty of Linux, in the
//! build image, with busybox's vi: `less.bin`, `top.bin` and `vi-pty.bin`.
//! Each `.bin` file here is read.
//!
//! The oracle is anstyle-parse, vte's state machine: what a terminal does
//! with each byte. A cut is clean when a terminal that starts reading at it
//! does what the terminal that read the whole stream does from there, so
//! that no part of a sequence shows as text.

use std::path::Path;
use std::time::Instant;

use anstyle_parse::{DefaultCharAccumulator, Params, Parser, Perform};
use podssh_terminal::grammar::{Ring, Tracker, BROKEN_AFTER};

/// The captures that must be here.
const NAMED: [&str; 2] = ["prompt.bin", "vi.bin"];
/// How many bytes after a cut the two terminals are compared: far more than
/// the longest sequence of the captures (a title of 26 bytes).
const WINDOW: usize = 256;
/// The cuts of a capture: each offset, or this many spread over a longer one.
const CUTS: usize = 4096;
/// The chunks that the tests push: a pty gives a program's output in
/// pieces, which cut sequences.
const CHUNK: usize = 61;

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures");
    let mut found: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "bin"))
        .map(|path| {
            let name = path.file_name().expect("a file name").to_string_lossy().into_owned();
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (name, bytes)
        })
        .collect();
    found.sort();
    for name in NAMED {
        assert!(found.iter().any(|(n, _)| n == name), "fixtures/{name} is missing");
    }
    found
}

fn fixture(name: &str) -> Vec<u8> {
    fixtures().into_iter().find(|(n, _)| n == name).map(|(_, bytes)| bytes).expect("a named capture")
}

/// What a terminal does, each act with the offset of the byte that made it.
#[derive(Default)]
struct Acts {
    at: u64,
    done: Vec<(u64, String)>,
}

impl Acts {
    fn act(&mut self, what: String) {
        self.done.push((self.at, what));
    }
}

fn numbers(params: &Params) -> Vec<Vec<u16>> {
    params.iter().map(<[u16]>::to_vec).collect()
}

impl Perform for Acts {
    fn print(&mut self, c: char) {
        self.act(format!("print {c:?}"));
    }

    fn execute(&mut self, byte: u8) {
        self.act(format!("execute {byte:#04x}"));
    }

    fn hook(&mut self, params: &Params, intermediates: &[u8], ignore: bool, action: u8) {
        self.act(format!("hook {:?} {intermediates:?} {ignore} {action:#04x}", numbers(params)));
    }

    fn put(&mut self, byte: u8) {
        self.act(format!("put {byte:#04x}"));
    }

    fn unhook(&mut self) {
        self.act("unhook".to_string());
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
        self.act(format!("osc {params:?} {bell_terminated}"));
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], ignore: bool, action: u8) {
        self.act(format!("csi {:?} {intermediates:?} {ignore} {action:#04x}", numbers(params)));
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
        self.act(format!("esc {intermediates:?} {ignore} {byte:#04x}"));
    }
}

/// What a terminal does with `bytes`, the first of which is at `from`.
fn acts(bytes: &[u8], from: u64) -> Vec<(u64, String)> {
    let mut parser = Parser::<DefaultCharAccumulator>::new();
    let mut acts = Acts::default();
    for (i, &b) in bytes.iter().enumerate() {
        acts.at = from + i as u64;
        parser.advance(&mut acts, b);
    }
    acts.done
}

/// Whether a cut before `at` is clean: a terminal that starts there does
/// what the terminal of the whole stream (`whole`) does, over [`WINDOW`]
/// bytes.
fn clean_at(bytes: &[u8], whole: &[(u64, String)], at: usize) -> Result<(), String> {
    let end = (at + WINDOW).min(bytes.len());
    let fresh = acts(&bytes[at..end], at as u64);
    let from = whole.partition_point(|(o, _)| *o < at as u64);
    let to = whole.partition_point(|(o, _)| *o < end as u64);
    let read = &whole[from..to];
    match fresh.iter().zip(read).position(|(a, b)| a != b) {
        None if fresh.len() == read.len() => Ok(()),
        first => {
            let i = first.unwrap_or(fresh.len().min(read.len()));
            Err(format!(
                "a cut at {at}: a terminal that starts there does {:?}, where the whole stream does {:?}",
                fresh.get(i),
                read.get(i)
            ))
        }
    }
}

/// The boundaries that the tracker finds in `bytes`, read in chunks that
/// came at one time.
fn boundaries(bytes: &[u8]) -> Vec<u64> {
    let mut tracker = Tracker::new();
    let now = Instant::now();
    let mut found = Vec::new();
    for chunk in bytes.chunks(CHUNK) {
        tracker.feed(chunk, now, |b| found.push(b.at));
    }
    found
}

fn find(bytes: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    bytes[from..].windows(needle.len()).position(|w| w == needle).map(|i| from + i)
}

#[test]
fn each_boundary_in_each_capture_is_clean() {
    for (name, bytes) in fixtures() {
        let whole = acts(&bytes, 0);
        let found = boundaries(&bytes);
        assert!(found.len() > bytes.len() / 4, "{name}: {} boundaries in {} bytes", found.len(), bytes.len());
        for at in found {
            if let Err(e) = clean_at(&bytes, &whole, at as usize) {
                panic!("{name}: {e}");
            }
        }
    }
}

/// The cuts of the Prove: a ring as small as each cut asks, its first byte
/// kept at a boundary, and a terminal that reads from there showing no part
/// of a sequence as text.
#[test]
fn a_ring_cut_at_each_offset_gives_its_bytes_from_a_clean_boundary() {
    let now = Instant::now();
    for (name, bytes) in fixtures() {
        let whole = acts(&bytes, 0);
        let found = boundaries(&bytes);
        let step = bytes.len().div_ceil(CUTS).max(1);
        for cut in (1..bytes.len()).step_by(step) {
            let capacity = bytes.len() - cut;
            let mut ring = Ring::new(capacity);
            for chunk in bytes.chunks(CHUNK) {
                ring.push(chunk, now);
            }
            assert!(ring.len() <= capacity, "{name}: {} bytes held in a ring of {capacity}", ring.len());
            let first = found.iter().copied().find(|&b| b >= cut as u64);
            match ring.start() {
                Some(start) => {
                    assert!(start >= cut as u64, "{name}: kept from {start}, before the cut at {cut}");
                    if let Err(e) = clean_at(&bytes, &whole, start as usize) {
                        panic!("{name}: {e}");
                    }
                    assert_eq!(ring.kept(), &bytes[start as usize..], "{name}: the bytes kept from {start}");
                }
                None => assert_eq!(first, None, "{name}: a cut at {cut} kept nothing, and {first:?} starts clean"),
            }
        }
    }
}

/// The oracle is no check that passes each cut: a cut inside a title, a
/// CSI or a UTF-8 character of each capture shows a part of it as text.
/// These are the cuts that a tracker which ignored OSC strings or UTF-8
/// continuation bytes would give.
#[test]
fn the_oracle_finds_a_cut_inside_a_sequence_or_a_character() {
    for (name, bytes) in fixtures() {
        let whole = acts(&bytes, 0);
        let inside = [
            find(&bytes, b"\x1b]", 0).map(|i| i + 2),
            find(&bytes, b"\x1b[", 0).map(|i| i + 2),
            bytes.iter().position(|b| (0x80..=0xbf).contains(b)),
        ];
        // top, for one, may write no title and no UTF-8.
        if NAMED.contains(&name.as_str()) {
            assert!(inside.iter().all(Option::is_some), "{name}: no title, CSI or UTF-8 character: {inside:?}");
        }
        for at in inside.into_iter().flatten() {
            assert!(clean_at(&bytes, &whole, at).is_err(), "{name}: a cut at {at} reads as clean");
        }
    }
}

/// A capture whose program fell silent for 10 s inside its title: the bytes
/// up to the next newline mean nothing, and the ring keeps from after it.
#[test]
fn a_capture_cut_by_10_s_of_silence_starts_at_the_next_newline() {
    let bytes = fixture("prompt.bin");
    let whole = acts(&bytes, 0);
    // The second prompt's title, cut after `ESC ] 0 ; de`.
    let title = find(&bytes, b"\x1b]0;", 0).and_then(|first| find(&bytes, b"\x1b]0;", first + 1)).expect("two titles");
    let split = title + 6;
    let newline = find(&bytes, b"\n", split).expect("a newline after the title");
    let bel = find(&bytes, b"\x07", split).expect("the BEL that ends the title");
    let t0 = Instant::now();
    // 5 s of silence break nothing: the BEL ends the title, and the next
    // byte starts clean.
    for (silence, expected) in [(BROKEN_AFTER, newline + 1), (BROKEN_AFTER / 2, bel + 1)] {
        let mut ring = Ring::new(bytes.len() - split - 1);
        ring.push(&bytes[..split], t0);
        ring.push(&bytes[split..], t0 + silence);
        assert_eq!(ring.start(), Some(expected as u64), "after {silence:?} of silence");
        assert_eq!(clean_at(&bytes, &whole, expected), Ok(()));
    }
    assert!(bytes[newline + 1..].starts_with(b"Gr\xc3\xbc"), "the text after the newline");
}

/// The same in vim's capture, which writes no newline until its exit: the
/// ring keeps from its next full repaint, `ESC [ 2 J`.
#[test]
fn a_capture_cut_by_10_s_of_silence_starts_at_the_next_repaint() {
    let bytes = fixture("vi.bin");
    let whole = acts(&bytes, 0);
    // Inside `ESC [ 2 2 ; 0 ; 0 t`, its second sequence.
    let csi = find(&bytes, b"\x1b[22;0;0t", 0).expect("vim saves the title");
    let split = csi + 4;
    let repaint = find(&bytes, b"\x1b[2J", split).expect("a repaint");
    assert_eq!(find(&bytes[..repaint], b"\n", split), None, "no newline before the repaint");
    let t0 = Instant::now();
    let mut ring = Ring::new(bytes.len() - split - 1);
    ring.push(&bytes[..split], t0);
    ring.push(&bytes[split..], t0 + BROKEN_AFTER);
    assert_eq!(ring.start(), Some(repaint as u64));
    assert!(ring.kept().starts_with(b"\x1b[2J"));
    assert_eq!(clean_at(&bytes, &whole, repaint), Ok(()));
}
