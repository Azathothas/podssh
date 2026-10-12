//! The session's side of ZMODEM (T-148), a module of `tests/zmodem.rs`:
//! the question before anything is written or sent, the temporary name
//! and the rename, a name that is taken, a refusal, a command from the
//! server, Ctrl-C, and a file sent to `rz`.

use std::io::Cursor;
use std::path::PathBuf;
use std::time::Instant;

use podssh_ssh::zmodem::receive::{Receiver, FLAGS};
use podssh_ssh::zmodem::send::Sender;
use podssh_ssh::zmodem::wire;
use podssh_ssh::zmodem::{Act, Ended, Zmodem, CANCEL};

use super::cleanup;
use super::{outgoing, read_header, split, zrinit};

/// A directory of its own for a test, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-zmodem-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// The session's side and a sender of the test, each one's bytes to the
/// other, until both are over: what the terminal showed.
fn exchange(
    z: &mut Zmodem,
    sender: &mut Sender<Cursor<Vec<u8>>>,
    mut to_session: Vec<u8>,
    mut to_sender: Vec<u8>,
    now: Instant,
) -> String {
    let mut screen = Vec::new();
    let mut over = false;
    for _ in 0..100_000 {
        if !to_sender.is_empty() && !over {
            let (bytes, acts) = split(sender.feed(&std::mem::take(&mut to_sender), now));
            to_session.extend(bytes);
            over |= acts.iter().any(|a| matches!(a, Act::End { .. }));
        }
        if sender.streaming() {
            to_session.extend(split(sender.pull(now)).0);
        }
        if !to_session.is_empty() {
            screen.extend(z.output(&std::mem::take(&mut to_session), now));
        }
        let taken = z.take(now);
        screen.extend(taken.screen);
        to_sender.extend(taken.server);
        if over && to_session.is_empty() && !z.busy() {
            break;
        }
    }
    assert!(over && !z.busy(), "the exchange did not end");
    String::from_utf8_lossy(&screen).into_owned()
}

/// With no terminal nothing is watched, so nothing is ever received: a
/// session with no terminal gets no watcher at all.
#[test]
fn with_no_terminal_there_is_no_watcher() {
    assert!(Zmodem::for_session(false).is_none());
}

/// The session's side of `sz`: the question comes first, and nothing goes
/// to the server and nothing is written before the answer; then the file
/// comes into the directory of the answer, under a temporary name, and the
/// rename gives it its name, with no temporary file left.
#[test]
fn the_session_asks_then_receives_into_the_directory_given() {
    let now = Instant::now();
    let dir = scratch("receive");
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let mut z = Zmodem::new();
    let mut start = b"rz\r".to_vec();
    start.extend(wire::hex_header(wire::ZRQINIT, [0; 4]));
    let screen = String::from_utf8_lossy(&z.output(&start, now)).into_owned();
    assert!(screen.starts_with("rz\r") && screen.contains("Receive into"), "{screen:?}");
    assert!(z.take(now).server.is_empty(), "nothing goes before the answer");
    // sz says ZRQINIT again while the question is open: it is dropped.
    assert!(z.output(&wire::hex_header(wire::ZRQINIT, [0; 4]), now).is_empty());
    assert_eq!(std::fs::read_dir(&dir).expect("the directory").count(), 0);
    assert!(z.keys(format!("{}\r", dir.display()).into_bytes(), now).is_empty(), "the keys stay here");
    let header = read_header(&z.take(now).server);
    assert_eq!(header, zrinit());
    let (mut sender, first) = Sender::new(Cursor::new(data.clone()), outgoing("notes.bin", data.len()), &header, now);
    let screen = exchange(&mut z, &mut sender, split(first).0, Vec::new(), now);
    assert_eq!(std::fs::read(dir.join("notes.bin")).expect("the file"), data);
    let names: Vec<_> =
        std::fs::read_dir(&dir).expect("the directory").map(|e| e.expect("an entry").file_name()).collect();
    assert_eq!(names.len(), 1, "no temporary file is left: {names:?}");
    assert!(screen.contains("received ") && screen.contains("(5000 bytes)"), "{screen:?}");
    // The shell's prompt after the end shows again.
    assert_eq!(z.output(b"$ ", now), b"$ ");
}

/// A name that is taken is replaced only after "y": "n" keeps the file and
/// skips the server's (ZSKIP), and the transfer ends with nothing else
/// written.
#[test]
fn a_file_that_exists_is_replaced_only_after_yes() {
    let now = Instant::now();
    let dir = scratch("exists");
    let data = b"the server's".to_vec();
    for (answer, want) in [("n", b"kept here".to_vec()), ("y", data.clone())] {
        std::fs::write(dir.join("notes.bin"), b"kept here").expect("a file");
        let mut z = Zmodem::new();
        z.output(&wire::hex_header(wire::ZRQINIT, [0; 4]), now);
        z.keys(format!("{}\r", dir.display()).into_bytes(), now);
        let header = read_header(&z.take(now).server);
        let (mut sender, first) =
            Sender::new(Cursor::new(data.clone()), outgoing("notes.bin", data.len()), &header, now);
        let screen = String::from_utf8_lossy(&z.output(&split(first).0, now)).into_owned();
        assert!(screen.contains("exists. Replace it? [y/N]"), "{screen:?}");
        assert!(z.take(now).server.is_empty(), "no answer before the user's");
        z.keys(format!("{answer}\r").into_bytes(), now);
        let reply = z.take(now).server;
        exchange(&mut z, &mut sender, Vec::new(), reply, now);
        assert_eq!(std::fs::read(dir.join("notes.bin")).expect("the file"), want, "{answer}");
        assert_eq!(std::fs::read_dir(&dir).expect("the directory").count(), 1, "{answer}");
    }
}

/// A refusal at the question cancels `sz` (8.4) and starts nothing; the
/// session's output shows again.
#[test]
fn a_refusal_cancels_sz_and_receives_nothing() {
    let now = Instant::now();
    let mut z = Zmodem::new();
    z.output(&wire::hex_header(wire::ZRQINIT, [0; 4]), now);
    assert!(z.keys(b"some/dir\x03".to_vec(), now).is_empty());
    assert_eq!(z.take(now).server, CANCEL);
    assert!(!z.busy());
    assert_eq!(z.output(b"$ ", now), b"$ ");
}

/// A command from the server (`sz -c`, ZCOMMAND in ZRQINIT's ZF0) never runs
/// here: the session cancels it, and says so.
#[test]
fn a_command_from_the_server_is_refused() {
    let now = Instant::now();
    let mut z = Zmodem::new();
    let screen = z.output(&wire::hex_header(wire::ZRQINIT, [0, 0, 0, wire::ZCOMMAND]), now);
    assert!(String::from_utf8_lossy(&screen).contains("refuses"), "{screen:?}");
    assert_eq!(z.take(now).server, CANCEL);
    assert!(!z.busy());
}

/// Ctrl-C during a transfer cancels it (8.4), and the temporary file goes:
/// nothing is kept of a file that did not end.
#[test]
fn ctrl_c_in_a_transfer_cancels_it_and_keeps_nothing() {
    let now = Instant::now();
    let dir = scratch("ctrl-c");
    let mut z = Zmodem::new();
    z.output(&wire::hex_header(wire::ZRQINIT, [0; 4]), now);
    z.keys(format!("{}\r", dir.display()).into_bytes(), now);
    let header = read_header(&z.take(now).server);
    let data = vec![7u8; 10_000];
    let (mut sender, first) = Sender::new(Cursor::new(data.clone()), outgoing("big.bin", data.len()), &header, now);
    z.output(&split(first).0, now);
    let zrpos = z.take(now).server;
    assert!(split(sender.feed(&zrpos, now)).1.is_empty());
    let part = split(sender.pull(now)).0;
    z.output(&part[..part.len() / 2], now);
    assert_eq!(std::fs::read_dir(&dir).expect("the directory").count(), 1, "the temporary file");
    assert!(z.keys(b"x\x03".to_vec(), now).is_empty());
    assert_eq!(z.take(now).server, CANCEL);
    assert!(!z.busy());
    assert_eq!(std::fs::read_dir(&dir).expect("the directory").count(), 0, "nothing is kept");
}

/// The session's side of `rz`: its ZRINIT brings a question, the answer
/// names a local file, and the file goes to a receiver of the test whole.
#[test]
fn the_session_asks_then_sends_the_file_named() {
    let now = Instant::now();
    let dir = scratch("send");
    let path = dir.join("up.bin");
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 13) as u8).collect();
    std::fs::write(&path, &data).expect("a file");
    let mut z = Zmodem::new();
    let mut out = b"rz waiting to receive.".to_vec();
    out.extend(wire::hex_header(wire::ZRINIT, [0, 0, 0, FLAGS]));
    let screen = String::from_utf8_lossy(&z.output(&out, now)).into_owned();
    assert!(screen.contains("Send which file?"), "{screen:?}");
    assert!(z.keys(format!("{}\r", path.display()).into_bytes(), now).is_empty());
    // The receiver's ZRINIT went already: the session's start was its.
    let (mut receiver, _) = Receiver::new(now);
    let mut to_receiver = z.take(now).server;
    let (mut written, mut ended, mut screen) = (Vec::new(), None, Vec::new());
    for _ in 0..100_000 {
        let (mut to_session, acts) = split(receiver.feed(&std::mem::take(&mut to_receiver), now));
        for act in acts {
            match act {
                Act::Offer(offer) => {
                    assert_eq!((offer.name.as_str(), offer.size), ("up.bin", Some(3000)));
                    to_session.extend(split(receiver.decide(true, now)).0);
                }
                Act::Write(bytes) => written.extend(bytes),
                Act::End { ended: e, .. } => ended = Some(e),
                _ => {}
            }
        }
        screen.extend(z.output(&to_session, now));
        let taken = z.take(now);
        screen.extend(taken.screen);
        to_receiver.extend(taken.server);
        if ended.is_some() && !z.busy() {
            break;
        }
    }
    assert_eq!(written, data);
    assert_eq!(ended, Some(Ended::Done));
    let screen = String::from_utf8_lossy(&screen);
    assert!(screen.contains("sent up.bin (3000 bytes)"), "{screen:?}");
}
