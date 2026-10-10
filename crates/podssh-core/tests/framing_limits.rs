//! One bad line never costs another (T-096). The reassembler hands out the
//! lines and the losses together, in their order; a line with no end keeps
//! nothing of itself in the buffer; and a line that is not UTF-8 is read as
//! Latin-1, as older networks write it, and marked so.

use podssh_core::irc::framing::{FrameError, Framed, Reassembler, DEFAULT_MAX_LINE};
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Event, Server, Session};

#[test]
fn lines_before_a_bad_line_are_kept() {
    let mut r = Reassembler::with_max_line(64);
    let long = "P".repeat(500);
    let out = r.push(format!("PING :before\r\n{long}\r\nPING :after\r\n").as_bytes());
    assert_eq!(
        out,
        [
            Framed::Line("PING :before".into()),
            Framed::Lost(FrameError::Overlong { bytes: 500, max_line: 64 }),
            Framed::Line("PING :after".into()),
        ]
    );
    // The long line ended with its LF, so nothing of it is left to skip.
    assert!(!r.overflowed());
    assert_eq!(r.push(b"PING :next\r\n"), [Framed::Line("PING :next".into())]);
}

#[test]
fn an_endless_line_keeps_the_buffer_at_the_limit() {
    let mut r = Reassembler::new();
    let chunk = vec![b'x'; 64 * 1024];
    let mut lost = Vec::new();
    for _ in 0..16 {
        for framed in r.push(&chunk) {
            match framed {
                Framed::Lost(e) => lost.push(e),
                other => panic!("an endless line gave {other:?}"),
            }
        }
        assert!(r.pending_len() <= DEFAULT_MAX_LINE, "{} bytes held", r.pending_len());
        assert!(r.overflowed(), "the rest of the line is being skipped");
    }
    // One loss for the one line, reported when it passed the limit.
    assert_eq!(lost.len(), 1, "{lost:?}");
    assert!(matches!(lost[0], FrameError::Overlong { max_line: DEFAULT_MAX_LINE, .. }), "{lost:?}");
    // Its end comes; the next line is whole.
    assert_eq!(r.push(b"xxxx\r\nPING :next\r\n"), [Framed::Line("PING :next".into())]);
    assert!(!r.overflowed());
}

/// A line at the limit, split right after its CR, is still a legal line:
/// the CRLF is counted once.
#[test]
fn a_line_at_the_limit_split_after_its_cr_is_kept() {
    let mut r = Reassembler::with_max_line(64);
    let line = format!("PRIVMSG #c :{}", "x".repeat(64 - 2 - "PRIVMSG #c :".len()));
    assert_eq!(line.len() + 2, 64);
    assert!(r.push(format!("{line}\r").as_bytes()).is_empty());
    assert!(!r.overflowed(), "{} bytes held", r.pending_len());
    assert_eq!(r.push(b"\n"), [Framed::Line(line)]);
}

#[test]
fn latin1_text_is_decoded() {
    let mut r = Reassembler::new();
    assert_eq!(r.push(b"PRIVMSG #c :caf\xe9\r\n"), [Framed::Latin1("PRIVMSG #c :caf\u{e9}".into())]);
    // UTF-8 stays UTF-8.
    assert_eq!(r.push("PRIVMSG #c :café\r\n".as_bytes()), [Framed::Line("PRIVMSG #c :café".into())]);
    // The session reads the line, and says that it was not UTF-8.
    let server = Server {
        host: "irc.example.org".into(),
        port: 6667,
        nick: "alice".into(),
        username: "alice".into(),
        realname: "Alice".into(),
    };
    let mut s = Session::new(server, ReapPolicy::default());
    let (_, events) = s.on_bytes(b":bob!u@h PRIVMSG #c :caf\xe9\r\n");
    assert!(matches!(&events[0], Event::Protocol(note) if note.contains("Latin-1")), "{events:?}");
    assert!(
        matches!(&events[1], Event::Privmsg { text, .. } if text == "caf\u{e9}"),
        "the text keeps its character: {events:?}"
    );
    // A loss is an event too, and the session goes on.
    let long = format!(":bob!u@h PRIVMSG #c :{}\r\n:bob!u@h PRIVMSG #c :after\r\n", "y".repeat(DEFAULT_MAX_LINE));
    let (_, events) = s.on_bytes(long.as_bytes());
    assert!(matches!(&events[0], Event::Protocol(note) if note.contains("limit")), "{events:?}");
    assert!(matches!(&events[1], Event::Privmsg { text, .. } if text == "after"), "{events:?}");
}
