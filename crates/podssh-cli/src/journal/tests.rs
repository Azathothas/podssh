//! The tests of the journal's copy (T-640): the priority of each level, the
//! bytes of an entry, the variable, and, on Linux, the probe and the copy
//! against a datagram socket of the test in a scratch directory, which reads
//! as the journal's own would; and the copy of the SSH client's lines
//! (T-674).

use super::*;
use std::cell::RefCell;

thread_local! {
    /// A test's sink for the copies of the SSH client's lines on its own
    /// thread: the binary's sink is never installed in a test, and the other
    /// tests' lines, on their threads, never reach it.
    static TEST_SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Whether a test's sink on this thread took the copy.
pub(super) fn to_test_sink(priority: u8, text: &str) -> bool {
    TEST_SINK.with(|sink| match sink.borrow().as_ref() {
        Some(sink) => {
            to_sink(sink, priority, text);
            true
        }
        None => false,
    })
}

#[test]
fn priority_of_each_level_follows_the_journal() {
    let cases = [
        (LogLevel::Fatal, 2),
        (LogLevel::Error, 3),
        (LogLevel::Quiet, 6),
        (LogLevel::Info, 6),
        (LogLevel::Verbose, 7),
        (LogLevel::Debug1, 7),
        (LogLevel::Debug2, 7),
        (LogLevel::Debug3, 7),
    ];
    for (level, number) in cases {
        assert_eq!(priority(level), number, "{level:?}");
    }
    // Only what says more than the stream's own `info` is copied; a warning
    // of the SSH client's does (T-674).
    assert!(priority(LogLevel::Error) < STREAM && priority(LogLevel::Info) >= STREAM);
    assert!(priority(LogLevel::Error) < WARNING && WARNING < STREAM);
}

#[test]
fn the_priority_comes_first_and_the_message_last() {
    let bytes = entry(3, "podssh node: lab: the pair expired");
    let want: &[u8] = b"PRIORITY=3\nSYSLOG_IDENTIFIER=podssh\nMESSAGE=podssh node: lab: the pair expired\n";
    assert_eq!(bytes, want, "{}", String::from_utf8_lossy(&bytes));
}

/// A refusal of three lines is one entry: the binary form, its length, and
/// nothing after its value but the line break.
#[test]
fn a_message_with_a_line_break_is_one_binary_field() {
    let message = "podssh ssh: -y is refused.\n  Use -E LOGFILE instead.\n  podssh does not write to syslog.";
    let bytes = entry(3, message);
    let head: &[u8] = b"PRIORITY=3\nSYSLOG_IDENTIFIER=podssh\nMESSAGE\n";
    assert!(bytes.starts_with(head), "{}", String::from_utf8_lossy(&bytes));
    let rest = &bytes[head.len()..];
    let length = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
    assert_eq!(length, message.len());
    assert_eq!(&rest[8..8 + length], message.as_bytes());
    assert_eq!(&rest[8 + length..], b"\n", "one entry, and nothing after it");
}

#[test]
fn the_variable_is_a_device_and_an_inode_in_decimal() {
    assert_eq!(stream_of("64:123456"), Some((64, 123_456)));
    for bad in ["", "64", "64:", ":1", "a:1", "1:2:3", "0x40:1", "+1:2", " 1:2", "1:2\n"] {
        assert_eq!(stream_of(bad), None, "{bad:?}");
    }
}

/// With no journal, a line is on `err` as before, and nothing else happens.
#[test]
fn a_line_with_no_journal_reaches_stderr_alone() {
    let mut err = Vec::new();
    line_to(&mut err, None, LogLevel::Error, "podssh node: lab: the pair expired; make a new pair");
    assert_eq!(err, b"podssh node: lab: the pair expired; make a new pair\n");
    // The binary's own sink, never installed in a test.
    let mut err = Vec::new();
    line(&mut err, LogLevel::Fatal, "podssh: a line");
    assert_eq!(err, b"podssh: a line\n");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::sink::{id_of, socket_beside, stream_is, Sink, SOCKET};
    use super::*;
    use std::io::ErrorKind;
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::path::{Path, PathBuf};

    /// A scratch directory and, in it, the journal's socket of the test: it
    /// reads at once what a sink sent, as a local datagram is queued by the
    /// send itself.
    struct Journal {
        dir: PathBuf,
        socket: UnixDatagram,
    }

    impl Journal {
        fn new(name: &str) -> Journal {
            let dir = std::env::temp_dir().join(format!("podssh-journal-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let socket = UnixDatagram::bind(dir.join("socket")).unwrap();
            socket.set_nonblocking(true).unwrap();
            Journal { dir, socket }
        }

        fn path(&self) -> PathBuf {
            self.dir.join("socket")
        }

        /// The next entry, or `None` when nothing came.
        fn read(&self) -> Option<Vec<u8>> {
            let mut buf = vec![0; 1 << 16];
            match self.socket.recv(&mut buf) {
                Ok(n) => Some(buf[..n].to_vec()),
                Err(e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => panic!("the test's journal: {e}"),
            }
        }
    }

    impl Drop for Journal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A stream that stands for stderr, and a sink whose stderr is it.
    fn sink_on(journal: &Journal) -> (Sink, UnixStream) {
        let (stderr, peer) = UnixStream::pair().unwrap();
        let stream = id_of(stderr.as_fd()).unwrap();
        let sink = Sink::to(stream, journal.path(), Box::new(move || id_of(stderr.as_fd()))).unwrap();
        (sink, peer)
    }

    /// The variable names this stream, and the probe takes it; a child that
    /// inherited the variable, whose stderr is another stream or a file,
    /// installs nothing, which the variable alone cannot tell.
    #[test]
    fn a_child_that_inherited_the_variable_installs_nothing() {
        let (ours, other) = UnixStream::pair().unwrap();
        let (device, inode) = id_of(ours.as_fd()).unwrap();
        let value = format!("{device}:{inode}");
        assert_eq!(stream_is(&value, ours.as_fd()), Some((device, inode)));
        assert_eq!(stream_is(&value, other.as_fd()), None, "another stream");
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(stream_is(&value, file.as_fd()), None, "a file");
        assert_eq!(stream_is("not a pair", ours.as_fd()), None);
    }

    /// An error line is on `err` and, once, in the journal, at 3.
    #[test]
    fn a_line_reaches_both_stderr_and_the_journal() {
        let journal = Journal::new("both");
        let (sink, _peer) = sink_on(&journal);
        assert!(sink.binds_nothing(), "the sink's socket has an address");
        let text = "podssh node: the relay refused the pair (403): make a new pair";
        let mut err = Vec::new();
        line_to(&mut err, Some(&sink), LogLevel::Error, text);
        assert_eq!(err, format!("{text}\n").into_bytes());
        assert_eq!(journal.read(), Some(entry(3, text)));
        assert_eq!(journal.read(), None, "one entry");
    }

    /// A line at info or below is the stream's alone: a copy would file it
    /// twice.
    #[test]
    fn a_line_at_info_reaches_stderr_alone() {
        let journal = Journal::new("info");
        let (sink, _peer) = sink_on(&journal);
        for level in [LogLevel::Quiet, LogLevel::Info, LogLevel::Verbose, LogLevel::Debug3] {
            let mut err = Vec::new();
            line_to(&mut err, Some(&sink), level, "podssh node: lab: online");
            assert_eq!(err, b"podssh node: lab: online\n", "{level:?}");
        }
        assert_eq!(journal.read(), None);
    }

    /// A journal that went away loses the copy, and the line is on `err`.
    #[test]
    fn a_line_reaches_stderr_alone_when_the_socket_is_gone() {
        let journal = Journal::new("gone");
        let (sink, _peer) = sink_on(&journal);
        drop(journal);
        let mut err = Vec::new();
        line_to(&mut err, Some(&sink), LogLevel::Fatal, "podssh: fatal");
        assert_eq!(err, b"podssh: fatal\n");
        assert!(!sink.say(LogLevel::Fatal, "podssh: fatal"));
    }

    /// A stderr that moved after the start (a detached run's log) gets no
    /// copy.
    #[test]
    fn a_stderr_that_moved_gets_no_copy() {
        let journal = Journal::new("moved");
        let (stderr, _peer) = UnixStream::pair().unwrap();
        let stream = id_of(stderr.as_fd()).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let sink = Sink::to(stream, journal.path(), Box::new(move || id_of(file.as_fd()))).unwrap();
        assert!(!sink.say(LogLevel::Error, "podssh: an error"));
        assert_eq!(journal.read(), None);
    }

    /// `sink` takes the copies of the SSH client's lines on this thread
    /// while the guard lives.
    struct OnThisThread;

    impl OnThisThread {
        fn set(sink: Sink) -> OnThisThread {
            TEST_SINK.with(|on| *on.borrow_mut() = Some(sink));
            OnThisThread
        }
    }

    impl Drop for OnThisThread {
        fn drop(&mut self) {
            TEST_SINK.with(|on| drop(on.borrow_mut().take()));
        }
    }

    /// A warning and an error of the SSH client's log reach the journal at
    /// their priorities, 4 and 3, in stderr's words, through the copy that
    /// `install` gives the log; a line of INFO is the stream's alone
    /// (T-674).
    #[test]
    fn a_warning_of_the_ssh_client_reaches_the_journal_at_its_priority() {
        let journal = Journal::new("client");
        let (sink, _peer) = sink_on(&journal);
        let _on = OnThisThread::set(sink);
        // What `install` gives the log where it found the journal.
        podssh_ssh::log::copy_lines(crate::journal::copy);
        let log = podssh_ssh::Log::new(LogLevel::Info);
        log.warning("Warning: remote port forwarding failed for listen port 2222");
        log.info("Forwarding port.");
        log.error("connect to 127.0.0.1 port 22: Connection refused");
        let warning = "podssh: Warning: remote port forwarding failed for listen port 2222";
        assert_eq!(journal.read(), Some(entry(WARNING, warning)));
        assert_eq!(journal.read(), Some(entry(3, "podssh: connect to 127.0.0.1 port 22: Connection refused")));
        assert_eq!(journal.read(), None, "a line of INFO is the stream's alone");
    }

    /// A log in a file (`-E`) sends nothing, even where stderr is the
    /// journal's stream: its lines are not the stream's.
    #[test]
    fn the_ssh_client_s_log_in_a_file_sends_nothing() {
        let journal = Journal::new("client-file");
        let (sink, _peer) = sink_on(&journal);
        let _on = OnThisThread::set(sink);
        podssh_ssh::log::copy_lines(crate::journal::copy);
        let log = podssh_ssh::Log::to_file(LogLevel::Info, &journal.dir.join("e.log")).unwrap();
        log.warning("Warning: remote port forwarding failed for listen port 2222");
        log.error("connect to 127.0.0.1 port 22: Connection refused");
        assert_eq!(journal.read(), None);
    }

    #[test]
    fn the_socket_is_beside_the_stream_of_the_journal() {
        let beside = |peer: &str| socket_beside(Some(Path::new(peer)));
        assert_eq!(beside("/run/systemd/journal/stdout"), Path::new("/run/systemd/journal/socket"));
        assert_eq!(beside("/run/systemd/journal.lab/stdout"), Path::new("/run/systemd/journal.lab/socket"));
        assert_eq!(beside("/tmp/a-stream"), Path::new(SOCKET));
        assert_eq!(socket_beside(None), Path::new(SOCKET));
    }
}
