//! The user's lines (T-099), read from stdin, or from the file of
//! `--sendfile`, by a thread of their own, so that a conversation never waits
//! on a read. While no peer takes them, at most 1000 lines or 1 MiB wait in
//! memory; the reader then reads no more until some went, and says so.
//! Nothing goes to disk.

use std::collections::VecDeque;
use std::io::{BufRead, Read};
use std::sync::{Arc, Condvar, Mutex};

use podssh_core::chat::record::MAX_TEXT;
use tokio::sync::mpsc;

use super::input::{self, Act};

/// The lines that may wait for a peer.
pub const MAX_LINES: usize = 1000;
/// The bytes of the lines that may wait for a peer.
pub const MAX_BYTES: usize = 1 << 20;

/// The lines that wait and their bytes, and the reader's wake-up when some
/// went.
#[derive(Default)]
struct Room {
    held: Mutex<(usize, usize)>,
    freed: Condvar,
}

impl Room {
    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, usize)> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait until one more line of `n` bytes fits; `full` is called once when
    /// it does not. One line always fits once nothing waits.
    fn take(&self, n: usize, full: &dyn Fn()) {
        let mut held = self.lock();
        let mut said = false;
        while held.0 > 0 && (held.0 >= MAX_LINES || held.1 + n > MAX_BYTES) {
            if !said {
                full();
                said = true;
            }
            held = self.freed.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        held.0 += 1;
        held.1 += n;
    }

    /// A line of `n` bytes went.
    fn give(&self, n: usize) {
        let mut held = self.lock();
        held.0 = held.0.saturating_sub(1);
        held.1 = held.1.saturating_sub(n);
        self.freed.notify_all();
    }
}

/// The user's lines, as the conversations take them.
pub struct Lines {
    rx: mpsc::Receiver<String>,
    room: Arc<Room>,
    /// Lines taken while no peer was there, first for the next one.
    front: VecDeque<String>,
}

impl Lines {
    /// The lines of `input`, read by a thread of their own; `say` gets the
    /// line that says the reader waits for room.
    pub fn read(input: impl Read + Send + 'static, say: impl Fn(String) + Send + 'static) -> std::io::Result<Lines> {
        let (tx, rx) = mpsc::channel(MAX_LINES);
        let room = Arc::new(Room::default());
        let theirs = room.clone();
        std::thread::Builder::new()
            .name("podssh-chat-input".into())
            .spawn(move || read_lines(std::io::BufReader::new(input), &tx, &theirs, &say))?;
        Ok(Lines { rx, room, front: VecDeque::new() })
    }

    /// No lines: `--send` and `--file` read no input.
    pub fn none() -> Lines {
        let (_, rx) = mpsc::channel(1);
        Lines { rx, room: Arc::default(), front: VecDeque::new() }
    }

    /// Lines that the caller sends itself, with no bound of their own.
    pub fn channel(capacity: usize) -> (mpsc::Sender<String>, Lines) {
        let (tx, rx) = mpsc::channel(capacity);
        (tx, Lines { rx, room: Arc::default(), front: VecDeque::new() })
    }

    /// The next line; `None` once the input ended and each line went.
    pub async fn recv(&mut self) -> Option<String> {
        let line = match self.front.pop_front() {
            Some(line) => line,
            None => self.rx.recv().await?,
        };
        self.room.give(line.len());
        Some(line)
    }

    /// While no peer is there: each line that comes waits for the next peer,
    /// and this returns once the user typed `/quit`, which acts at once.
    pub async fn until_quit(&mut self) {
        loop {
            match self.rx.recv().await {
                Some(line) if input::parse(&line) == Ok(Act::Quit) => {
                    self.room.give(line.len());
                    return;
                }
                // Its room stays taken: the line still waits.
                Some(line) => self.front.push_back(line),
                None => std::future::pending().await,
            }
        }
    }

    /// Whether the input ended and no line waits.
    pub fn done(&self) -> bool {
        self.front.is_empty() && self.rx.is_closed() && self.rx.is_empty()
    }

    /// The lines that wait, taken: at the end of a run, they went to no one.
    pub fn left(&mut self) -> Vec<String> {
        let mut left: Vec<String> = self.front.drain(..).collect();
        while let Ok(line) = self.rx.try_recv() {
            left.push(line);
        }
        for line in &left {
            self.room.give(line.len());
        }
        left
    }
}

/// Read each line of `input` into `tx` until its end, or until nobody takes
/// lines. A line past the limit of a message keeps one byte more than the
/// limit, so that the conversation refuses it whole, and its rest is read
/// and dropped.
fn read_lines<R: BufRead>(mut input: R, tx: &mpsc::Sender<String>, room: &Room, say: &dyn Fn(String)) {
    let limit = MAX_TEXT as u64 + 2;
    let full =
        || say(format!("{MAX_LINES} lines or 1 MiB wait for the peer: podssh reads no more input until some go"));
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = match (&mut input).take(limit).read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                say(format!("the input could not be read: {e}"));
                return;
            }
        };
        if n == 0 {
            return;
        }
        if buf.last() != Some(&b'\n') && n as u64 == limit && input.skip_until(b'\n').is_err() {
            return;
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        let line = String::from_utf8_lossy(&buf).into_owned();
        room.take(line.len(), &full);
        if tx.blocking_send(line).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap()
    }

    fn all(text: &[u8]) -> Vec<String> {
        let mut lines = Lines::read(std::io::Cursor::new(text.to_vec()), |_| {}).unwrap();
        runtime().block_on(async {
            let mut got = Vec::new();
            while let Some(line) = lines.recv().await {
                got.push(line);
            }
            got
        })
    }

    #[test]
    fn each_line_comes_without_its_end() {
        assert_eq!(all(b"one\r\ntwo\n\nthree"), ["one", "two", "", "three"]);
    }

    #[test]
    fn a_line_past_the_limit_is_cut_one_byte_past_it_and_its_rest_dropped() {
        let mut text = vec![b'a'; MAX_TEXT + 100];
        text.extend_from_slice(b"\nnext\n");
        let got = all(&text);
        assert_eq!(got.len(), 2, "{:?}", got.iter().map(String::len).collect::<Vec<_>>());
        assert!(got[0].len() > MAX_TEXT, "the conversation refuses it as too long");
        assert_eq!(got[1], "next");
    }

    /// The reader stops at 1000 lines that wait, and says so once; a line
    /// taken lets it read on.
    #[test]
    fn at_most_a_thousand_lines_wait() {
        let text: Vec<u8> = (0..MAX_LINES + 5).flat_map(|i| format!("{i}\n").into_bytes()).collect();
        let said = Arc::new(Mutex::new(0));
        let counted = said.clone();
        let mut lines = Lines::read(std::io::Cursor::new(text), move |_| *counted.lock().unwrap() += 1).unwrap();
        runtime().block_on(async {
            while *said.lock().unwrap() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert_eq!(lines.room.lock().0, MAX_LINES);
            let mut got = 0;
            while lines.recv().await.is_some() {
                got += 1;
            }
            assert_eq!(got, MAX_LINES + 5);
        });
        assert!(*said.lock().unwrap() >= 1);
    }

    #[test]
    fn the_reader_waits_once_a_mebibyte_waits() {
        let room = Room::default();
        room.take(MAX_BYTES - 10, &|| panic!("it fits"));
        let said = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| room.take(100, &|| said.store(true, std::sync::atomic::Ordering::SeqCst)));
            while !said.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::yield_now();
            }
            room.give(MAX_BYTES - 10);
        });
        assert_eq!(*room.lock(), (1, 100));
    }

    /// While no peer is there, `/quit` acts at once, and the other lines wait
    /// for the next peer, in their order.
    #[test]
    fn quit_acts_at_once_and_the_other_lines_wait() {
        let (tx, mut lines) = Lines::channel(8);
        runtime().block_on(async {
            for line in ["first", "/file x", "/quit", "after"] {
                tx.send(line.to_string()).await.unwrap();
            }
            lines.until_quit().await;
            drop(tx);
            let mut got = Vec::new();
            while let Some(line) = lines.recv().await {
                got.push(line);
            }
            assert_eq!(got, ["first", "/file x", "after"]);
        });
    }
}
