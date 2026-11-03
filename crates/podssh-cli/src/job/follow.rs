//! `podssh job log --follow HOST ID` (T-485): a job's output as it comes, on
//! one connection, then its status as the exit. Each call of the far
//! script's `follow` gives the bytes from the offset that this end counted,
//! for 20 s at most, and a call of `state` after it says whether the job
//! ended. The offset is the count of the bytes that came, so that a call
//! that broke goes on where the output stopped, with no byte twice; and a
//! call of 20 s keeps the 30 s of each piece of an answer, so a dead link
//! is found as for each other call. `--jsonl` gives one object for each
//! line of the output, and a last one with the state and the status.

use std::io::{self, Write};
use std::sync::Arc;

use base64::Engine as _;
use podssh_ssh::{Connection, Log, EXIT_FAILURE};
use serde_json::json;

use super::{far, first_line, queue, unexpected};
use crate::ssh::resolve::Resolved;

/// The longest line that `--jsonl` holds before it gives it as it is.
const LINE_MOST: usize = 1 << 20;

/// What a follow gives its reader: the bytes, or with `--jsonl` one object
/// for each line; and the count of the bytes of the call that runs.
pub struct Sink<'a> {
    out: &'a mut dyn Write,
    jsonl: bool,
    /// A line of `--jsonl` whose end has not come.
    line: Vec<u8>,
    /// The bytes of the call that runs, given to the reader.
    pub came: u64,
    /// The reader went away (`| head`): the follow ends.
    pub gone: bool,
}

impl<'a> Sink<'a> {
    pub fn new(out: &'a mut dyn Write, jsonl: bool) -> Sink<'a> {
        Sink { out, jsonl, line: Vec::new(), came: 0, gone: false }
    }

    /// Each whole line of `data` as an object, the rest kept for the next.
    fn lines(&mut self, data: &[u8]) -> io::Result<()> {
        self.line.extend_from_slice(data);
        while let Some(end) = self.line.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.line.drain(..=end).collect();
            self.event(&line_event(&line[..end]))?;
        }
        // A line with no end in sight goes as it is, so that memory stays
        // bounded.
        if self.line.len() > LINE_MOST {
            let line = std::mem::take(&mut self.line);
            self.event(&line_event(&line))?;
        }
        Ok(())
    }

    fn event(&mut self, value: &serde_json::Value) -> io::Result<()> {
        writeln!(self.out, "{value}")?;
        self.out.flush()
    }

    /// The end of the follow: with `--jsonl`, the line that had no end, and
    /// the object of the end, with the state and the status as known.
    pub fn end(&mut self, state: Option<&str>, status: Option<i32>) {
        if !self.jsonl || self.gone {
            let _ = self.out.flush();
            return;
        }
        if !self.line.is_empty() {
            let line = std::mem::take(&mut self.line);
            let _ = self.event(&line_event(&line));
        }
        let _ = self.event(&json!({ "event": "end", "state": state, "status": status }));
    }
}

impl Write for Sink<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.gone {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.came += data.len() as u64;
        let given =
            if self.jsonl { self.lines(data) } else { self.out.write_all(data).and_then(|()| self.out.flush()) };
        if let Err(e) = given {
            self.gone = true;
            return Err(e);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// One line of the output, without its newline: `text` when it is UTF-8,
/// else `base64`, so that no byte changes.
pub fn line_event(bytes: &[u8]) -> serde_json::Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({ "event": "line", "text": text }),
        Err(_) => json!({ "event": "line", "base64": base64::engine::general_purpose::STANDARD.encode(bytes) }),
    }
}

/// Where a follow stands: the offset of the next call (`None` before the
/// first of `--from-end`, which asks for the size of the output then), and
/// the state last read, for the end at a `--timeout`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Place {
    pub from: Option<u64>,
    pub state: Option<String>,
}

/// Follow the job `id` into `sink`, from `place`: the job's status once it
/// ended, 0 when the reader went, 255 for a job that is lost or not there
/// or a host that does not answer. After a connection broke, a new one,
/// [`queue::TRIES`] in a row at most with no answer, as `wait` does.
pub(crate) async fn follow(
    resolved: &Resolved,
    host: &str,
    id: &str,
    sink: &mut Sink<'_>,
    place: &mut Place,
    log: &Arc<Log>,
) -> i32 {
    let (mut tries, mut reached) = (0u32, false);
    loop {
        if let Some(handles) = far::connect(resolved, log).await {
            reached = true;
            let handle = handles.last().expect("the destination's connection");
            let end = watch(handle, host, id, sink, place, log, &mut tries).await;
            podssh_ssh::run::disconnect_all(&handles).await;
            if let Some(code) = end {
                return code;
            }
        }
        // A host that never answered is a failure at once; its words are
        // said already.
        if !reached {
            return EXIT_FAILURE;
        }
        tries += 1;
        if tries > queue::TRIES {
            log.error(&format!(
                "job {id} on {host}: no answer after {} new connections; the job may still run",
                queue::TRIES
            ));
            return EXIT_FAILURE;
        }
        let pause = podssh_relay::open::backoff(tries);
        log.info(&format!("a new connection to {host} in {:.1} s ({tries} of {})", pause.as_secs_f64(), queue::TRIES));
        tokio::time::sleep(pause).await;
    }
}

/// Calls of `follow`, then of `state`, over `handle` until the job ends:
/// `Some(exit code)`; `None` when a call broke, for a new connection.
async fn watch(
    handle: &Connection,
    host: &str,
    id: &str,
    sink: &mut Sink<'_>,
    place: &mut Place,
    log: &Log,
    tries: &mut u32,
) -> Option<i32> {
    loop {
        let from = place.from.map_or_else(|| "end".to_string(), |n| n.to_string());
        let mut start = None;
        sink.came = 0;
        let words = ["follow", id, from.as_str()];
        let called = far::stream(handle, host, &words, "out", &mut *sink, true, &mut start).await;
        if sink.gone {
            return Some(0);
        }
        // The far end says where the bytes of this call began; each byte
        // that came is counted, also of a call that broke.
        match start.as_deref().map(|s| s.trim().parse::<u64>()) {
            Some(Ok(at)) => {
                place.from = Some(at + sink.came);
                log.verbose(&format!("job {id} on {host}: {} bytes from {at}", sink.came));
            }
            Some(Err(_)) => {
                log.error(&unexpected(host, &format!("out {}", start.as_deref().unwrap_or(""))));
                return Some(EXIT_FAILURE);
            }
            None => {}
        }
        match called {
            Ok(far::Streamed::Out) => {}
            Ok(far::Streamed::Other(line)) => {
                log.error(&far::refusal(host, &line).unwrap_or_else(|| unexpected(host, &line)));
                return Some(EXIT_FAILURE);
            }
            Err(why) => {
                log.info(&why);
                return None;
            }
        }
        *tries = 0;
        let lines = match far::lines(handle, host, &["state", id]).await {
            Ok(lines) => lines,
            Err(why) => {
                log.info(&why);
                return None;
            }
        };
        let first = match first_line(host, &lines) {
            Ok(first) => first,
            Err(why) => {
                log.error(&why);
                return Some(EXIT_FAILURE);
            }
        };
        let Some((state, status)) = queue::parse_state(first) else {
            log.error(&unexpected(host, first));
            return Some(EXIT_FAILURE);
        };
        place.state = Some(state.clone());
        match (state.as_str(), status) {
            ("done", Some(code)) => {
                sink.end(Some("done"), Some(code));
                return Some(code.clamp(0, 255));
            }
            ("lost", _) => {
                sink.end(Some("lost"), None);
                log.error(&format!(
                    "job {id} on {host} is lost: neither its runner nor its status is there, as after a restart \
                     of the host"
                ));
                return Some(EXIT_FAILURE);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes go through as they come, and each is counted.
    #[test]
    fn the_bytes_go_through_and_are_counted() {
        let mut out = Vec::new();
        let mut sink = Sink::new(&mut out, false);
        sink.write_all(b"tick 1\ntick").unwrap();
        sink.write_all(b" 2\n").unwrap();
        assert_eq!(sink.came, 14);
        sink.end(Some("done"), Some(3));
        assert_eq!(out, b"tick 1\ntick 2\n", "no end object without --jsonl");
    }

    /// `--jsonl`: one object for each whole line, a line cut between two
    /// pieces given once whole, bytes that are not UTF-8 as base64, and the
    /// end with what had no newline and the state and the status.
    #[test]
    fn jsonl_gives_each_line_once_whole_then_the_end() {
        let mut out = Vec::new();
        let mut sink = Sink::new(&mut out, true);
        sink.write_all(b"a\nb").unwrap();
        sink.write_all(b"c\n\xff\xfe\nlast").unwrap();
        sink.end(Some("done"), Some(3));
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 5, "{text}");
        assert_eq!(lines[0], json!({ "event": "line", "text": "a" }));
        assert_eq!(lines[1], json!({ "event": "line", "text": "bc" }));
        assert_eq!(lines[2], json!({ "event": "line", "base64": "//4=" }));
        assert_eq!(lines[3], json!({ "event": "line", "text": "last" }));
        assert_eq!(lines[4], json!({ "event": "end", "state": "done", "status": 3 }));
    }

    /// A reader that went ends the follow: the sink says so, and refuses
    /// the bytes after.
    #[test]
    fn a_reader_that_went_is_said_once() {
        struct Gone;
        impl Write for Gone {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut gone = Gone;
        let mut sink = Sink::new(&mut gone, false);
        assert!(sink.write_all(b"x").is_err());
        assert!(sink.gone);
        assert!(sink.write_all(b"y").is_err());
        assert_eq!(sink.came, 1, "the bytes after are not counted");
    }
}
