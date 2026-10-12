//! The acts of the protocol in a session: the bytes for the server, an
//! offer and its file, the bytes of the file, its end, and the end of the
//! transfer; and the line of progress.

use std::time::{Duration, Instant};

use super::super::files::{self, Incoming};
use super::super::receive::Offer;
use super::super::{Act, Ended};
use super::{About, Mode, Zmodem};

impl Zmodem {
    /// The acts of the protocol, in order.
    pub(super) fn run(&mut self, acts: Vec<Act>, now: Instant) {
        for act in acts {
            match act {
                Act::Send(bytes) => self.server.extend(bytes),
                Act::Offer(offer) => self.offered(offer, now),
                Act::Write(data) => self.write(&data, now),
                Act::Close(length) => self.closed(length),
                Act::Skipped => {
                    let name = match &self.mode {
                        Mode::Send(s) => shown(&s.name),
                        _ => String::new(),
                    };
                    self.say(&format!("rz on the server skipped {name}: a file of that name may be there"));
                }
                Act::Progress(done) => self.gauge.show(done, now, &mut self.screen),
                Act::End { ended, rest } => {
                    self.ended(ended);
                    self.screen.extend(rest);
                }
            }
        }
    }

    pub(super) fn offered(&mut self, offer: Offer, now: Instant) {
        let name = match files::check_name(&offer.name) {
            Ok(name) => name,
            Err(why) => {
                self.say(&format!("skipped a file: {why}"));
                self.decide(false, now);
                return;
            }
        };
        if offer.size.is_some_and(|size| size > u64::from(u32::MAX)) {
            self.say(&format!("skipped {}: ZMODEM carries files under 4 GiB", shown(&name)));
            self.decide(false, now);
            return;
        }
        let dest = self.dir.join(&name);
        match std::fs::symlink_metadata(&dest) {
            Ok(meta) if meta.is_dir() => {
                self.say(&format!("skipped {}: {} is a directory", shown(&name), dest.display()));
                self.decide(false, now);
            }
            Ok(_) => {
                let question = format!("{} exists. Replace it? [y/N] ", shown(&dest.display().to_string()));
                self.ask(question, About::Replace(offer, name));
            }
            Err(_) => self.open(offer, name, false, now),
        }
    }

    pub(super) fn open(&mut self, offer: Offer, name: String, replace: bool, now: Instant) {
        match Incoming::create(&self.dir, &name, &offer, replace) {
            Ok(file) => {
                if let Mode::Receive(r) = &mut self.mode {
                    r.file = Some(file);
                }
                self.gauge.start(&name, offer.size);
                self.decide(true, now);
            }
            Err(e) => {
                self.say(&format!("skipped {}: {e}", shown(&name)));
                self.decide(false, now);
            }
        }
    }

    pub(super) fn decide(&mut self, take: bool, now: Instant) {
        let acts = match &mut self.mode {
            Mode::Receive(r) => r.proto.decide(take, now),
            _ => return,
        };
        self.run(acts, now);
    }

    pub(super) fn write(&mut self, data: &[u8], now: Instant) {
        let written = match &mut self.mode {
            Mode::Receive(r) => r.file.as_mut().map_or(Ok(()), |file| file.write(data)),
            _ => return,
        };
        if let Err(e) = written {
            self.cancel(&format!("the file could not be written: {e}"), now);
        }
    }

    pub(super) fn closed(&mut self, length: u64) {
        let message = match &mut self.mode {
            Mode::Receive(r) => match r.file.take() {
                Some(mut file) => match file.finish(length) {
                    Ok(path) => format!("received {} ({length} bytes)", shown(&path.display().to_string())),
                    Err(why) => shown(&why),
                },
                None => return,
            },
            Mode::Send(s) => format!("sent {} ({length} bytes)", shown(&s.name)),
            _ => return,
        };
        self.gauge.stop();
        self.say(&message);
    }

    pub(super) fn cancel(&mut self, why: &str, now: Instant) {
        let acts = match &mut self.mode {
            Mode::Receive(r) => r.proto.cancel(why),
            Mode::Send(s) => s.proto.cancel(why),
            Mode::Idle | Mode::Armed { .. } => return,
        };
        self.run(acts, now);
    }

    pub(super) fn ended(&mut self, ended: Ended) {
        self.gauge.stop();
        let mode = std::mem::replace(&mut self.mode, Mode::Idle);
        let unfinished = match &mode {
            Mode::Receive(r) => r.file.as_ref().map(|file| shown(&file.name)),
            _ => None,
        };
        // A file that did not end is removed with it.
        drop(mode);
        if let Some(name) = unfinished {
            self.say(&format!("{name}: the transfer ended before the end of the file, and nothing was kept"));
        }
        if let Ended::Stopped(why) = ended {
            self.say(&format!("ZMODEM: {why}"));
        }
    }
}

/// How often the line of progress changes at most.
const EVERY: Duration = Duration::from_millis(250);

/// The line of a transfer's progress, rewritten in place.
#[derive(Debug, Default)]
pub(super) struct Gauge {
    name: Option<String>,
    size: Option<u64>,
    last: Option<Instant>,
}

impl Gauge {
    pub(super) fn start(&mut self, name: &str, size: Option<u64>) {
        self.name = Some(shown(name));
        self.size = size;
        self.last = None;
    }

    pub(super) fn stop(&mut self) {
        self.name = None;
    }

    pub(super) fn show(&mut self, done: u64, now: Instant, screen: &mut Vec<u8>) {
        let Some(name) = &self.name else { return };
        if self.last.is_some_and(|at| now.duration_since(at) < EVERY) {
            return;
        }
        self.last = Some(now);
        let line = match self.size {
            Some(size) if size > 0 => format!("{name}: {done} of {size} bytes ({}%)", done.min(size) * 100 / size),
            _ => format!("{name}: {done} bytes"),
        };
        screen.extend_from_slice(format!("\r\x1b[K{line}").as_bytes());
    }
}

/// A name from the server, or a path, made safe to print.
pub(super) fn shown(text: &str) -> String {
    podssh_ws::text::one_line(text)
}

pub(super) fn yes(answer: &str) -> bool {
    matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes")
}
