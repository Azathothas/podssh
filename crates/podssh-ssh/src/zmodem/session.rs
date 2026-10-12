//! [`Zmodem`]: ZMODEM in a session. It watches the server's output for the
//! start of `sz` or `rz` ([`super::detect`]), asks on the terminal, and then
//! runs one side of the protocol. Meanwhile the transfer's bytes stay off
//! the terminal; a question takes the keys, and during a transfer Ctrl-C
//! stops it and each other key is dropped. The session's pump gives it the
//! output, the keys and the time, and takes what it has for the terminal
//! and for the server.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::ask::{Answer, Question};
use super::detect::{Detector, Start};
use super::files::{self, Incoming};
use super::receive::{Offer, Receiver};
use super::send::Sender;
use super::wire::{self, Header};
use super::{CANCEL, WAIT};

mod acts;

use acts::{shown, yes, Gauge};

/// What the session's pump takes: the bytes for the terminal, in order, and
/// those for the server.
#[derive(Debug, Default)]
pub struct Taken {
    pub screen: Vec<u8>,
    pub server: Vec<u8>,
}

struct Receiving {
    proto: Receiver,
    file: Option<Incoming>,
}

struct Sending {
    proto: Sender<File>,
    name: String,
}

/// What ZMODEM does in the session.
enum Mode {
    Idle,
    /// `~Z` chose a file and typed `rz`; its start is awaited until then.
    Armed {
        path: PathBuf,
        until: Instant,
    },
    Receive(Box<Receiving>),
    Send(Box<Sending>),
}

/// What an open question is about.
enum About {
    /// `sz` started: where the files go.
    Directory,
    /// The offered file's name is taken here: replace it?
    Replace(Offer, String),
    /// `rz` started: the file to send.
    Upload(Header),
    /// `~Z`: the file to send, before `rz` is typed.
    Escape,
}

/// ZMODEM in one session with a pty and a local terminal.
pub struct Zmodem {
    detect: Detector,
    mode: Mode,
    question: Option<(Question, About)>,
    screen: Vec<u8>,
    server: Vec<u8>,
    /// Where files come: the current directory, then the last answer.
    dir: PathBuf,
    gauge: Gauge,
}

impl Default for Zmodem {
    fn default() -> Self {
        Zmodem::new()
    }
}

impl Zmodem {
    /// The watcher of a session: only when it has a pty and a local
    /// terminal, and `PODSSH_ZMODEM` is not `off`. With no terminal nothing
    /// is watched, so nothing is ever received.
    pub fn for_session(terminal: bool) -> Option<Zmodem> {
        let off = std::env::var("PODSSH_ZMODEM").is_ok_and(|v| v.trim().eq_ignore_ascii_case("off"));
        (terminal && !off).then(Zmodem::new)
    }

    /// A watcher, whatever the session: [`Zmodem::for_session`] decides
    /// when there is one.
    pub fn new() -> Zmodem {
        Zmodem {
            detect: Detector::new(),
            mode: Mode::Idle,
            question: None,
            screen: Vec::new(),
            server: Vec::new(),
            dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            gauge: Gauge::default(),
        }
    }

    /// Whether a question is open, a transfer runs, or `rz` is awaited.
    pub fn busy(&self) -> bool {
        self.question.is_some() || !matches!(self.mode, Mode::Idle)
    }

    /// The server's output: what shows on the terminal, in order with
    /// podssh's own words.
    pub fn output(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        // While a question is open, the far side waits; what it sends again
        // meanwhile (its start, once more) is dropped.
        if self.question.is_none() {
            let acts = match &mut self.mode {
                Mode::Receive(r) => Some(r.proto.feed(data, now)),
                Mode::Send(s) => Some(s.proto.feed(data, now)),
                Mode::Idle | Mode::Armed { .. } => None,
            };
            match acts {
                Some(acts) => self.run(acts, now),
                None => self.scan(data, now),
            }
        }
        std::mem::take(&mut self.screen)
    }

    /// Keys: those that go on to the server. A question takes each key; a
    /// transfer drops them, and Ctrl-C stops it.
    pub fn keys(&mut self, keys: Vec<u8>, now: Instant) -> Vec<u8> {
        if let Some((question, _)) = self.question.as_mut() {
            let (echo, answer) = question.keys(&keys);
            self.screen.extend(echo);
            let taken = if answer.is_some() { self.question.take() } else { None };
            if let (Some(answer), Some((_, about))) = (answer, taken) {
                self.answered(about, answer, now);
            }
            return Vec::new();
        }
        if !matches!(self.mode, Mode::Receive(_) | Mode::Send(_)) {
            return keys;
        }
        if keys.contains(&0x03) {
            self.cancel("cancelled here (Ctrl-C)", now);
        }
        Vec::new()
    }

    /// `~Z`: ask for a file, then type `rz` on the server.
    pub fn escape(&mut self) {
        if self.busy() {
            self.say("a ZMODEM transfer runs already");
            return;
        }
        self.ask(ESCAPE_QUESTION.to_string(), About::Escape);
    }

    /// When [`Zmodem::tick`] is due.
    pub fn deadline(&self) -> Option<Instant> {
        let protocol = match &self.mode {
            _ if self.question.is_some() => None,
            Mode::Receive(r) => r.proto.deadline(),
            Mode::Send(s) => s.proto.deadline(),
            Mode::Armed { until, .. } => Some(*until),
            Mode::Idle => None,
        };
        [protocol, self.detect.deadline()].into_iter().flatten().min()
    }

    /// The time: held bytes that were no start show, a wait of the protocol
    /// that ran out acts, and `rz` that did not start is given up.
    pub fn tick(&mut self, now: Instant) {
        let held = self.detect.flush(now);
        self.screen.extend(held);
        if self.question.is_some() {
            return;
        }
        if matches!(&self.mode, Mode::Armed { until, .. } if now >= *until) {
            self.mode = Mode::Idle;
            self.say(&format!("rz did not start on the server within {} s; nothing was sent", WAIT.as_secs()));
            return;
        }
        let acts = match &mut self.mode {
            Mode::Receive(r) => r.proto.timeout(now),
            Mode::Send(s) => s.proto.timeout(now),
            Mode::Idle | Mode::Armed { .. } => return,
        };
        self.run(acts, now);
    }

    /// Whether a sender has more of its file to send now.
    pub fn more(&self) -> bool {
        self.question.is_none() && matches!(&self.mode, Mode::Send(s) if s.proto.streaming())
    }

    /// What waits for the terminal and for the server. A sender's next bytes
    /// are read here, when nothing else waits for the server.
    pub fn take(&mut self, now: Instant) -> Taken {
        if self.server.is_empty() && self.more() {
            let acts = match &mut self.mode {
                Mode::Send(s) => s.proto.pull(now),
                _ => Vec::new(),
            };
            self.run(acts, now);
        }
        Taken { screen: std::mem::take(&mut self.screen), server: std::mem::take(&mut self.server) }
    }

    fn scan(&mut self, data: &[u8], now: Instant) {
        let scan = self.detect.feed(data, now);
        self.screen.extend(scan.shown);
        if let Some(start) = scan.start {
            self.start(start, scan.rest, now);
        }
    }

    fn start(&mut self, start: Start, rest: Vec<u8>, now: Instant) {
        let armed = match std::mem::replace(&mut self.mode, Mode::Idle) {
            Mode::Armed { path, .. } => Some(path),
            _ => None,
        };
        match (start, armed) {
            // `sz -c` sends a command (ZCOMMAND in ZF0): never run here.
            (Start::Offer(header), _) if header.flags() == wire::ZCOMMAND => {
                self.server.extend_from_slice(CANCEL);
                self.say("the server asked to run a command here (sz -c), which podssh refuses");
            }
            (Start::Offer(_), _) => {
                let question = self.directory_question();
                self.ask(question, About::Directory);
            }
            (Start::Ready(header), Some(path)) => {
                self.upload(&path, &header, now);
                // What came after ZRINIT is the receiver's, for the sender.
                let acts = match &mut self.mode {
                    Mode::Send(s) if !rest.is_empty() => s.proto.feed(&rest, now),
                    _ => Vec::new(),
                };
                self.run(acts, now);
            }
            (Start::Ready(header), None) => self.ask(UPLOAD_QUESTION.to_string(), About::Upload(header)),
        }
    }

    fn directory_question(&self) -> String {
        format!(
            "the server sends by ZMODEM (sz). Receive into {}? Enter takes it, a path changes it, Ctrl-C refuses: ",
            self.dir.display()
        )
    }

    fn ask(&mut self, prompt: String, about: About) {
        let (question, bytes) = Question::new(&format!("podssh: {prompt}"));
        self.screen.extend(bytes);
        self.question = Some((question, about));
    }

    fn say(&mut self, text: &str) {
        self.screen.extend_from_slice(format!("\r\x1b[Kpodssh: {text}\r\n").as_bytes());
    }

    fn answered(&mut self, about: About, answer: Answer, now: Instant) {
        let line = match answer {
            Answer::Line(line) => Some(line),
            Answer::Refused => None,
        };
        match about {
            About::Directory => self.receive_into(line, now),
            About::Replace(offer, name) => {
                if line.is_some_and(|l| yes(&l)) {
                    self.open(offer, name, true, now);
                } else {
                    self.say(&format!("kept {}; the server's file was skipped", shown(&name)));
                    self.decide(false, now);
                }
            }
            About::Upload(header) => match line.filter(|l| !l.is_empty()).map(|l| typed_path(&l)) {
                Some(path) => match files::open(&path) {
                    Ok(_) => self.upload(&path, &header, now),
                    Err(why) => {
                        self.say(&why);
                        self.ask(UPLOAD_QUESTION.to_string(), About::Upload(header));
                    }
                },
                None => {
                    self.server.extend_from_slice(CANCEL);
                    self.say("nothing was sent, and rz on the server was cancelled");
                }
            },
            About::Escape => {
                let Some(path) = line.filter(|l| !l.is_empty()).map(|l| typed_path(&l)) else { return };
                match files::open(&path) {
                    Ok(_) => {
                        // "The sending program may send the string "rz\r" to
                        // invoke the receiving program from a possible command
                        // mode" (8.1).
                        self.server.extend_from_slice(b"rz\r");
                        self.mode = Mode::Armed { path, until: now + WAIT };
                    }
                    Err(why) => {
                        self.say(&why);
                        self.ask(ESCAPE_QUESTION.to_string(), About::Escape);
                    }
                }
            }
        }
    }

    fn receive_into(&mut self, line: Option<String>, now: Instant) {
        let Some(line) = line else {
            self.server.extend_from_slice(CANCEL);
            self.say("refused, and sz on the server was cancelled");
            return;
        };
        let dir = if line.is_empty() { self.dir.clone() } else { typed_path(&line) };
        if !dir.is_dir() {
            self.say(&format!("{} is not a directory", dir.display()));
            let question = self.directory_question();
            self.ask(question, About::Directory);
            return;
        }
        self.dir = dir;
        let (proto, acts) = Receiver::new(now);
        self.mode = Mode::Receive(Box::new(Receiving { proto, file: None }));
        self.run(acts, now);
    }

    fn upload(&mut self, path: &Path, header: &Header, now: Instant) {
        match files::open(path) {
            Ok((file, info)) => {
                let name = info.name.clone();
                self.gauge.start(&name, Some(info.size));
                let (proto, acts) = Sender::new(file, info, header, now);
                self.mode = Mode::Send(Box::new(Sending { proto, name }));
                self.run(acts, now);
            }
            Err(why) => {
                self.server.extend_from_slice(CANCEL);
                self.say(&format!("{why}; rz on the server was cancelled"));
            }
        }
    }
}

/// A path as typed: `~` at its start is the home directory, as a shell
/// reads it.
fn typed_path(line: &str) -> PathBuf {
    let home = || std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    match (line.strip_prefix('~'), home()) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with(['/', '\\']) => {
            home.join(rest.trim_start_matches(['/', '\\']))
        }
        _ => PathBuf::from(line),
    }
}

const UPLOAD_QUESTION: &str =
    "the server waits for a file by ZMODEM (rz). Send which file? Enter with no name, or Ctrl-C, refuses: ";

const ESCAPE_QUESTION: &str =
    "send which file by ZMODEM? podssh types rz on the server. Enter with no name, or Ctrl-C, sends none: ";
