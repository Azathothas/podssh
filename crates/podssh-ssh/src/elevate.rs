//! `--sudo` and `--su` (T-032): a remote command run as root, with the
//! password asked here, on the terminal or through `SSH_ASKPASS`, and never
//! taken from the command line. `sudo -S` prints a prompt that podssh
//! chooses, and the command prints a second marker before it starts: podssh
//! sends the password for that prompt, once, holds its own input until the
//! command starts, and removes both markers from the output. With no prompt
//! (a `NOPASSWD` rule) no password is sent. `su` reads a terminal alone: with
//! a pty, its prompt is its output that ends with no newline before the
//! command starts, and that output, su's own, is written only if the command
//! never starts.

use std::time::Duration;

use russh::client::Msg;
use russh::ChannelWriteHalf;
use zeroize::Zeroizing;

use crate::log::Log;
use crate::options::Elevate;
use crate::prompt::{self, PromptError};

/// How long the prompt or the start of the command may take, and the check
/// of the password after it was sent (as a reply to a request, T-032).
pub const WAIT: Duration = Duration::from_secs(30);

/// The two markers of one run: random, so that no output holds them by
/// chance, and of letters, digits and `-` alone, which no shell expands.
#[derive(Debug, Clone)]
pub struct Markers {
    prompt: String,
    started: String,
}

impl Markers {
    pub fn new() -> Self {
        let id: u64 = rand::random();
        Markers { prompt: format!("podssh-{id:016x}-password"), started: format!("podssh-{id:016x}-started") }
    }
}

impl Default for Markers {
    fn default() -> Self {
        Self::new()
    }
}

/// The command that runs `command` as root, for a remote shell that reads
/// POSIX quoting: `sudo -S` with the prompt of `markers`, and `-k`, so that it
/// asks also when it remembers a password; or `su -c`.
pub fn command(how: Elevate, command: &str, markers: &Markers) -> String {
    let script = quote(&format!("printf %s {} >&2; {command}", markers.started));
    match how {
        Elevate::Sudo => format!("sudo -S -k -p {} -- sh -c {script}", markers.prompt),
        Elevate::Su => format!("su -c {script}"),
    }
}

/// `text` in single quotes, each `'` in it closed, escaped and opened again.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// What the output of an elevated command asks of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The prompt: send the password.
    Ask,
    /// A prompt after the password was sent: it was refused.
    Again,
    /// The command started: the session's input goes to it from now on.
    Started,
}

/// The output of an elevated command, until it starts.
#[derive(Debug)]
pub struct Filter {
    how: Elevate,
    markers: Markers,
    started: bool,
    asked: bool,
    /// For stdout and stderr: an end of a read that may begin a marker.
    held: [Vec<u8>; 2],
    /// su's own output before the command started.
    own: Vec<u8>,
}

impl Filter {
    pub fn new(how: Elevate, markers: Markers) -> Self {
        Filter { how, markers, started: false, asked: false, held: [Vec::new(), Vec::new()], own: Vec::new() }
    }

    pub fn started(&self) -> bool {
        self.started
    }

    /// A read of stdout, or of stderr: the bytes to write, and what the
    /// session must do.
    pub fn feed(&mut self, data: &[u8], stderr: bool) -> (Vec<u8>, Vec<Event>) {
        if self.started {
            return (data.to_vec(), Vec::new());
        }
        let stream = usize::from(stderr);
        let mut text = std::mem::take(&mut self.held[stream]);
        text.extend_from_slice(data);
        let (mut out, mut events) = (Vec::new(), Vec::new());
        let markers = [(self.markers.prompt.clone(), Event::Ask), (self.markers.started.clone(), Event::Started)];
        let mut at = 0;
        while !self.started {
            let next = markers
                .iter()
                .filter_map(|(m, e)| find(&text[at..], m.as_bytes()).map(|p| (at + p, m.len(), *e)))
                .min_by_key(|(p, ..)| *p);
            let Some((p, len, event)) = next else { break };
            self.before(&text[at..p], &mut out);
            at = p + len;
            match event {
                Event::Ask if self.asked => events.push(Event::Again),
                Event::Ask => {
                    self.asked = true;
                    events.push(Event::Ask);
                }
                _ => {
                    self.started = true;
                    self.own.clear();
                    events.push(Event::Started);
                }
            }
        }
        let tail = &text[at..];
        if self.started {
            out.extend_from_slice(tail);
            return (out, events);
        }
        let keep = held(tail, [self.markers.prompt.as_bytes(), self.markers.started.as_bytes()]);
        self.before(&tail[..tail.len() - keep], &mut out);
        self.held[stream] = tail[tail.len() - keep..].to_vec();
        // su: its prompt is its own output that ends with no newline.
        if self.how == Elevate::Su && !self.asked && keep == 0 && !self.own.is_empty() && !self.own.ends_with(b"\n") {
            self.asked = true;
            events.push(Event::Ask);
        }
        (out, events)
    }

    /// Output before the command started: sudo's goes out as it comes (its
    /// lecture, "Sorry, try again"); su's own is kept.
    fn before(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        match self.how {
            Elevate::Sudo => out.extend_from_slice(bytes),
            Elevate::Su => self.own.extend_from_slice(bytes),
        }
    }

    /// At the end of a command that never started: su's own output, which
    /// holds its refusal, and the ends held back, which were no markers.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.own);
        for held in &mut self.held {
            out.append(held);
        }
        out
    }
}

/// Until `at`, or for ever with none.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The length of the longest end of `bytes` that begins one of `markers`.
fn held(bytes: &[u8], markers: [&[u8]; 2]) -> usize {
    let most = markers.iter().map(|m| m.len() - 1).max().unwrap_or(0).min(bytes.len());
    (1..=most).rev().find(|&n| markers.iter().any(|m| m.starts_with(&bytes[bytes.len() - n..]))).unwrap_or(0)
}

/// An elevated command's session: its filter, the question for its
/// password, and the time it has to start.
pub struct Elevated {
    filter: Filter,
    question: String,
    /// Whether a question may be asked: no `BatchMode`, and a terminal or
    /// `SSH_ASKPASS` to ask on.
    may_ask: bool,
    events: Vec<Event>,
    asking: Option<tokio::task::JoinHandle<Result<Zeroizing<String>, PromptError>>>,
    deadline: Option<tokio::time::Instant>,
}

impl Elevated {
    pub fn new(how: Elevate, markers: Markers, question: String, may_ask: bool) -> Self {
        Elevated {
            filter: Filter::new(how, markers),
            question,
            may_ask,
            events: Vec::new(),
            asking: None,
            deadline: Some(tokio::time::Instant::now() + WAIT),
        }
    }

    pub fn started(&self) -> bool {
        self.filter.started()
    }

    /// A read of the channel, filtered: the bytes to write.
    pub fn feed(&mut self, data: &[u8], stderr: bool) -> Vec<u8> {
        let (out, events) = self.filter.feed(data, stderr);
        self.events.extend(events);
        out
    }

    /// What the output asked: the question for the password, the end of the
    /// input on a refusal, the input once the command started. `held` is
    /// whether the session holds its input; `ended`, whether it has ended.
    pub async fn act(&mut self, writer: &ChannelWriteHalf<Msg>, held: &mut bool, ended: bool, log: &Log) {
        for event in std::mem::take(&mut self.events) {
            match event {
                Event::Ask if !self.may_ask => {
                    log.info("the remote command asked for a password, and podssh may ask none (BatchMode, or no terminal and no SSH_ASKPASS)");
                    let _ = writer.eof().await;
                }
                Event::Ask => {
                    self.deadline = None;
                    let question = self.question.clone();
                    self.asking = Some(tokio::task::spawn_blocking(move || prompt::ask(&question, false)));
                }
                Event::Again => {
                    log.info("the password was refused");
                    let _ = writer.eof().await;
                }
                Event::Started => {
                    self.deadline = None;
                    *held = false;
                    if ended {
                        let _ = writer.eof().await;
                    }
                }
            }
        }
    }

    /// Until the answer to the question was sent (false), or the command's
    /// time to start is up (true).
    pub async fn next(&mut self, writer: &ChannelWriteHalf<Msg>, log: &Log) -> bool {
        let deadline = self.deadline;
        tokio::select! {
            () = self.answer(writer, log) => false,
            () = until(deadline) => true,
        }
    }

    /// Until the answer to the question comes; then it is sent, with a
    /// newline, or the input ends.
    async fn answer(&mut self, writer: &ChannelWriteHalf<Msg>, log: &Log) {
        let Some(asking) = self.asking.as_mut() else { return std::future::pending().await };
        let answer = asking.await;
        self.asking = None;
        match answer {
            Ok(Ok(password)) => {
                let mut line = Zeroizing::new(password.as_bytes().to_vec());
                line.push(b'\n');
                let _ = writer.data(&line[..]).await;
                self.deadline = Some(tokio::time::Instant::now() + WAIT);
            }
            Ok(Err(why)) => {
                log.info(&format!("the password for the remote command: {why}"));
                let _ = writer.eof().await;
            }
            Err(_) => {
                let _ = writer.eof().await;
            }
        }
    }

    /// What was held back, for the end of a command that never started.
    pub fn finish(&mut self) -> Vec<u8> {
        self.filter.finish()
    }
}

#[cfg(test)]
#[path = "elevate_tests.rs"]
mod tests;
