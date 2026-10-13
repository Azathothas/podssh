//! The lines of the broadcast (T-185): each line typed goes into the queue
//! ([`Feed`]) of each host of the selection, and a line that starts with `:`
//! is for podssh. Plain logic over the feeds, so that a test drives it with
//! no network and no terminal: [`super`] gives it the bytes, the keys and
//! the ends of the hosts, and writes what it says, a line each.

use podssh_ssh::io::Feed;

use crate::each::fan::Ended;
use crate::hosts::Groups;

/// What may wait for one host: a line that would pass it does not go to
/// that host, which leaves the selection, and the user is told. No byte
/// typed is dropped with no word.
pub const QUEUE: usize = 64 * 1024;
const KIB: usize = QUEUE / 1024;

/// The emergency stop's key, as the terminal of this system types it.
pub const STOP_KEY: &str = if cfg!(windows) { "Ctrl-Break" } else { "Ctrl-\\" };

/// The key that ends the input of a terminal of this system.
const END_KEY: &str = if cfg!(windows) { "Ctrl-Z" } else { "Ctrl-D" };

/// What podssh says at the end of the input, when it may wait for a shell.
pub const ENDED: &str = "the end of the input: each shell ends once it has read its lines; Ctrl-C cuts those that run";

/// The commands, each with what it does, for `:help`.
const HELP: &[(&str, &str)] = &[
    (":all", "each host that runs takes the lines"),
    (":none", "no host takes a line"),
    (":only HOST...", "these hosts alone; braces and @GROUP as in HOSTS, and USER@ may be left out"),
    (":list", "each host, whether it is selected, and its state"),
    (":intr", "signal INT to each selected host; a server may ignore it"),
    ("::LINE", "the line :LINE, to the selected hosts"),
];

/// One host of the broadcast.
struct Host {
    label: String,
    feed: Feed,
    selected: bool,
    /// How it ended, once it has.
    ended: Option<Ended>,
    /// The lines that did not reach it because its queue was full.
    missed: usize,
}

/// The broadcast between two keys.
pub struct Hub {
    hosts: Vec<Host>,
    groups: Groups,
    /// `--confirm`: a line for more than one host waits for a second Enter.
    confirm: bool,
    /// That line, while it waits.
    held: Option<Vec<u8>>,
    /// The start of a line that has no end yet.
    partial: Vec<u8>,
    /// A line longer than [`QUEUE`] is dropped up to its end.
    skipping: bool,
    /// The input goes on: the end of a host is said only then.
    reading: bool,
}

impl Hub {
    /// The hub of the hosts `labels`, each with its feed, each selected.
    pub fn new(labels: Vec<String>, feeds: Vec<Feed>, groups: Groups, confirm: bool) -> Hub {
        let hosts = labels
            .into_iter()
            .zip(feeds)
            .map(|(label, feed)| Host { label, feed, selected: true, ended: None, missed: 0 })
            .collect();
        Hub { hosts, groups, confirm, held: None, partial: Vec::new(), skipping: false, reading: true }
    }

    /// The first words: the hosts, the commands and the stop.
    pub fn banner(&self) -> Vec<String> {
        vec![format!(
            "each line goes to the {} hosts; :help lists the commands, and {STOP_KEY} stops the broadcast at once",
            self.hosts.len()
        )]
    }

    /// Bytes typed: each whole line, acted on. What podssh says.
    pub fn typed(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut said = Vec::new();
        for piece in bytes.split_inclusive(|b| *b == b'\n') {
            let ended = piece.last() == Some(&b'\n');
            if self.skipping {
                self.skipping = !ended;
                continue;
            }
            self.partial.extend_from_slice(piece.strip_suffix(b"\n").unwrap_or(piece));
            if ended {
                let line = std::mem::take(&mut self.partial);
                said.extend(self.line(line));
            } else if self.partial.len() > QUEUE {
                self.partial.clear();
                self.skipping = true;
                said.push(format!("a line of more than {KIB} KiB goes to no host; it is dropped to its end"));
            }
        }
        said
    }

    /// One whole line, with no newline.
    fn line(&mut self, mut line: Vec<u8>) -> Vec<String> {
        // A Windows console ends a line with CR LF.
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let mut said = Vec::new();
        if let Some(held) = self.held.take() {
            if line.is_empty() {
                return self.send(held);
            }
            said.push("the line that waited for a second Enter is not sent".to_string());
        }
        if line.starts_with(b"::") {
            line.remove(0);
            said.extend(self.for_hosts(line));
        } else if let Some(command) = line.strip_prefix(b":") {
            said.extend(self.command(&String::from_utf8_lossy(command)));
        } else {
            said.extend(self.for_hosts(line));
        }
        said
    }

    /// A line for the hosts: now, or after a second Enter with `--confirm`.
    fn for_hosts(&mut self, line: Vec<u8>) -> Vec<String> {
        let to = self.hosts.iter().filter(|h| h.selected).count();
        if self.confirm && to > 1 && !line.is_empty() {
            self.held = Some(line);
            return vec![format!("this line goes to {to} hosts: Enter sends it, another line drops it")];
        }
        self.send(line)
    }

    /// `line` and a newline into the queue of each selected host that has
    /// room for it; a host that has none leaves the selection, with a word.
    fn send(&mut self, mut line: Vec<u8>) -> Vec<String> {
        line.push(b'\n');
        if line.len() > QUEUE {
            return vec![format!("a line of more than {KIB} KiB goes to no host")];
        }
        let mut said = Vec::new();
        let mut sent = 0;
        for host in self.hosts.iter_mut().filter(|h| h.selected) {
            let waiting = host.feed.held();
            if waiting + line.len() > QUEUE {
                host.selected = false;
                host.missed += 1;
                said.push(format!(
                    "{}: its queue is full ({waiting} bytes wait for it): this line does not go to it, and it leaves \
                     the selection; :all or :only takes it back",
                    host.label
                ));
                continue;
            }
            host.feed.put(&line);
            sent += 1;
        }
        if sent == 0 && said.is_empty() {
            said.push("no host is selected: the line goes to no host; :all selects each host".to_string());
        }
        said
    }

    /// A command of podssh: the words after the `:`.
    fn command(&mut self, text: &str) -> Vec<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        match words.as_slice() {
            ["all"] => {
                for host in &mut self.hosts {
                    host.selected = host.ended.is_none();
                }
                vec![self.count()]
            }
            ["none"] => {
                for host in &mut self.hosts {
                    host.selected = false;
                }
                vec![self.count()]
            }
            ["only"] => vec!["give the hosts: :only HOST...".to_string()],
            ["only", names @ ..] => self.only(names),
            ["list"] => self.list(),
            ["intr"] => self.intr(),
            [] | ["help"] => self.help(),
            [word, ..] if matches!(*word, "all" | "none" | "list" | "intr" | "help") => {
                vec![format!(":{word} takes no other word")]
            }
            _ => vec![format!(
                ":{} is not a command; :help lists them, and a line that starts with :: goes to the hosts with one \
                 : less",
                text.trim()
            )],
        }
    }

    /// `:only`: the hosts that `words` name, and no other. A word that names
    /// no host changes nothing.
    fn only(&mut self, words: &[&str]) -> Vec<String> {
        let mut chosen = vec![false; self.hosts.len()];
        for word in words {
            let names = match crate::hosts::expand(word, &self.groups) {
                Ok(names) => names,
                Err(refusal) => return vec![format!("{}; the selection is as it was", refusal.message)],
            };
            for name in names {
                let mut found = false;
                for (i, host) in self.hosts.iter().enumerate() {
                    if names_host(&host.label, &name) {
                        chosen[i] = true;
                        found = true;
                    }
                }
                if !found {
                    return vec![format!(
                        "{name} is not a host of this broadcast (:list gives them); the selection is as it was"
                    )];
                }
            }
        }
        let mut said = Vec::new();
        for (host, chosen) in self.hosts.iter_mut().zip(chosen) {
            host.selected = chosen && host.ended.is_none();
            if chosen && host.ended.is_some() {
                said.push(format!("{}: it has ended, and takes no line", host.label));
            }
        }
        said.push(self.count());
        said
    }

    /// How many hosts take the lines.
    fn count(&self) -> String {
        let selected = self.hosts.iter().filter(|h| h.selected).count();
        format!("{selected} of {} hosts take the lines", self.hosts.len())
    }

    /// `:list`: each host, whether it is selected, and its state.
    fn list(&self) -> Vec<String> {
        let width = self.hosts.iter().map(|h| h.label.chars().count()).max().unwrap_or(0);
        self.hosts
            .iter()
            .map(|h| {
                let state = match &h.ended {
                    Some(Ended::Status(code)) => format!("ended with {code}"),
                    Some(Ended::Failed(_)) => "no session".to_string(),
                    Some(Ended::NotStarted) => "not started".to_string(),
                    None if h.feed.reading() => "open".to_string(),
                    None => "connecting".to_string(),
                };
                let waiting = h.feed.held();
                let waits = if waiting > 0 { format!(", {waiting} bytes wait for it") } else { String::new() };
                let mark = if h.selected { "selected" } else { "-" };
                format!("  {:width$}  {mark:8}  {state}{waits}", h.label)
            })
            .collect()
    }

    /// `:intr`: `signal INT` to each selected host.
    fn intr(&self) -> Vec<String> {
        let mut asked = 0;
        for host in self.hosts.iter().filter(|h| h.selected && h.ended.is_none()) {
            host.feed.interrupt();
            asked += 1;
        }
        vec![format!("signal INT to {asked} hosts; a server may ignore it")]
    }

    fn help(&self) -> Vec<String> {
        let mut lines: Vec<String> = HELP.iter().map(|(command, what)| format!("  {command:14}  {what}")).collect();
        lines.push(format!("  {STOP_KEY:14}  the emergency stop: no host takes a line, and what waits is dropped"));
        lines.push(format!("  {END_KEY:14}  the end of the input: each shell ends when it has read its lines"));
        lines
    }

    /// The emergency stop: no host is selected, and each byte that waits for
    /// a host, a line that waits for its second Enter and the start of a
    /// line are dropped, at once; `unread`, the bytes read before the key
    /// and not given to the hub, were dropped by the caller.
    pub fn stop(&mut self, unread: usize) -> Vec<String> {
        let mut dropped = unread + self.partial.len() + self.held.take().map_or(0, |line| line.len());
        self.partial.clear();
        for host in &mut self.hosts {
            host.selected = false;
            dropped += host.feed.take().len();
        }
        let mut said = vec!["broadcast stopped; :all starts it again".to_string()];
        if dropped > 0 {
            said.push(format!("{dropped} bytes that waited were dropped"));
        }
        said
    }

    /// Ctrl-C while the input goes on: it goes to no host.
    pub fn ctrl_c(&self) -> Vec<String> {
        vec![format!(
            "Ctrl-C goes to no host: :intr sends signal INT to the selected hosts, {END_KEY} ends the input, and \
             {STOP_KEY} stops the broadcast"
        )]
    }

    /// The end of the input: a last line with no newline goes as a line, a
    /// line that waits for its second Enter is dropped, and each shell reads
    /// what waits for it, then its end.
    pub fn end(&mut self) -> Vec<String> {
        let mut said = Vec::new();
        if !self.partial.is_empty() && !self.skipping {
            let line = std::mem::take(&mut self.partial);
            said.extend(self.line(line));
        }
        if self.held.take().is_some() {
            said.push("the line that waited for a second Enter is not sent".to_string());
        }
        self.reading = false;
        for host in &self.hosts {
            host.feed.end();
        }
        said
    }

    /// Host `i` ended so: it leaves the selection, and what waited for it is
    /// said.
    pub fn ended(&mut self, i: usize, end: &Ended) -> Vec<String> {
        let Some(host) = self.hosts.get_mut(i) else { return Vec::new() };
        host.selected = false;
        host.ended = Some(end.clone());
        let lost = host.feed.take().len();
        let mut said = Vec::new();
        if self.reading {
            said.push(match end {
                Ended::Status(code) => format!("{}: its shell ended with {code}; it takes no more lines", host.label),
                _ => format!("{}: no session; the broadcast goes on without it", host.label),
            });
        }
        if lost > 0 {
            said.push(format!("{}: {lost} bytes that waited for it were not sent", host.label));
        }
        said
    }

    /// Each host that a line did not reach because its queue was full.
    pub fn missed(&self) -> Vec<String> {
        self.hosts
            .iter()
            .filter(|h| h.missed > 0)
            .map(|h| format!("{}: lines that did not reach it because its queue was full: {}", h.label, h.missed))
            .collect()
    }
}

/// Whether `name` names the host `label`: the label, or the label without
/// its `USER@`.
pub fn names_host(label: &str, name: &str) -> bool {
    label == name || label.rsplit_once('@').is_some_and(|(_, host)| host == name)
}

#[cfg(test)]
#[path = "hub_tests.rs"]
mod tests;
