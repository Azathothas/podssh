//! Expect rules (T-191): in a session with a pty, each rule waits for a
//! literal text in the output, then sends its keys, in the order given. The
//! session's own input is held until the last rule has sent its keys, so
//! that no key typed here comes between them. A rule that sees no match
//! within its time ends the session (255), and its words name the rule.

use std::time::Duration;

/// The most output that a rule looks back over: older output is dropped.
pub const WINDOW: usize = 64 * 1024;

/// One rule: the text to wait for, and the keys to send then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub expect: Vec<u8>,
    pub send: Vec<u8>,
}

/// The rules of a run, and how long each may wait for its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    pub rules: Vec<Rule>,
    pub wait: Duration,
}

/// The rules of one session, as its output comes.
#[derive(Debug)]
pub struct Expect {
    rules: Vec<Rule>,
    wait: Duration,
    /// The rule that waits now; the count of the rules once each matched.
    next: usize,
    /// The output since the last match: its last [`WINDOW`] bytes.
    seen: Vec<u8>,
    /// The keys of the rules that matched, not sent yet.
    queued: Vec<u8>,
    /// When the rule that waits runs out of time.
    deadline: tokio::time::Instant,
}

impl Expect {
    /// The rules of a session that starts now: the first rule's time runs
    /// from here.
    pub fn new(rules: &Rules) -> Self {
        Expect {
            rules: rules.rules.clone(),
            wait: rules.wait,
            next: 0,
            seen: Vec::new(),
            queued: Vec::new(),
            deadline: tokio::time::Instant::now() + rules.wait,
        }
    }

    /// Whether each rule has matched.
    pub fn done(&self) -> bool {
        self.next >= self.rules.len()
    }

    /// A piece of the session's output, as the terminal shows it: each rule
    /// that it completes queues its keys, and the next rule's time starts.
    /// A text that a piece cuts in two still matches.
    pub fn feed(&mut self, data: &[u8]) {
        if self.done() {
            return;
        }
        self.seen.extend_from_slice(data);
        while let Some(rule) = self.rules.get(self.next) {
            let Some(at) = find(&self.seen, &rule.expect) else { break };
            self.queued.extend_from_slice(&rule.send);
            // The next rule looks only at what came after this match.
            self.seen.drain(..at + rule.expect.len());
            self.next += 1;
            self.deadline = tokio::time::Instant::now() + self.wait;
        }
        if self.seen.len() > WINDOW {
            let cut = self.seen.len() - WINDOW;
            self.seen.drain(..cut);
        }
    }

    /// The keys to send now: those of each rule that matched since the last
    /// call.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.queued)
    }

    /// Until the rule that waits runs out of time: the words that say which
    /// rule saw no match; for ever once each rule matched.
    pub async fn missed(&self) -> String {
        let Some(rule) = self.rules.get(self.next) else { return std::future::pending().await };
        tokio::time::sleep_until(self.deadline).await;
        format!(
            "--expect {} ({:?}) saw no match within {}; the session ends",
            self.next + 1,
            String::from_utf8_lossy(&rule.expect),
            shown(self.wait)
        )
    }
}

/// A time as a person reads it: whole seconds, else milliseconds.
fn shown(wait: Duration) -> String {
    if wait.subsec_millis() == 0 {
        format!("{} s", wait.as_secs())
    } else {
        format!("{} ms", wait.as_millis())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[path = "expect_tests.rs"]
mod tests;
