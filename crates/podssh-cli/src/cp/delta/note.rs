//! What a copy with `--delta` says of itself (T-470): the blocks that went,
//! or why the whole file went. The reason is one line at the default level,
//! once for each file, since the user asked for a delta and must not take a
//! full copy for one; a first copy, which has no older version to spare,
//! says it at `-v` alone. With `--jsonl` it is the `delta` of the file's
//! `done` object.

use podssh_ssh::Log;

use crate::cp::resume::Progress;

/// Why a copy with `--delta` sends the whole file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// No older version on the other side, or an empty one: a first copy.
    NoOld,
    /// Up: the server has no `copy-data`, and gives no digest of a block,
    /// as a server that runs no command does.
    NoCommand,
    /// The server gives no digest of a block: it runs no command, or has no
    /// `dd` or digest tool.
    NoDigests,
    /// Up: the server has no `copy-data`, and its command made no copy of
    /// the old file.
    NoFarCopy,
    /// The copy goes on from the temporary file of an earlier attempt.
    Resumed,
    /// The copy by exec, which sends no delta.
    ByExec,
    /// The digests differed after the delta.
    Differ,
}

impl Full {
    /// Its word in `--jsonl`.
    pub fn word(self) -> &'static str {
        match self {
            Full::NoOld => "no-older-file",
            Full::NoCommand => "no-copy-data",
            Full::NoDigests => "no-block-digests",
            Full::NoFarCopy => "no-far-copy",
            Full::Resumed => "resumed",
            Full::ByExec => "by-exec",
            Full::Differ => "digests-differ",
        }
    }

    fn why(self) -> &'static str {
        match self {
            Full::NoOld => "no older version of the file is there",
            Full::NoCommand => "the server has no copy-data and runs no command that gives the digests of blocks",
            Full::NoDigests => "the server gives no digest of a block (no command, no dd or no digest tool)",
            Full::NoFarCopy => "the server has no copy-data, and its command made no copy of the old file",
            Full::Resumed => "the copy goes on from the temporary file of an earlier attempt",
            Full::ByExec => "the copy by exec sends no delta",
            Full::Differ => "the digests differ after the delta",
        }
    }
}

/// What a copy with `--delta` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delta {
    /// The blocks of the file, those that went, and their bytes.
    Sent { blocks: u64, sent: u64, bytes: u64 },
    /// The whole file went, and why.
    Full(Full),
}

impl Delta {
    /// The `delta` of a `done` object of `--jsonl`.
    pub fn json(&self) -> serde_json::Value {
        match self {
            Delta::Sent { blocks, sent, bytes } => {
                serde_json::json!({ "blocks": blocks, "sent": sent, "bytes": bytes })
            }
            Delta::Full(why) => serde_json::json!({ "full": why.word() }),
        }
    }
}

/// The line that says why `source` goes whole.
pub fn line(source: &str, why: Full) -> String {
    match why {
        Full::Resumed => format!("{source}: --delta: {}, so the rest of the file goes", why.why()),
        _ => format!("{source}: --delta: {}: this copy sends the whole file", why.why()),
    }
}

/// Say once for the file why it goes whole, and give the `delta` of its
/// result: at `-v` for a first copy, else at the default level. The digests
/// that differ after a delta are said where they are found, with the tool
/// that found them. A later attempt of the same file keeps the first reason.
pub fn full(source: &str, why: Full, progress: &mut Progress, log: &Log) -> Delta {
    if let Some(first) = progress.delta_why {
        return Delta::Full(first);
    }
    progress.delta_why = Some(why);
    match why {
        Full::NoOld => log.verbose(&line(source, why)),
        Full::Differ => {}
        _ => log.info(&line(source, why)),
    }
    Delta::Full(why)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_reason_has_a_word_and_a_line_that_says_the_whole_file_goes() {
        let all =
            [Full::NoOld, Full::NoCommand, Full::NoDigests, Full::NoFarCopy, Full::Resumed, Full::ByExec, Full::Differ];
        let words: std::collections::BTreeSet<&str> = all.iter().map(|w| w.word()).collect();
        assert_eq!(words.len(), all.len(), "one word for each reason");
        let line = line("big.bin", Full::NoCommand);
        assert!(line.starts_with("big.bin: --delta: the server has no copy-data"), "{line}");
        assert!(line.ends_with(": this copy sends the whole file"), "{line}");
        assert!(super::line("f", Full::Resumed).ends_with("so the rest of the file goes"));
    }

    #[test]
    fn the_delta_of_a_done_object() {
        let sent = Delta::Sent { blocks: 5, sent: 1, bytes: 1 << 20 };
        assert_eq!(sent.json(), serde_json::json!({ "blocks": 5, "sent": 1, "bytes": 1_048_576 }));
        assert_eq!(Delta::Full(Full::NoCommand).json(), serde_json::json!({ "full": "no-copy-data" }));
    }

    #[test]
    fn the_reason_is_said_once_for_a_file() {
        let log = Log::new(podssh_ssh::LogLevel::Quiet);
        let mut progress = Progress::default();
        assert_eq!(full("f", Full::NoCommand, &mut progress, &log), Delta::Full(Full::NoCommand));
        assert_eq!(progress.delta_why, Some(Full::NoCommand));
        // A second attempt of the same file says nothing more, and keeps the
        // first reason.
        assert_eq!(full("f", Full::Resumed, &mut progress, &log), Delta::Full(Full::NoCommand));
    }
}
