//! Output for a Windows console (T-294). The console's writer of Rust's
//! standard library turns UTF-8 into UTF-16, and refuses a byte that is not
//! UTF-8; podssh took that refusal for a stdout that is gone, and lost the
//! rest of the session's output. Here each sequence that is not UTF-8
//! becomes U+FFFD, as a terminal of Linux shows it, and a sequence that the
//! end of a message cuts waits for the next message. A pipe, a file and a
//! terminal of Unix get the bytes unchanged: none of this is used for them.

/// U+FFFD, in UTF-8.
const REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

/// The bytes of one stream on their way to a console.
#[derive(Debug, Default)]
pub(crate) struct ConsoleText {
    /// The start of a sequence that the last message ended in.
    held: Vec<u8>,
}

impl ConsoleText {
    /// `data` as UTF-8 that the console takes.
    pub(crate) fn convert(&mut self, data: &[u8]) -> Vec<u8> {
        let mut input = std::mem::take(&mut self.held);
        input.extend_from_slice(data);
        let mut out = Vec::with_capacity(input.len());
        let mut rest = input.as_slice();
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.extend_from_slice(text.as_bytes());
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    out.extend_from_slice(valid);
                    match e.error_len() {
                        Some(bad) => {
                            out.extend_from_slice(REPLACEMENT);
                            rest = &after[bad..];
                        }
                        // The start of a sequence, cut by the end of the message.
                        None => {
                            self.held = after.to_vec();
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// The end of the stream: a sequence that never ended shows as U+FFFD.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        if self.held.is_empty() {
            return Vec::new();
        }
        self.held.clear();
        REPLACEMENT.to_vec()
    }
}

/// The text of stdout and of stderr, each when it is a Windows console.
#[derive(Debug, Default)]
pub(crate) struct Consoles {
    streams: [Option<ConsoleText>; 2],
}

impl Consoles {
    /// The streams of this process that are Windows consoles.
    pub(crate) fn of_this_process() -> Consoles {
        let of = |stderr| super::is_console(stderr).then(ConsoleText::default);
        Consoles { streams: [of(false), of(true)] }
    }

    /// `data` for stdout, or for stderr: converted for a console, unchanged
    /// for anything else.
    pub(crate) fn text(&mut self, stderr: bool, data: Vec<u8>) -> Vec<u8> {
        match self.streams[usize::from(stderr)].as_mut() {
            Some(console) => console.convert(&data),
            None => data,
        }
    }

    /// What a stream still holds at the end of the session.
    pub(crate) fn finish(&mut self, stderr: bool) -> Vec<u8> {
        self.streams[usize::from(stderr)].as_mut().map(ConsoleText::finish).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn converted(messages: &[&[u8]]) -> Vec<u8> {
        let mut text = ConsoleText::default();
        let mut out: Vec<u8> = messages.iter().flat_map(|m| text.convert(m)).collect();
        out.extend(text.finish());
        out
    }

    #[test]
    fn utf8_text_passes_unchanged() {
        let text = "plain, h\u{e9}llo \u{20ac} \u{2713} and \u{1f600}\r\n";
        assert_eq!(converted(&[text.as_bytes()]), text.as_bytes());
    }

    #[test]
    fn utf8_a_bad_byte_shows_as_the_replacement_and_the_rest_goes_on() {
        assert_eq!(converted(&[b"before\n\xffafter\n"]), "before\n\u{fffd}after\n".as_bytes());
        assert_eq!(converted(&[b"a\xc3Ab"]), "a\u{fffd}Ab".as_bytes());
        assert_eq!(converted(&[b"\xff", b"\xfe", b"x"]), "\u{fffd}\u{fffd}x".as_bytes());
    }

    #[test]
    fn utf8_a_character_split_across_messages_shows_whole() {
        let mut text = ConsoleText::default();
        assert_eq!(text.convert(b"h\xc3"), b"h");
        assert_eq!(text.convert(b"\xa9llo \xe2\x82"), "\u{e9}llo ".as_bytes());
        assert_eq!(text.convert(b"\xac"), "\u{20ac}".as_bytes());
        assert_eq!(text.finish(), b"");
    }

    #[test]
    fn utf8_a_sequence_that_never_ends_shows_as_the_replacement_at_the_end() {
        assert_eq!(converted(&[b"cut \xe2\x82"]), "cut \u{fffd}".as_bytes());
    }

    #[test]
    fn utf8_a_stream_that_is_no_console_keeps_its_bytes() {
        let mut consoles = Consoles::default();
        assert_eq!(consoles.text(false, b"\xff\xfe raw".to_vec()), b"\xff\xfe raw");
        assert_eq!(consoles.finish(true), b"");
    }
}
