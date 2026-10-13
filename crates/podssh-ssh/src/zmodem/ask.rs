//! A question on the terminal while the session's keys come to podssh: one
//! line, with its echo, Backspace and Ctrl-U; Enter answers, and Ctrl-C or
//! Ctrl-D refuses. The terminal is raw, so podssh echoes each key itself,
//! and drops the bytes of an escape sequence (an arrow, a function key).
//! The session's input task reads the keys, so the question reads them from
//! there, never from the terminal a second time.

/// The longest answer, in bytes.
pub const MOST: usize = 4096;

/// What the user answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The line, with the spaces around it trimmed.
    Line(String),
    /// Ctrl-C or Ctrl-D.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sequence {
    None,
    /// After ESC.
    Escape,
    /// After `ESC [` or `ESC O`, until a final byte.
    Csi,
}

/// One open question.
#[derive(Debug)]
pub struct Question {
    prompt: String,
    line: Vec<u8>,
    sequence: Sequence,
}

impl Question {
    /// A question, and the bytes that show it at the start of its line.
    pub fn new(prompt: &str) -> (Question, Vec<u8>) {
        let shown = format!("\r\x1b[K{prompt}").into_bytes();
        (Question { prompt: prompt.to_string(), line: Vec::new(), sequence: Sequence::None }, shown)
    }

    /// Keys: what to show, and the answer once there is one. Keys after the
    /// answer in the same read are dropped.
    pub fn keys(&mut self, keys: &[u8]) -> (Vec<u8>, Option<Answer>) {
        let (echo, answer) = self.keys_and_rest(keys);
        (echo, answer.map(|(answer, _)| answer))
    }

    /// As [`Question::keys`], with how many of the keys the answer took: the
    /// keys after it belong to the session, for `~C` (T-291). A CR and the
    /// LF after it are one Enter.
    pub fn keys_and_rest(&mut self, keys: &[u8]) -> (Vec<u8>, Option<(Answer, usize)>) {
        let mut echo = Vec::new();
        for (at, &key) in keys.iter().enumerate() {
            match self.sequence {
                Sequence::Escape => {
                    self.sequence = if key == b'[' || key == b'O' { Sequence::Csi } else { Sequence::None };
                    continue;
                }
                Sequence::Csi => {
                    if (0x40..=0x7e).contains(&key) {
                        self.sequence = Sequence::None;
                    }
                    continue;
                }
                Sequence::None => {}
            }
            match key {
                b'\r' | b'\n' => {
                    echo.extend_from_slice(b"\r\n");
                    let line = String::from_utf8_lossy(&self.line).trim().to_string();
                    let took = if key == b'\r' && keys.get(at + 1) == Some(&b'\n') { at + 2 } else { at + 1 };
                    return (echo, Some((Answer::Line(line), took)));
                }
                0x03 | 0x04 => {
                    echo.extend_from_slice(b"\r\n");
                    return (echo, Some((Answer::Refused, at + 1)));
                }
                0x7f | 0x08 => {
                    // A whole UTF-8 character goes, and one cell of the screen.
                    let mut gone = false;
                    while let Some(b) = self.line.pop() {
                        gone = true;
                        if (b & 0xc0) != 0x80 {
                            break;
                        }
                    }
                    if gone {
                        echo.extend_from_slice(b"\x08 \x08");
                    }
                }
                0x15 => {
                    self.line.clear();
                    echo.extend_from_slice(format!("\r\x1b[K{}", self.prompt).as_bytes());
                }
                0x1b => self.sequence = Sequence::Escape,
                key if key < 0x20 => {}
                key => {
                    if self.line.len() < MOST {
                        self.line.push(key);
                        echo.push(key);
                    }
                }
            }
        }
        (echo, None)
    }
}
