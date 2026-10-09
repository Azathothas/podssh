//! The escape-sequence parser: what counts as a sequence, and what it decides.
//!
//! **This module exists because the reference's parser cannot satisfy this
//! entry's own plant**, and the reason is worth reading.
//!
//! **The reference reads exactly two bytes.** **READ**,
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs:142-150` and `244-262`: `ESC`
//! then `[`, then **the very next byte is dispatched** and the sequence is
//! over. So `ESC [ 1 5 ~` — **a real F5 keypress**, and the exact sequence
//! this entry's `Prove` block names — is dispatched on `1`, which is unknown, so
//! it rings a bell **and then `5` and `~` arrive as ordinary characters and
//! land in the user's command line.**
//!
//! **That contradicts the entry's own acceptance clause**, which reads: *"an
//! unknown escape, `ESC [ 1 5 ~`. Assert a bell and **no state change**."*
//! A transcription that stopped at the reference's parser would ring the bell,
//! pass a test that only checks the bell, **and silently corrupt the command
//! a user is typing** every time they press a function key. **MEASURED** — a
//! test of this module runs the reference's own parser over `ESC [ 1 5 ~` and
//! asserts what it produces, so the divergence is a recorded measurement
//! rather than an argument.
//!
//! ## What this parser reads instead
//!
//! **A whole CSI sequence, per ECMA-48**: `ESC [`, then parameter bytes
//! (`0x30`–`0x3f`), then intermediate bytes (`0x20`–`0x2f`), then **one final
//! byte** (`0x40`–`0x7e`). The sequence ends at its final byte, so `1` and `5`
//! in `ESC [ 1 5 ~` are consumed *as parameters* and never become text.
//!
//! **A final byte with parameters behind it is refused**, not interpreted.
//! `ESC [ 1 C` is a real sequence meaning "cursor forward 1" — the cooked
//! discipline does not implement parameterised cursor motion, and a discipline
//! that interprets sequences it has not tested is a discipline that will corrupt
//! somebody's terminal. So it rings a bell, and that is the entry's rule:
//! *"a discipline that silently drops a sequence its client was promised is worse
//! than one that rings a bell"*.
//!
//! ## The keys that are not a CSI
//!
//! - **SS3, `ESC O` and a final byte.** A terminal in application mode sends
//!   the arrows, Home and End this way, F1 to F4 are `ESC O P` to `ESC O S`
//!   on most terminals, and the keypad in application mode sends `ESC O M`
//!   for Enter. Some terminals put a parameter before the final, as in
//!   `ESC O 2 P` for Shift+F1, so the bytes before it are read as a CSI's are.
//! - **The Linux console's F1 to F5**, `ESC [ [ A` to `ESC [ [ E`. The second
//!   `[` would end a CSI, so `ESC [ [` takes one more byte.
//! - **An Alt key**: `ESC` and a character is how a terminal sends Alt. No Alt
//!   key is bound, so it is refused whole: one bell, and the character is not
//!   typed, each of its UTF-8 bytes included.
//!
//! ## The bytes that end a sequence early
//!
//! **A control byte below `0x20` ends the sequence and is handled as a fresh
//! key.** This is deliberate and it is the `Restart` arm below: a user who
//! presses `ESC` and then `Ctrl-C` means to interrupt, and a parser that
//! swallowed the `Ctrl-C` as part of a malformed sequence would leave them with
//! no way to stop a running command — which is the failure plant E exists to
//! catch. **It holds right after `ESC` too**, so an escape never takes Ctrl-C,
//! Ctrl-D or Enter.
//!
//! **`ESC` starts a new sequence wherever it comes.** It is never text: a raw
//! `ESC` in the line would reach the terminal as the start of a sequence.
//!
//! ## A lone Escape
//!
//! **Only time tells a lone `ESC` from the start of a key**, and `ESC [` and
//! `ESC O` (Alt+[ and Alt+O) from the start of a longer one. A terminal writes
//! the bytes of one key at once, and a person types slower than that, so the
//! caller ticks the discipline when no byte came for [`crate::echo::IDLE`], and
//! the tick ends the open sequence ([`Esc::abandon`]) with one bell. The next
//! key is then a key. **This parser reads no clock**, so a test drives the
//! tick.

use crate::echo::units::utf8_len;

/// The longest parameter/intermediate run a CSI sequence may accumulate before
/// podssh stops counting.
///
/// **A bound for the same reason [`crate::echo::LINE_CAP`] is one.** A
/// client that sends `ESC [` and then bytes forever would otherwise grow this
/// state without limit, and the cap costs nothing when real sequences are two
/// or three bytes long.
pub const CSI_PARAM_CAP: usize = 16;

/// Escape-sequence parser state.
///
/// **Not `Copy`, and deliberately**: a CSI in progress owns its parameters, and
/// a `Copy` state machine that silently aliased its own parameters would be a
/// bug the type system could have prevented.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Esc {
    /// Not in a sequence.
    #[default]
    None,
    /// **`ESC` seen, and the next byte decides what follows.**
    /// **READ**, `session.rs:148`.
    Escape,
    /// **`ESC [` seen**, with the parameter and intermediate bytes so far.
    Csi(Vec<u8>),
    /// **`ESC O` seen**, with the parameter and intermediate bytes so far.
    Ss3(Vec<u8>),
    /// **`ESC [ [` seen**: the Linux console's F1 to F5 end with one more byte.
    LinuxFn,
    /// **An Alt key**, whose character has this many UTF-8 bytes still to come.
    Alt(u8),
}

/// The introducer of a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intro {
    /// `ESC [`.
    Csi,
    /// `ESC O`: a key of a terminal in application mode, or of its keypad.
    Ss3,
}

/// What stands between the introducer of a sequence and its final byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    /// Nothing. **The recognised keys are exactly these**, which is what
    /// makes `ESC [ 1 C` a refusal rather than a silently-honoured cursor
    /// move.
    None,
    /// One decimal number, as in `ESC [ 3 ~`.
    Number(u16),
    /// Anything else: two numbers, a private marker, an intermediate byte, or
    /// a run cut at [`CSI_PARAM_CAP`].
    Other,
}

impl Param {
    /// The parameter that these bytes make, read between the introducer and
    /// the final byte.
    pub fn read(bytes: &[u8]) -> Param {
        if bytes.is_empty() {
            return Param::None;
        }
        // A run at the cap may have lost the bytes past it, so it is never
        // read as a number.
        if bytes.len() >= CSI_PARAM_CAP || !bytes.iter().all(u8::is_ascii_digit) {
            return Param::Other;
        }
        std::str::from_utf8(bytes).ok().and_then(|s| s.parse().ok()).map_or(Param::Other, Param::Number)
    }
}

/// What the parser decided about one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// **The byte belongs to the sequence** and nothing happens yet.
    Continue,
    /// **The sequence ended here**, at a final byte.
    Final {
        /// `ESC [` or `ESC O`.
        intro: Intro,
        /// The final byte, `0x40`–`0x7e`.
        final_byte: u8,
        /// What stood before it; [`Param::None`] for a key.
        param: Param,
    },
    /// **Refused.** The caller rings the bell and changes nothing.
    Refused,
    /// **The byte is not part of a sequence**, so the caller handles it as a
    /// key: each byte outside one, and a byte that ends one early. It exists
    /// so a signal character is never swallowed by a malformed sequence.
    Restart,
}

/// **A parameter byte**, `0x30`–`0x3f`: the digits, `:;<=>?`.
pub fn is_csi_param(b: u8) -> bool {
    (0x30..=0x3f).contains(&b)
}

/// **An intermediate byte**, `0x20`–`0x2f`.
pub fn is_csi_intermediate(b: u8) -> bool {
    (0x20..=0x2f).contains(&b)
}

/// **A final byte**, `0x40`–`0x7e`. This is where a CSI sequence ends.
pub fn is_csi_final(b: u8) -> bool {
    (0x40..=0x7e).contains(&b)
}

impl Esc {
    /// Feed one byte, and report what to do.
    ///
    /// **The whole parser, and nothing else.** It moves no cursor, changes
    /// no line and emits no bytes: the discipline owns the line, this owns the
    /// sequence, and a parser that also edited the line would be two
    /// disciplines wearing one name.
    pub fn step(&mut self, b: u8) -> Step {
        // `ESC` starts a new sequence in every state: it is never text, and
        // a raw one in the line would reach the terminal.
        if b == 0x1b {
            *self = Esc::Escape;
            return Step::Continue;
        }
        // Each arm sets the next state; taking the state out moves the
        // parameters of a CSI rather than copying them.
        match std::mem::take(self) {
            Esc::None => Step::Restart,
            Esc::Escape => self.after_escape(b),
            // The second `[` would end the CSI, but on the Linux console it
            // begins F1 to F5.
            Esc::Csi(params) if params.is_empty() && b == b'[' => {
                *self = Esc::LinuxFn;
                Step::Continue
            }
            Esc::Csi(params) => self.sequence(Intro::Csi, params, b),
            Esc::Ss3(params) => self.sequence(Intro::Ss3, params, b),
            // A printable byte is the last of the Linux form, and no key of
            // that form is bound.
            Esc::LinuxFn if (0x20..=0x7e).contains(&b) => Step::Refused,
            Esc::LinuxFn => Step::Restart,
            Esc::Alt(left) => match b {
                0x80..=0xbf if left > 1 => {
                    *self = Esc::Alt(left - 1);
                    Step::Continue
                }
                0x80..=0xbf => Step::Refused,
                // The character was cut short, and the byte is a key of its
                // own.
                _ => Step::Restart,
            },
        }
    }

    /// The byte after a lone `ESC`. The reference refuses each byte that is
    /// not `[` (`session.rs:248-251`); this one also reads SS3, lets a control
    /// byte through, and refuses an Alt key whole.
    fn after_escape(&mut self, b: u8) -> Step {
        match b {
            b'[' => {
                *self = Esc::Csi(Vec::new());
                Step::Continue
            }
            b'O' => {
                *self = Esc::Ss3(Vec::new());
                Step::Continue
            }
            // A control byte is a key of its own: an escape never takes
            // Ctrl-C, Ctrl-D or Enter.
            0x00..=0x1f => Step::Restart,
            // Alt and a character of several UTF-8 bytes waits for the rest,
            // so that no lone continuation byte reaches the line.
            0xc2..=0xf4 => {
                *self = Esc::Alt(utf8_len(b).unwrap_or(2) as u8 - 1);
                Step::Continue
            }
            // Alt and a key: one bell, and the key is not typed. Typing it
            // would make Alt+b insert a `b`.
            _ => Step::Refused,
        }
    }

    /// The bytes of a CSI or an SS3 after its introducer: parameters and
    /// intermediates, then one final byte.
    fn sequence(&mut self, intro: Intro, mut params: Vec<u8>, b: u8) -> Step {
        if is_csi_param(b) || is_csi_intermediate(b) {
            // **Over the cap the bytes stop accumulating, and the
            // sequence is refused at its final byte** — a sequence with
            // more parameters than any real one is a malformed one, and
            // a bounded buffer is the alternative to a line that grows
            // until the process dies.
            if params.len() < CSI_PARAM_CAP {
                params.push(b);
            }
            *self = match intro {
                Intro::Csi => Esc::Csi(params),
                Intro::Ss3 => Esc::Ss3(params),
            };
            Step::Continue
        } else if is_csi_final(b) {
            Step::Final { intro, final_byte: b, param: Param::read(&params) }
        } else {
            // **The control byte.** See the module docs: a `Ctrl-C`
            // after a stray `ESC` must still interrupt.
            Step::Restart
        }
    }

    /// Whether a sequence is open, so that the caller owes an idle tick.
    pub fn is_open(&self) -> bool {
        *self != Esc::None
    }

    /// The idle tick: no byte came, so an open sequence ends here. True when
    /// one was open, which the caller answers with one bell.
    pub fn abandon(&mut self) -> bool {
        std::mem::take(self) != Esc::None
    }
}

#[cfg(test)]
mod tests;
