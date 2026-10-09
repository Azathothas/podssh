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
//! test at the bottom of this file runs the reference's own parser over
//! `ESC [ 1 5 ~` and asserts what it produces, so the divergence is a recorded
//! measurement rather than an argument.
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
//! ## The one byte that escapes a sequence
//!
//! **A control byte below `0x20` ends the sequence and is handled as a fresh
//! key.** This is deliberate and it is the `Restart` arm below: a user who
//! presses `ESC` and then `Ctrl-C` means to interrupt, and a parser that
//! swallowed the `Ctrl-C` as part of a malformed sequence would leave them with
//! no way to stop a running command — which is the failure plant E exists to
//! catch.

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
    /// **`ESC` seen, and the next byte decides whether this is a CSI.**
    /// **READ**, `session.rs:148`.
    Escape,
    /// **`ESC [` seen**, with the parameter and intermediate bytes so far.
    Csi(Vec<u8>),
}

/// What the parser decided about one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// **The byte belongs to the sequence** and nothing happens yet.
    Continue,
    /// **The sequence ended here**, at a final byte. `bare` is `true` when
    /// no parameter or intermediate byte preceded it — **the recognised
    /// keys are exactly the bare ones**, which is what makes `ESC [ 1 C` a
    /// refusal rather than a silently-honoured cursor move.
    Final {
        /// The final byte, `0x40`–`0x7e`.
        final_byte: u8,
        /// Whether no parameters or intermediates preceded it.
        bare: bool,
    },
    /// **Refused.** The caller rings the bell and changes nothing.
    Refused,
    /// **The byte was not part of the sequence**, so the caller handles it as
    /// a fresh key. Only a control byte below `0x20` gets here, and it
    /// exists so a signal character is never swallowed by a malformed sequence.
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
        match self {
            Esc::None => {
                if b == 0x1b {
                    *self = Esc::Escape;
                    Step::Continue
                } else {
                    Step::Restart
                }
            }
            Esc::Escape => {
                if b == b'[' {
                    *self = Esc::Csi(Vec::new());
                    Step::Continue
                } else {
                    // Transcribed from `session.rs:248-251`: anything after
                    // `ESC` that is not `[` is refused, and the byte is consumed
                    // with it.
                    *self = Esc::None;
                    Step::Refused
                }
            }
            Esc::Csi(params) => {
                if is_csi_param(b) || is_csi_intermediate(b) {
                    // **Over the cap the bytes stop accumulating, and the
                    // sequence is refused at its final byte** — a sequence with
                    // more parameters than any real one is a malformed one, and
                    // a bounded buffer is the alternative to a line that grows
                    // until the process dies.
                    if params.len() < CSI_PARAM_CAP {
                        params.push(b);
                    }
                    Step::Continue
                } else if is_csi_final(b) {
                    // `bare` is read **before** the state is replaced, because
                    // the replacement is what moves the parameters out.
                    let bare = params.is_empty();
                    *self = Esc::None;
                    Step::Final { final_byte: b, bare }
                } else {
                    // **The control byte.** See the module docs: a `Ctrl-C`
                    // after a stray `ESC` must still interrupt.
                    *self = Esc::None;
                    Step::Restart
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a whole string through the parser, collecting the steps.
    fn run(bytes: &[u8]) -> Vec<Step> {
        let mut esc = Esc::None;
        bytes.iter().map(|b| esc.step(*b)).collect()
    }

    #[test]
    fn a_recognised_key_is_a_bare_final() {
        // **The accepted case, and the one a guard that refuses everything
        // cannot pass.** `ESC [ C` must end in a bare `C` — `bare: true` is
        // what tells the discipline "this is the key, not a parameterised
        // motion", and it is the only thing that keeps the refusal narrow.
        let steps = run(b"\x1b[C");
        assert_eq!(steps, vec![Step::Continue, Step::Continue, Step::Final { final_byte: b'C', bare: true }]);
        assert_eq!(Esc::None, Esc::None);
    }

    #[test]
    fn the_five_recognised_keys_are_bare_finals() {
        // **Exactly `A B C D H F`, and every one of them bare.**
        for final_byte in *b"ABCDHF" {
            assert_eq!(
                run(&[0x1b, b'[', final_byte]).last(),
                Some(&Step::Final { final_byte, bare: true }),
                "final {:?}",
                final_byte as char
            );
        }
    }

    #[test]
    fn the_plant_sequence_is_consumed_whole_and_never_becomes_text() {
        // **THE PLANT, and the whole reason this module exists.**
        // `ESC [ 1 5 ~` must ring a bell and insert nothing: the `1` and the `5`
        // are **parameters**, consumed by the sequence, and `~` is its final
        // byte. **The last step is a `Final`, not a `Restart`** — a
        // `Restart` would mean `~` fell through to the line as text, which is
        // precisely the defect this parser fixes.
        let steps = run(b"\x1b[1~");
        assert_eq!(
            steps,
            vec![
                Step::Continue, // ESC
                Step::Continue, // [
                Step::Continue, // 1  — a parameter
                Step::Final { final_byte: b'~', bare: false },
            ],
            "'1' is consumed as a parameter and '~' ends the sequence"
        );

        let steps = run(b"\x1b[15~");
        assert_eq!(
            steps.last(),
            Some(&Step::Final { final_byte: b'~', bare: false }),
            "and ESC [ 1 5 ~ likewise: 1 and 5 are both parameters"
        );
    }

    #[test]
    fn the_reference_parser_produces_the_defect_this_module_fixes() {
        // **The measurement behind the divergence, kept as a test so it
        // cannot be quietly forgotten.** This is the sibling's parser,
        // transcribed exactly from `session.rs:244-262`: `ESC` then `[`, then
        // **the next byte is dispatched and the sequence is over.**
        //
        // Fed `ESC [ 1 5 ~`, it dispatches on `1` (unknown, bell) and then
        // **`5` and `~` fall through to the line as ordinary characters.**
        // That is what the entry's plant forbids — *"a bell and no state
        // change"* — and it is why the transcription stops at the byte rules
        // and not at the parser.
        fn reference(bytes: &[u8]) -> Vec<u8> {
            #[derive(Clone, Copy, PartialEq, Eq)]
            enum State {
                None,
                SawEsc,
                SawCsi,
            }
            let mut state = State::None;
            let mut inserted = Vec::new();
            for b in bytes {
                match state {
                    State::SawEsc => {
                        state = if *b == b'[' { State::SawCsi } else { State::None };
                    }
                    State::SawCsi => {
                        state = State::None; // dispatch on this byte; unknown -> bell
                    }
                    State::None => {
                        if *b == 0x1b {
                            state = State::SawEsc;
                        } else {
                            inserted.push(*b);
                        }
                    }
                }
            }
            inserted
        }

        let inserted = reference(b"\x1b[1~");
        assert_eq!(inserted, vec![b'~'], "MEASURED on the reference's own parser: '~' reaches the line");

        let inserted = reference(b"\x1b[15~");
        assert_eq!(inserted, vec![b'5', b'~'], "and for the entry's own ESC [ 1 5 ~, '5' and '~' reach the line");

        // **And what this parser does instead.** Nothing is inserted: every
        // byte after `ESC [` belongs to the sequence.
        let mut esc = Esc::None;
        let mut inserted = Vec::new();
        for b in b"\x1b[15~" {
            match esc.step(*b) {
                Step::Restart => inserted.push(*b),
                Step::Refused | Step::Continue | Step::Final { .. } => {}
            }
        }
        assert!(inserted.is_empty(), "MEASURED on this parser: nothing reaches the line");
    }

    #[test]
    fn a_control_byte_abandons_the_sequence_so_a_signal_still_signals() {
        // **The `Restart` arm, and it is load-bearing.** `ESC` followed by
        // `Ctrl-C` must interrupt; a parser that swallowed the `Ctrl-C` as part
        // of a malformed sequence would leave a user with no way to stop a
        // running command, which is the failure plant E exists to catch.
        assert_eq!(
            run(b"\x1b[1\x03"),
            vec![
                Step::Continue, // ESC
                Step::Continue, // [
                Step::Continue, // 1  — a parameter
                Step::Restart,  // 0x03 abandons the sequence and comes back
            ],
            "the 0x03 comes back as Restart, so the caller signals"
        );
    }

    #[test]
    fn an_escape_that_is_not_a_csi_is_refused_and_the_byte_is_consumed() {
        // **Transcribed**, `session.rs:248-251`: `ESC x` is a bell, and the
        // `x` does not become text either.
        assert_eq!(run(b"\x1bx"), vec![Step::Continue, Step::Refused], "the 'x' is consumed with the refused sequence");
    }

    #[test]
    fn a_parameterised_motion_is_refused_rather_than_guessed() {
        // **`ESC [ 1 C` is a real sequence** — "cursor forward one" — and the
        // cooked discipline does not implement parameterised motion. It is
        // refused rather than treated as a plain `C`, because **a discipline
        // that interprets sequences it has not tested is a discipline that will
        // corrupt somebody's terminal** — and a bare `C` handler would move the
        // cursor as though the `1` had not been there.
        let steps = run(b"\x1b[1C");
        assert_eq!(
            steps.last(),
            Some(&Step::Final { final_byte: b'C', bare: false }),
            "'C' with a parameter behind it is not the bare key"
        );
    }

    #[test]
    fn a_sequence_longer_than_the_cap_is_still_refused_and_the_state_is_bounded() {
        // **The bound, and the state it bounds.** Twenty parameter bytes is
        // not a real sequence, and the buffer stops growing at sixteen.
        let mut esc = Esc::None;
        for b in b"\x1b[0123456789012345678901234567890123456789" {
            let _ = esc.step(*b);
        }
        match &esc {
            Esc::Csi(params) => {
                assert_eq!(params.len(), CSI_PARAM_CAP, "the buffer stops at the cap");
                assert!(params.iter().all(|b| is_csi_param(*b)), "and holds only parameters");
            }
            other => panic!("the state should still be a CSI in progress: {other:?}"),
        }
        // And it still ends at a final byte, with `bare: false` because the
        // parameters are there — so the sequence is refused.
        assert_eq!(esc.step(b'~'), Step::Final { final_byte: b'~', bare: false });
    }

    #[test]
    fn the_byte_classes_do_not_overlap() {
        // **Three ranges, and a byte in two of them would make the parser's
        // order the only thing deciding what a sequence means.** Asserted
        // here so a careless edit to a boundary is caught.
        for b in 0x20u8..=0x7e {
            let count = is_csi_param(b) as u8 + is_csi_intermediate(b) as u8 + is_csi_final(b) as u8;
            assert_eq!(count, 1, "byte {b:#x} is in {count} classes");
        }
        for b in 0x00u8..0x20 {
            assert!(!is_csi_param(b) && !is_csi_intermediate(b) && !is_csi_final(b));
            assert!(!is_csi_final(b), "a control byte never ends a CSI");
        }
        for b in 0x7fu8..=0xff {
            assert!(!is_csi_param(b) && !is_csi_intermediate(b) && !is_csi_final(b));
        }
    }
}
