//! The parser's own tests: each state, the bytes that end it, and the
//! measurement of the reference's parser.

use super::*;

/// Run a whole string through the parser, collecting the steps.
fn run(bytes: &[u8]) -> Vec<Step> {
    let mut esc = Esc::None;
    bytes.iter().map(|b| esc.step(*b)).collect()
}

/// The parser after these bytes.
fn after(bytes: &[u8]) -> Esc {
    let mut esc = Esc::None;
    for b in bytes {
        let _ = esc.step(*b);
    }
    esc
}

/// The end of a CSI with this final byte and parameter.
fn csi(final_byte: u8, param: Param) -> Step {
    Step::Final { intro: Intro::Csi, final_byte, param }
}

/// The end of an SS3 with this final byte and parameter.
fn ss3(final_byte: u8, param: Param) -> Step {
    Step::Final { intro: Intro::Ss3, final_byte, param }
}

/// The prefix of each state that a sequence can be in.
const OPEN: [&[u8]; 6] = [b"\x1b", b"\x1b[", b"\x1b[1", b"\x1bO", b"\x1b[[", b"\x1b\xe2\x82"];

#[test]
fn a_recognised_key_is_a_bare_final() {
    // **The accepted case, and the one a guard that refuses everything
    // cannot pass.** `ESC [ C` must end in a `C` with no parameter — that
    // is what tells the discipline "this is the key, not a parameterised
    // motion", and it is the only thing that keeps the refusal narrow.
    let steps = run(b"\x1b[C");
    assert_eq!(steps, vec![Step::Continue, Step::Continue, csi(b'C', Param::None)]);
    assert_eq!(after(b"\x1b[C"), Esc::None, "the sequence is over at its final byte");
}

#[test]
fn the_five_recognised_keys_are_bare_finals() {
    // **Exactly `A B C D H F`, and every one of them bare**, in both forms:
    // a terminal in application mode sends `ESC O` where others send `ESC [`.
    for final_byte in *b"ABCDHF" {
        let name = final_byte as char;
        assert_eq!(run(&[0x1b, b'[', final_byte]).last(), Some(&csi(final_byte, Param::None)), "CSI {name}");
        assert_eq!(run(&[0x1b, b'O', final_byte]).last(), Some(&ss3(final_byte, Param::None)), "SS3 {name}");
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
            csi(b'~', Param::Number(1)),
        ],
        "'1' is consumed as a parameter and '~' ends the sequence"
    );

    let steps = run(b"\x1b[15~");
    assert_eq!(
        steps.last(),
        Some(&csi(b'~', Param::Number(15))),
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
    // **And from each other open state**, a lone `ESC` first among them:
    // Ctrl-C, Ctrl-D and Enter are never part of an escape.
    for prefix in OPEN {
        for key in [0x03u8, 0x04, b'\r', b'\n'] {
            let bytes = [prefix, &[key]].concat();
            assert_eq!(run(&bytes).last(), Some(&Step::Restart), "{bytes:02x?}");
        }
    }
}

#[test]
fn an_escape_that_is_not_a_csi_is_refused_and_the_byte_is_consumed() {
    // **An Alt key**: `ESC x` is how a terminal sends Alt+x, and no Alt key
    // is bound. So it is a bell, and the `x` does not become text either, as
    // in the reference (`session.rs:248-251`).
    assert_eq!(run(b"\x1bx"), vec![Step::Continue, Step::Refused], "the 'x' is consumed with the refused sequence");
    assert_eq!(after(b"\x1bx"), Esc::None, "and the next byte is a key");
}

#[test]
fn an_alt_key_with_a_character_of_several_bytes_is_refused_whole() {
    // Alt+é and Alt+€: one refusal at the last byte, so no lone
    // continuation byte reaches the line.
    assert_eq!(run(b"\x1b\xc3\xa9"), vec![Step::Continue, Step::Continue, Step::Refused]);
    assert_eq!(run(b"\x1b\xe2\x82\xac"), vec![Step::Continue, Step::Continue, Step::Continue, Step::Refused]);
    // A byte that cannot continue the character is a key of its own.
    assert_eq!(run(b"\x1b\xc3a").last(), Some(&Step::Restart));
}

#[test]
fn ss3_reads_a_final_and_a_parameter_as_a_csi_does() {
    // F1 is `ESC O P`; some terminals send Shift+F1 as `ESC O 2 P`.
    assert_eq!(run(b"\x1bOP"), vec![Step::Continue, Step::Continue, ss3(b'P', Param::None)]);
    assert_eq!(run(b"\x1bO2P").last(), Some(&ss3(b'P', Param::Number(2))));
    // The keypad in application mode: Enter is `ESC O M`.
    assert_eq!(run(b"\x1bOM").last(), Some(&ss3(b'M', Param::None)));
}

#[test]
fn the_linux_console_form_takes_one_more_byte() {
    // The Linux console sends F1 as `ESC [ [ A`. The second `[` is a final
    // byte of a CSI, and reading it as one would type the `A`.
    assert_eq!(run(b"\x1b[[A"), vec![Step::Continue, Step::Continue, Step::Continue, Step::Refused]);
    assert_eq!(after(b"\x1b[[A"), Esc::None);
    // The `[` opens the form only right after `ESC [`: `ESC [ 1 [` is a
    // CSI with a parameter, ended by the `[`.
    assert_eq!(run(b"\x1b[1[").last(), Some(&csi(b'[', Param::Number(1))));
}

#[test]
fn escape_starts_a_new_sequence_in_every_state() {
    // **A second `ESC` is never text.** Read as a control byte, it would
    // restart as a key and go into the line raw.
    for prefix in OPEN {
        let bytes = [prefix, b"\x1b"].concat();
        assert_eq!(run(&bytes).last(), Some(&Step::Continue), "{bytes:02x?}");
        assert_eq!(after(&bytes), Esc::Escape, "{bytes:02x?}");
    }
    assert_eq!(run(b"\x1b[\x1b[D").last(), Some(&csi(b'D', Param::None)));
}

#[test]
fn abandon_ends_each_open_state_and_says_whether_one_was_open() {
    // **The idle tick.** Each open state ends, and only an open one asks
    // for the bell.
    for prefix in OPEN {
        let mut esc = after(prefix);
        assert!(esc.is_open(), "{prefix:02x?}");
        assert!(esc.abandon(), "{prefix:02x?}");
        assert_eq!(esc, Esc::None, "{prefix:02x?}");
        assert!(!esc.abandon(), "a second tick finds nothing open");
    }
    assert!(!after(b"\x1b[C").is_open(), "a whole key leaves nothing open");
}

#[test]
fn param_reads_one_number_and_nothing_else() {
    assert_eq!(Param::read(b""), Param::None);
    assert_eq!(Param::read(b"3"), Param::Number(3));
    assert_eq!(Param::read(b"15"), Param::Number(15));
    assert_eq!(Param::read(b"65535"), Param::Number(65535));
    // Past `u16`, two numbers, a private marker, an intermediate.
    for other in [&b"65536"[..], b"1;5", b"?1", b"1 ", b";"] {
        assert_eq!(Param::read(other), Param::Other, "{other:?}");
    }
    // A run at the cap may have lost bytes, so it is not a number.
    assert_eq!(Param::read(&[b'0'; CSI_PARAM_CAP]), Param::Other);
}

#[test]
fn a_parameterised_motion_is_refused_rather_than_guessed() {
    // **`ESC [ 1 C` is a real sequence** — "cursor forward one" — and the
    // cooked discipline does not implement parameterised motion. It is
    // refused rather than treated as a plain `C`, because **a discipline
    // that interprets sequences it has not tested is a discipline that will
    // corrupt somebody's terminal** — and a plain `C` handler would move the
    // cursor as though the `1` had not been there.
    let steps = run(b"\x1b[1C");
    assert_eq!(steps.last(), Some(&csi(b'C', Param::Number(1))), "'C' with a parameter behind it is not the key");
}

#[test]
fn a_sequence_longer_than_the_cap_is_still_refused_and_the_state_is_bounded() {
    // **The bound, and the state it bounds.** Twenty parameter bytes is
    // not a real sequence, and the buffer stops growing at sixteen.
    let mut esc = after(b"\x1b[0123456789012345678901234567890123456789");
    match &esc {
        Esc::Csi(params) => {
            assert_eq!(params.len(), CSI_PARAM_CAP, "the buffer stops at the cap");
            assert!(params.iter().all(|b| is_csi_param(*b)), "and holds only parameters");
        }
        other => panic!("the state should still be a CSI in progress: {other:?}"),
    }
    // And it still ends at a final byte, with a parameter that is not a
    // number, so the sequence is refused.
    assert_eq!(esc.step(b'~'), csi(b'~', Param::Other));
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
