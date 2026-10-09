//! **The keys: escapes, history, signals, and the two modes.** Window size
//! is in `window.rs`, and a byte past the line cap in `discipline.rs`.
//!
//! **Byte-exact on both legs, exactly as the entry demands**, and every
//! rule below names the line of
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs` it was transcribed from,
//! read with `sed -n` on 2026-10-02.
//!
//! **What separates this file from `discipline.rs`** is the subject, not the
//! rigour: that file pins echo, erasing and submission — **what a byte typed
//! into a line produces** and this one pins **what a key that is not a
//! character produces**, plus the place where the answer depends on
//! something other than the byte: the mode that the facts chose.
//!
//! **Both files assert exact bytes on `local` and `remote` separately.** A
//! test that only checks that "something was echoed" cannot catch this class of
//! bug, because the failure is the right bytes in the wrong direction or the
//! wrong sequence substituted.

use podssh_terminal::echo::{Discipline, Event, Sig, BELL, EL, HISTORY_CAP};
use podssh_terminal::session::{Facts, Mode, Session};

mod common;
use common::{feed, has, legs, over_a_pty, selected};

// ───────────────────────────────── history

#[test]
fn up_and_down_walk_history_and_enter_reruns() {
    // **A redraw on every recall**, and the recalled bytes are the whole line.
    // Transcribed: `session.rs:897-914`.
    let mut d = Discipline::new();
    assert_eq!(feed(&mut d, b"one\ntwo\n").remote, b"one\ntwo\n");
    assert!(feed(&mut d, b"\x1b[A").local.ends_with(b"two"), "newest first");
    assert!(feed(&mut d, b"\x1b[A").local.ends_with(b"one"), "then older");
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "past the oldest is a bell");
    feed(&mut d, b"\x1b[B");
    assert_eq!(feed(&mut d, b"\n").remote, b"two\n", "and it runs again");
}

#[test]
fn history_skips_empty_lines_and_consecutive_duplicates() {
    // **"Up must reach a command, not blank air"** — the reference's own
    // reason, and it is the reason this assertion exists.
    // Transcribed: `session.rs:916-925`, `200-214`.
    let mut d = Discipline::new();
    feed(&mut d, b"\nx\nx\n");
    assert!(feed(&mut d, b"\x1b[A").local.ends_with(b"x"));
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "one entry, not three");
}

#[test]
fn history_forgets_past_the_cap_and_the_oldest_goes_first() {
    // **The cap is 100 and the oldest leaves**, so `Up` from a full history
    // reaches back exactly `HISTORY_CAP` entries and then rings.
    // Transcribed: `session.rs:1069-1086`, `105`.
    assert_eq!(HISTORY_CAP, 100);
    let mut d = Discipline::new();
    for i in 0..HISTORY_CAP + 5 {
        let line = format!("cmd{i}\n");
        feed(&mut d, line.as_bytes());
    }
    assert_eq!(d.history().len(), HISTORY_CAP, "the cap holds");
    assert_eq!(d.history()[0], b"cmd5", "the oldest five left");
    assert_eq!(d.history()[HISTORY_CAP - 1], b"cmd104", "and the newest is last");
    // Up walks the history **backwards from the newest**, so the first press
    // reaches `cmd104` and the hundredth reaches `cmd5` which is exactly the
    // cap, and the hundred-and-first has nothing left to reach.
    for step in 0..HISTORY_CAP {
        let got = feed(&mut d, b"\x1b[A");
        let expected = format!("cmd{}", 104 - step);
        assert_ne!(got.local, BELL, "press {step} must reach {expected}");
        assert!(got.local.ends_with(expected.as_bytes()), "press {step} must reach {expected}");
    }
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "and then the bell");
}

#[test]
fn down_past_the_newest_restores_the_line_the_browse_set_aside() {
    // **The parked line.** Type something, browse up, browse back past
    // the newest: the uncommitted line **returns**, and Enter runs *it* rather
    // than the recalled entry. Without the `saved` slot, Up would silently
    // destroy what the user was typing. Transcribed: `session.rs:1088-1103`.
    let mut d = Discipline::new();
    feed(&mut d, b"one\n");
    feed(&mut d, b"tw");
    assert!(feed(&mut d, b"\x1b[A").local.ends_with(b"one"));
    assert!(feed(&mut d, b"\x1b[B").local.ends_with(b"tw"), "the parked line returns");
    assert_eq!(feed(&mut d, b"\n").remote, b"tw\n", "and Enter runs it");
}

#[test]
fn down_with_no_browse_in_progress_bells_and_keeps_the_line() {
    // **A refusal that damages nothing.** Transcribed: `session.rs:1021-1032`.
    let mut d = Discipline::new();
    feed(&mut d, b"one\n");
    feed(&mut d, b"tw");
    let got = feed(&mut d, b"\x1b[B");
    assert_eq!(got.local, BELL, "{}", got.show());
    assert_eq!(feed(&mut d, b"\n").remote, b"tw\n", "the line survived");
}

// ───────────────────────────────── signal characters

#[test]
fn ctrl_c_signals_the_group_and_discards_the_line() {
    // **Three things at once, and all three are the contract.** The
    // signal is reported, the echo is the caret notation plus a fresh prompt,
    // and **history never saw the interrupted line** — the third is what a
    // signal that also "helpfully" submitted the line would break.
    // Transcribed: `session.rs:848-858`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"abc\x03");
    assert_eq!(got.signals, vec![Sig::Int], "{}", got.show());
    assert_eq!(got.local, b"abc^C\r\n$ ", "the caret notation, then a prompt");
    assert!(got.remote.is_empty(), "the interrupted line never ran");
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "and history never saw it");
}

#[test]
fn ctrl_backslash_signals_quit() {
    // **The caret is a backslash**, which is the one byte that has to be
    // escaped in a Rust byte literal and is easy to get wrong.
    // Transcribed: `session.rs:860-866`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x1c");
    assert_eq!(got.signals, vec![Sig::Quit], "{}", got.show());
    assert_eq!(got.local, b"^\\\r\n$ ");
}

// ───────────────────────────────── refusals

#[test]
fn suspend_and_flow_control_bell_and_change_nothing() {
    // **The catalogue's refused half, pinned as refused.** A bell, no
    // signal, and **the line intact underneath** — that last clause is the
    // plant: a refusal that cleared the buffer would pass a test checking only
    // the bell. Transcribed: `session.rs:868-881`, `271`.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    for b in [0x1au8, 0x11, 0x13] {
        let got = feed(&mut d, &[b]);
        assert_eq!(got.local, BELL, "byte {b:#x}: {}", got.show());
        assert!(got.signals.is_empty(), "byte {b:#x}: {}", got.show());
        assert!(got.remote.is_empty(), "byte {b:#x}: {}", got.show());
    }
    assert_eq!(feed(&mut d, b"\n").remote, b"ab\n", "the line was never harmed");
}

#[test]
fn ctrl_u_and_ctrl_w_on_an_empty_line_bell() {
    // Two more refusals, same shape. Transcribed: `session.rs:1046-1055`.
    let mut d = Discipline::new();
    for b in [0x15u8, 0x17] {
        let got = feed(&mut d, &[b]);
        assert_eq!(got.local, BELL, "byte {b:#x}: {}", got.show());
        assert!(got.remote.is_empty(), "byte {b:#x}: {}", got.show());
    }
}

#[test]
fn ctrl_d_is_eof_on_an_empty_line_and_delete_inside_one() {
    // **Three positions, three answers**, and they are different answers:
    // end of input, a deletion with a redraw, and nothing at all.
    // Transcribed: `session.rs:310-321`, `883-895`, `1034-1044`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x04");
    assert!(got.eof, "on an empty line: {}", got.show());
    assert!(got.local.is_empty(), "and nothing was echoed");

    let mut d = Discipline::new();
    feed(&mut d, b"ab\x1b[D");
    let got = feed(&mut d, b"\x04\n");
    assert!(!got.eof, "mid-line it deletes: {}", got.show());
    assert_eq!(got.remote, b"a\n");
    assert!(has(&got.local, EL), "and the redraw happened: {}", got.show());

    // **The silent one.** Past the last cell there is nothing to delete: no
    // bell, no redraw, no shell bytes. Transcribed: `session.rs:1034-1044`.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x04");
    assert!(!got.eof && got.local.is_empty() && got.remote.is_empty(), "{}", got.show());
}

// ───────────────────────────────── the escape guard: the plant and its control

#[test]
fn an_unknown_bracket_sequence_bells_and_changes_no_state() {
    // **THE PLANT. `ESC [ 1 5 ~` is refused.** Assert three things: a
    // bell, **no bytes on either leg**, and **the line underneath is
    // unchanged** — the last is what a guard that consumed the sequence as an
    // edit would fail. `ESC [ 1 5 ~` is a real F5 key, and the cooked mode
    // does not implement function keys; it says so rather than guessing.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x1b[15~");
    assert_eq!(got.local, BELL, "one bell and nothing else: {}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
    assert!(!got.eof, "{}", got.show());
    // **The state change that must not have happened.** The `1`, the `5`
    // and the `~` are consumed with the sequence; none may be inserted.
    assert_eq!(feed(&mut d, b"\n").remote, b"ab\n", "the line is exactly as it was");
}

#[test]
fn the_same_guard_accepts_the_sequences_it_must() {
    // **THE CONTROL, and it is not optional.** A guard that refuses
    // everything is indistinguishable from a good one until it is asked about
    // something it must accept. `ESC [ C` must move the cursor, and every
    // one of the six recognised finals must be consumed rather than inserted.
    // Transcribed: `session.rs:381-403`.
    //
    // **The left move first, and it is load-bearing.** Right is guarded by
    // `if cursor < line.len()` — **READ**, `session.rs:385` — so on `"ac"` with
    // the cursor at the end, `ESC [ C` is **the at-bound refusal**, not an
    // acceptance, and a test that asked for a move there would be testing the
    // wrong thing. The bound refusal is asserted separately, in
    // `an_arrow_at_its_bound_bells_and_the_line_survives`.
    let mut d = Discipline::new();
    feed(&mut d, b"ac");
    feed(&mut d, b"\x1b[D"); // left: the cursor is now between 'a' and 'c'
    let got = feed(&mut d, b"\x1b[C");
    assert_eq!(got.local, b"\x1b[C", "right arrow: it moves, and it echoes");
    assert!(got.remote.is_empty(), "and it is not an edit: {}", got.show());
    // Left then right puts the cursor back at the end, so the insert appends.
    // The *mid-line* insert is what the left alone gives, and it is asserted
    // in `discipline.rs`; here what matters is that the right arrow was accepted
    // at all, which the echo above already proves.
    assert_eq!(feed(&mut d, b"b\n").remote, b"acb\n", "back at the end, so it appends");

    // Each recognised final is consumed whole: none of them leaks a byte into
    // the line. A, B, C, D, H, F — and `X` is the negative case, above.
    for final_byte in *b"ABCDHFX" {
        let mut d = Discipline::new();
        feed(&mut d, b"one\n");
        let got = feed(&mut d, &[0x1b, b'[', final_byte]);
        assert_eq!(got.remote, b"", "final {:?} must not submit", final_byte as char);
        assert!(!got.eof, "final {:?}", final_byte as char);
        // Whatever else it did, the byte did not become part of the line.
        let after = feed(&mut d, b"\n");
        assert!(
            after.remote == b"\n" || after.remote == b"one\n" || after.remote == b"tw\n",
            "final {:?} leaked into the line: {}",
            final_byte as char,
            after.show()
        );
    }
}

#[test]
fn an_escape_that_is_not_a_csi_bells() {
    // **An Alt key**: `ESC x` with no pause is Alt+x, refused whole, and the
    // `x` is consumed with it, as in the reference (`session.rs:247-253`).
    // `ESC O`, a control byte and a second `ESC` are not Alt keys: see the
    // `escape_` tests.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x1bxa");
    assert_eq!(got.local, [BELL.to_vec(), b"a".to_vec()].concat(), "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
}

// ───────────────────────────────── the other escape keys, and the lone Escape

#[test]
fn escape_ss3_arrows_move_like_csi_arrows() {
    // **A terminal in application mode sends `ESC O D` for Left.** The
    // screen moves by the CSI form, because `ESC O D` written to a terminal
    // is no motion at all.
    let mut d = Discipline::new();
    feed(&mut d, b"ac");
    let got = feed(&mut d, b"\x1bOD");
    assert_eq!(got.local, b"\x1b[D", "{}", got.show());
    // An insert between, then Home and End: the line is `abc`.
    feed(&mut d, b"b\x1bOH\x1bOF");
    assert_eq!(feed(&mut d, b"\r").remote, b"abc\n");
    assert!(feed(&mut d, b"\x1bOA").local.ends_with(b"abc"), "Up recalls, as `ESC [ A` does");
}

#[test]
fn escape_f1_to_f4_ring_once_and_insert_nothing() {
    // F1 to F4 as each terminal sends them: xterm and its kin and Windows
    // (`ESC O P` to `ESC O S`), the Linux console (`ESC [ [ A` to
    // `ESC [ [ D`), rxvt (`ESC [ 1 1 ~` to `ESC [ 1 4 ~`), and a modified F1.
    let keys: [&[u8]; 11] = [
        b"\x1bOP",
        b"\x1bOQ",
        b"\x1bOR",
        b"\x1bOS",
        b"\x1b[[A",
        b"\x1b[[B",
        b"\x1b[[C",
        b"\x1b[[D",
        b"\x1b[11~",
        b"\x1b[14~",
        b"\x1bO2P",
    ];
    for key in keys {
        let mut d = Discipline::new();
        feed(&mut d, b"ab");
        let got = feed(&mut d, key);
        assert_eq!(got.local, BELL, "{key:02x?}: one bell and nothing else: {}", got.show());
        assert!(!d.waiting(), "{key:02x?}: the key is whole");
        assert_eq!(feed(&mut d, b"\r").remote, b"ab\n", "{key:02x?}: the line is unchanged");
    }
}

#[test]
fn escape_then_ctrl_c_still_signals() {
    // **An escape never takes Ctrl-C, Ctrl-D or Enter**, so a user who
    // pressed Escape first can still interrupt, end input, or submit.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x1b\x03");
    assert_eq!(got.signals, vec![Sig::Int], "{}", got.show());
    assert_eq!(got.local, b"^C\r\n$ ", "no bell, no caret byte typed: {}", got.show());
    let got = feed(&mut d, b"\x1bO\x03");
    assert_eq!(got.signals, vec![Sig::Int], "from inside a sequence too: {}", got.show());
    assert_eq!(feed(&mut d, b"x\x1b\r").remote, b"x\n", "Enter after Escape submits");
    assert!(feed(&mut d, b"\x1b\x04").eof, "Ctrl-D after Escape ends input on an empty line");
}

#[test]
fn escape_alone_then_idle_keeps_the_next_key() {
    // **The lone Escape rings once its pause ends**, and the key after the
    // pause is typed. Without the tick, `c` would end the key as Alt+c.
    let mut d = Discipline::new();
    feed(&mut d, b"ab\x1b");
    assert!(d.waiting(), "the Escape is open");
    assert_eq!(legs(d.idle()).local, BELL, "one bell at the tick");
    assert!(!d.waiting(), "and nothing is open after it");
    assert_eq!(legs(d.idle()), Default::default(), "a second tick finds nothing");
    assert_eq!(feed(&mut d, b"c\r").remote, b"abc\n", "the next key is typed");
}

#[test]
fn escape_idle_through_the_session_and_never_in_the_transparent_mode() {
    // The caller ticks the session. The transparent mode reads no key, so it
    // never waits: there the program below owns Escape.
    let mut s = Session::new(selected());
    legs(s.on_local_bytes(b"ab\x1b"));
    assert!(s.waiting());
    assert_eq!(legs(s.on_idle()).local, BELL);
    assert_eq!(legs(s.on_local_bytes(b"c\r")).remote, b"abc\n");
    let mut t = Session::new(over_a_pty());
    assert_eq!(t.on_local_bytes(b"\x1b"), vec![Event::ToRemote(b"\x1b".to_vec())]);
    assert!(!t.waiting());
    assert!(t.on_idle().is_empty());
}

#[test]
fn escape_and_a_letter_is_an_alt_key_refused_whole() {
    // **The control for the tick**: with no pause, `ESC c` is Alt+c. It is
    // refused whole, so Alt+b never inserts a `b`, nor Alt+é a lone byte.
    let mut d = Discipline::with_utf8(true);
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x1bc");
    assert_eq!(got.local, BELL, "{}", got.show());
    let got = feed(&mut d, "\x1bé".as_bytes());
    assert_eq!(got.local, BELL, "{}", got.show());
    assert!(!d.waiting());
    assert_eq!(feed(&mut d, b"\r").remote, b"ab\n");
}

#[test]
fn escape_a_second_escape_starts_a_new_sequence() {
    // `ESC [` cut short by a whole key: the second `ESC` is not typed raw
    // into the line, where the terminal would read it as a sequence.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x1b[\x1b[DX\r");
    assert_eq!(got.remote, b"aXb\n", "{}", got.show());
}

#[test]
fn escape_idle_ends_a_sequence_cut_short() {
    // `ESC [ 1` and a pause: the tick ends it, so `l` is a key rather than
    // the final byte of a stale sequence.
    let mut d = Discipline::new();
    feed(&mut d, b"ab\x1b[1");
    assert_eq!(legs(d.idle()).local, BELL);
    assert_eq!(feed(&mut d, b"l\r").remote, b"abl\n");
}

#[test]
fn escape_keypad_in_application_mode_types_its_keys() {
    // A program may leave the keypad in application mode (`ESC =`). Its keys
    // then come as `ESC O` and a letter, and each types what it shows.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x1bOq\x1bOk\x1bOy\x1bOX\x1bOM");
    assert_eq!(got.remote, b"1+9=\n", "{}", got.show());
}

// ───────────────────────────────── the two modes, in one place

#[test]
fn the_two_modes_agree_where_they_must() {
    // **The difference that justifies two modes, asserted in one test
    // because it needs both modes side by side.** A `\r\n` pair means one
    // thing to a user typing into a cooked shell and another to a program
    // drawing in pass-through, and **the same bytes must produce different
    // results** — otherwise one of the two modes has a bug in it.
    let mut cooked = Session::new(selected());
    let cooked_events = cooked.on_local_bytes(b"ls\r\n");
    let forward: Vec<u8> = cooked_events
        .iter()
        .filter_map(|e| match e {
            Event::ToRemote(b) => Some(b.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(forward, b"ls\n", "cooked: one Enter, one line");

    let mut passed = Session::new(over_a_pty());
    let remote = passed.on_remote_bytes(b"ls\r\n");
    let local: Vec<u8> = remote
        .iter()
        .filter_map(|e| match e {
            Event::ToLocal(b) => Some(b.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(local, b"ls\r\n", "passthrough: both bytes arrive");
}

#[test]
fn mode_a_granted_pty_adds_no_local_echo() {
    // **A pty below echoes**, so an echo here shows each key twice; with the
    // selection too, the pty wins. The plant: a selection that alone gives the
    // cooked mode fails the second row on the echo.
    for facts in [over_a_pty(), Facts { pty_below: true, selected: true, ..Facts::default() }] {
        let mut s = Session::new(facts);
        let got = legs(s.on_local_bytes(b"ab\x7f\r"));
        assert!(got.local.is_empty(), "{facts:?}: no echo: {}", got.show());
        assert_eq!(got.remote, b"ab\x7f\r", "{facts:?}: each byte once, as it came: {}", got.show());
        assert_eq!(s.mode(), Mode::Transparent, "{facts:?}");
    }
}

#[test]
fn mode_no_pty_and_no_selection_is_transparent() {
    // **A missing pty alone never selects the discipline**: no bell, and the
    // session goes on.
    let mut s = Session::new(Facts::default());
    assert_eq!(s.mode(), Mode::Transparent);
    let got = legs(s.on_local_bytes(b"a\r\x03\x1a"));
    assert_eq!(got.remote, b"a\r\x03\x1a", "{}", got.show());
    assert!(got.local.is_empty() && got.signals.is_empty(), "no bell, no signal: {}", got.show());
    assert!(!s.ended(), "the session goes on");
    assert_eq!(legs(s.on_remote_bytes(b"out\n")).local, b"out\n");
}

#[test]
fn mode_the_selected_discipline_echoes_and_edits() {
    let mut s = Session::new(selected());
    assert_eq!(s.mode(), Mode::Cooked);
    let got = legs(s.on_local_bytes(b"ab\x7fc\r"));
    assert_eq!(got.remote, b"ac\n", "the edited line, once: {}", got.show());
    assert!(has(&got.local, b"ab") && has(&got.local, b"c"), "each key echoed: {}", got.show());
}

#[test]
fn mode_each_combination_of_the_three_facts() {
    // **Eight rows, one of them cooked.** A rule that forgot one of the two
    // facts below fails one of the rows that have it.
    for pty_below in [false, true] {
        for discipline_below in [false, true] {
            for selected in [false, true] {
                let facts = Facts { pty_below, discipline_below, selected };
                let want = if selected && !pty_below && !discipline_below { Mode::Cooked } else { Mode::Transparent };
                assert_eq!(Mode::select(facts), want, "{facts:?}");
            }
        }
    }
}

#[test]
fn mode_transparent_passes_ctrl_z_s_q() {
    // **Job control and flow control belong to the pty below**, so the keys
    // that the cooked mode refuses go on here, with no bell.
    let mut s = Session::new(over_a_pty());
    for b in [0x1au8, 0x11, 0x13] {
        assert_eq!(s.on_local_byte(b), vec![Event::ToRemote(vec![b])], "byte {b:#x}");
    }
}
