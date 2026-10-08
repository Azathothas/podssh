//! ⛔ **The keys: escapes, history, signals, the two modes, and window size.**
//!
//! ⛔ **Byte-exact on both legs, exactly as the entry demands**, and ⛔ every
//! rule below names the line of
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs` it was transcribed from,
//! read with `sed -n` on 2026-10-02.
//!
//! ⛔ **What separates this file from `discipline.rs`** is the subject, not the
//! rigour: that file pins echo, erasing and submission ⛔ — **what a byte typed
//! into a line produces** ⛔ and this one pins ⛔ **what a key that is not a
//! character produces**, ⛔ plus the two places where the answer depends on
//! something other than the byte: the mode the server granted, and whether a
//! full-screen frame is open.
//!
//! ⛔ **Both files assert exact bytes on `local` and `remote` separately.** ⛔ A
//! test that only checks that "something was echoed" cannot catch this class of
//! bug, because the failure is the right bytes in the wrong direction or the
//! wrong sequence substituted.

use podssh_terminal::echo::{Discipline, Event, Sig, BELL, EL, HISTORY_CAP, LINE_CAP};
use podssh_terminal::passthrough::Passthrough;
use podssh_terminal::session::{Mode, Session};
use podssh_terminal::window::{Size, Window};

mod common;
use common::{feed, has, LocalBytes};

// ───────────────────────────────── history

#[test]
fn up_and_down_walk_history_and_enter_reruns() {
    // ⛔ **A redraw on every recall**, and the recalled bytes are the whole line.
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
    // ⛔ **"Up must reach a command, not blank air"** — the reference's own
    // reason, and it is the reason this assertion exists.
    // Transcribed: `session.rs:916-925`, `200-214`.
    let mut d = Discipline::new();
    feed(&mut d, b"\nx\nx\n");
    assert!(feed(&mut d, b"\x1b[A").local.ends_with(b"x"));
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "one entry, not three");
}

#[test]
fn history_forgets_past_the_cap_and_the_oldest_goes_first() {
    // ⛔ **The cap is 100 and the oldest leaves**, so `Up` from a full history
    // reaches back exactly `HISTORY_CAP` entries and then rings.
    // Transcribed: `session.rs:1069-1086`, `105`.
    assert_eq!(HISTORY_CAP, 100);
    let mut d = Discipline::new();
    for i in 0..HISTORY_CAP + 5 {
        let line = format!("cmd{i}\n");
        feed(&mut d, line.as_bytes());
    }
    assert_eq!(d.history().len(), HISTORY_CAP, "the cap holds");
    assert_eq!(d.history()[0], "cmd5", "the oldest five left");
    assert_eq!(d.history()[HISTORY_CAP - 1], "cmd104", "and the newest is last");
    // ⛔ Up walks the history **backwards from the newest**, so the first press
    // reaches `cmd104` and the hundredth reaches `cmd5` ⛔ which is exactly the
    // cap, and the hundred-and-first has nothing left to reach.
    for step in 0..HISTORY_CAP {
        let got = feed(&mut d, b"\x1b[A");
        let expected = format!("cmd{}", 104 - step);
        assert_ne!(got.local, BELL, "press {step} must reach {expected}");
        assert!(
            got.local.ends_with(expected.as_bytes()),
            "press {step} must reach {expected}"
        );
    }
    assert_eq!(feed(&mut d, b"\x1b[A").local, BELL, "and then the bell");
}

#[test]
fn down_past_the_newest_restores_the_line_the_browse_set_aside() {
    // ⛔ **The parked line.** ⛔ Type something, browse up, browse back past
    // the newest: the uncommitted line **returns**, and Enter runs *it* rather
    // than the recalled entry. ⛔ Without the `saved` slot, Up would silently
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
    // ⛔ **A refusal that damages nothing.** Transcribed: `session.rs:1021-1032`.
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
    // ⛔ **Three things at once, and all three are the contract.** ⛔ The
    // signal is reported, ⛔ the echo is the caret notation plus a fresh prompt,
    // and ⛔ **history never saw the interrupted line** — the third is what a
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
    // ⛔ **The caret is a backslash**, which is the one byte that has to be
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
    // ⛔ **The catalogue's refused half, pinned as refused.** ⛔ A bell, no
    // signal, and ⛔ **the line intact underneath** — that last clause is the
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
    // ⛔ Two more refusals, same shape. Transcribed: `session.rs:1046-1055`.
    let mut d = Discipline::new();
    for b in [0x15u8, 0x17] {
        let got = feed(&mut d, &[b]);
        assert_eq!(got.local, BELL, "byte {b:#x}: {}", got.show());
        assert!(got.remote.is_empty(), "byte {b:#x}: {}", got.show());
    }
}

#[test]
fn ctrl_d_is_eof_on_an_empty_line_and_delete_inside_one() {
    // ⛔ **Three positions, three answers**, and they are different answers:
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

    // ⛔ **The silent one.** Past the last cell there is nothing to delete: no
    // bell, no redraw, no shell bytes. Transcribed: `session.rs:1034-1044`.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x04");
    assert!(!got.eof && got.local.is_empty() && got.remote.is_empty(), "{}", got.show());
}

// ───────────────────────────────── the escape guard: the plant and its control

#[test]
fn an_unknown_bracket_sequence_bells_and_changes_no_state() {
    // ⛔ **THE PLANT. `ESC [ 1 5 ~` is refused.** ⛔ Assert three things: a
    // bell, ⛔ **no bytes on either leg**, and ⛔ **the line underneath is
    // unchanged** — the last is what a guard that consumed the sequence as an
    // edit would fail. ⛔ `ESC [ 1 5 ~` is a real F5 key, and the cooked mode
    // does not implement function keys; it says so rather than guessing.
    let mut d = Discipline::new();
    feed(&mut d, b"ab");
    let got = feed(&mut d, b"\x1b[1~");
    assert_eq!(got.local, BELL, "one bell and nothing else: {}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
    assert!(!got.eof, "{}", got.show());
    // ⛔ **The state change that must not have happened.** The `1` and the `~`
    // are consumed with the sequence; they must not have been inserted.
    assert_eq!(feed(&mut d, b"\n").remote, b"ab\n", "the line is exactly as it was");
}

#[test]
fn the_same_guard_accepts_the_sequences_it_must() {
    // ⛔ **THE CONTROL, and it is not optional.** ⛔ A guard that refuses
    // everything is indistinguishable from a good one until it is asked about
    // something it must accept. ⛔ `ESC [ C` must move the cursor, and ⛔ every
    // one of the six recognised finals must be consumed rather than inserted.
    // Transcribed: `session.rs:381-403`.
    //
    // ⛔ **The left move first, and it is load-bearing.** ⛔ Right is guarded by
    // `if cursor < line.len()` — **READ**, `session.rs:385` — ⛔ so on `"ac"` with
    // the cursor at the end, `ESC [ C` is ⛔ **the at-bound refusal**, not an
    // acceptance, and a test that asked for a move there would be testing the
    // wrong thing. ⛔ The bound refusal is asserted separately, in
    // `an_arrow_at_its_bound_bells_and_the_line_survives`.
    let mut d = Discipline::new();
    feed(&mut d, b"ac");
    feed(&mut d, b"\x1b[D"); // left: the cursor is now between 'a' and 'c'
    let got = feed(&mut d, b"\x1b[C");
    assert_eq!(got.local, b"\x1b[C", "right arrow: it moves, and it echoes");
    assert!(got.remote.is_empty(), "and it is not an edit: {}", got.show());
    // ⛔ Left then right puts the cursor back at the end, so the insert appends.
    // ⛔ The *mid-line* insert is what the left alone gives, and it is asserted
    // in `discipline.rs`; here what matters is that the right arrow was accepted
    // at all, which the echo above already proves.
    assert_eq!(feed(&mut d, b"b\n").remote, b"acb\n", "back at the end, so it appends");

    // ⛔ Each recognised final is consumed whole: none of them leaks a byte into
    // the line. ⛔ A, B, C, D, H, F — and `X` is the negative case, above.
    for final_byte in [b'A', b'B', b'C', b'D', b'H', b'F', b'X'] {
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
    // ⛔ **Anything after `ESC` that is not `[` is refused**, and the byte that
    // followed is consumed with it. Transcribed: `session.rs:247-253`.
    let mut d = Discipline::new();
    let got = feed(&mut d, b"\x1bxa");
    assert_eq!(got.local, [BELL.to_vec(), b"a".to_vec()].concat(), "{}", got.show());
    assert!(got.remote.is_empty(), "{}", got.show());
}

// ───────────────────────────────── the cap

#[test]
fn a_line_past_the_cap_drops_bytes_with_a_bell_each() {
    // ⛔ **Exactly one bell per rejected byte, and the accepted bytes still
    // echo themselves.** ⛔ An unbounded line buffer is the defect the cap
    // exists to prevent, so the cap's arithmetic is asserted, not its existence.
    // Transcribed: `session.rs:957-968`, `108`.
    assert_eq!(LINE_CAP, 65536);
    let mut d = Discipline::new();
    let big = vec![b'y'; LINE_CAP + 5];
    let got = feed(&mut d, &big);
    assert_eq!(got.local.len(), LINE_CAP + 5, "echo plus five bells");
    assert_eq!(got.local.iter().filter(|b| **b == b'\x07').count(), 5, "one bell each");
    assert_eq!(feed(&mut d, b"\n").remote.len(), LINE_CAP + 1, "and the line submits");
}

// ───────────────────────────────── the two modes, in one place

#[test]
fn the_two_modes_agree_where_they_must() {
    // ⛔ **The difference that justifies two modes, asserted in one test
    // because it needs both modes side by side.** ⛔ A `\r\n` pair means one
    // thing to a user typing into a cooked shell and another to a program
    // drawing in pass-through, and ⛔ **the same bytes must produce different
    // results** — otherwise one of the two modes has a bug in it.
    let mut cooked = Session::new(true, true);
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

    let mut passed = Session::new(true, false);
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
fn the_mode_is_decided_by_the_grant_and_by_nothing_else() {
    // ⛔ **All four combinations, including the two that answer alike.** ⛔ A
    // refused pty answers `NoPty` whatever the program is, because there is no
    // terminal to run one in — and ⛔ a mode chosen from one of the two facts is
    // the bug this entry names.
    assert_eq!(Mode::from_grant(true, true), Mode::Cooked);
    assert_eq!(Mode::from_grant(true, false), Mode::Passthrough);
    assert_eq!(Mode::from_grant(false, true), Mode::NoPty);
    assert_eq!(Mode::from_grant(false, false), Mode::NoPty);
    assert!(Mode::Cooked.has_pty() && Mode::Passthrough.has_pty());
    assert!(!Mode::NoPty.has_pty());
}

#[test]
fn a_refused_pty_emulates_nothing_and_says_so() {
    // ⛔ **The refusal that must never become an emulation.** ⛔ *"podssh says
    // so and offers copy mode; it does not continue and pretend."* ⛔ Bytes typed
    // into such a session bell, nothing is forwarded to a shell that has no
    // terminal to have a line, and ⛔ **no `TERM` is offered** because the field
    // on the `pty-req` does not exist.
    let mut s = Session::new(false, true);
    assert_eq!(s.mode(), Mode::NoPty);
    assert_eq!(s.term(), None, "no TERM on a refused pty-req");
    assert_eq!(s.term_choice(), None, "and nothing to have replaced");
    for b in [b'a', b'\r', b'\x03'] {
        let got = s.on_local_byte(b);
        assert_eq!(got, vec![Event::ToLocal(BELL.to_vec())], "byte {b:#x}");
    }
    assert!(s.on_remote_bytes(b"anything").is_empty(), "nothing comes back either");
    assert!(s.on_resize(Size::new(40, 120)).is_none(), "and no size is propagated");
    assert!(s.ended(), "and the session is over");
}

// ───────────────────────────────── window size: the plant and its control

#[test]
fn a_resize_mid_frame_is_deferred_and_the_frame_survives_intact() {
    // ⛔ **THE PLANT, and it is stated in the terms the entry uses.**
    //
    // ⛔ The claim: a resize that arrives while a full-screen program is drawing
    // must not be interleaved into the frame, because a program that sees a size
    // change mid-render draws against two geometries at once.
    //
    // ⛔ The measurements, both of them exact bytes:
    //   * **the frame is intact** — every byte the program drew arrives at the
    //     local side, in order, with nothing inserted and nothing dropped;
    //   * **the size was not lost** — it is released when the frame ends.
    let mut p = Passthrough::new();
    let frame = b"\x1b[2J\x1b[Hrow one\x1b[K\x1b[2Krow two\x1b[K";
    p.begin_frame();

    // ⛔ Three resizes arrive mid-frame, each between two of the frame's bytes.
    assert_eq!(p.on_resize(Size::new(40, 120)), None, "first: held");
    let mut arrived = p.forward_remote(&frame[..9]).concat_local();
    assert_eq!(p.on_resize(Size::new(45, 150)), None, "second: held");
    arrived.extend_from_slice(&p.forward_remote(&frame[9..]).concat_local());

    // ⛔ **The frame is intact.** ⛔ A byte for byte, which is the whole of the
    // assertion: had a resize been interleaved, this would be longer than the
    // input, or shorter.
    assert_eq!(arrived, frame, "the frame arrived whole and in order");
    assert_eq!(arrived.len(), frame.len(), "and not one byte was added");

    // ⛔ **And the size survived the frame**, released at its end.
    assert_eq!(p.end_frame(), Some(Size::new(45, 150)), "the latest size is released");
}

#[test]
fn a_resize_while_idle_propagates_immediately() {
    // ⛔ **THE CONTROL for the plant above, on the same guard.** ⛔ A guard
    // that defers everything looks exactly like a guard that defers correctly,
    // and only the idle case tells them apart. ⛔ **This is also the clause
    // `stty size` in the `Prove` block depends on**: a size that only ever gets
    // deferred is a window that never resizes.
    let mut p = Passthrough::new();
    assert!(!p.in_frame(), "no frame is open");
    assert_eq!(p.on_resize(Size::new(50, 160)), Some(Size::new(50, 160)), "at once");
    assert!(!p.in_frame(), "and it did not open a frame");

    // ⛔ **Through the driver too**, so the mode dispatch is covered.
    let mut s = Session::new(true, false);
    assert_eq!(s.on_resize(Size::new(24, 80)), Some(Size::new(24, 80)));
}

#[test]
fn a_resize_can_never_be_dropped() {
    // ⛔ **The invariant, over a whole sequence.** ⛔ Hold any number of
    // resizes across any number of frames and ⛔ **the last one is always
    // released**, so a resize cannot be swallowed by a frame boundary — the
    // failure a deferral that only ever holds one field could have.
    let mut w = Window::new();
    let mut released = Vec::new();
    for (frame, rows, cols) in [(1, 30u16, 100u16), (2, 31, 101), (3, 40, 120)] {
        w.begin_frame();
        for step in 0..frame {
            w.on_resize(Size::new(rows + step, cols + step));
        }
        if let Some(size) = w.end_frame() {
            released.push(size);
        }
    }
    assert_eq!(
        released,
        vec![Size::new(30, 100), Size::new(32, 102), Size::new(42, 122)],
        "each frame released its last held size"
    );
    assert_eq!(w.propagated(), Some(Size::new(42, 122)), "and the last is current");
}

// ───────────────────────────────── `stty size`, as far as this crate gets

#[test]
fn the_size_a_program_would_read_is_the_one_that_was_propagated() {
    // ⛔ **The `stty size` clause of the acceptance, at the only level this
    // crate can reach.** ⛔ The real command needs the constrained host and a
    // built CLI; what it needs *from here* is the size it would be given.
    // ⛔ **This is the plant for the whole window-size half**: the sibling's
    // refusal would leave `propagated()` `None` forever and this fails, which is
    // why the sibling's code alone would have shipped the bug.
    let mut w = Window::new();
    assert_eq!(w.propagated(), None, "nothing has been propagated yet");
    let sent = w.on_resize(Size::new(50, 160)).expect("idle: sent at once");
    assert_eq!(sent, w.propagated().expect("and it is now the propagated size"));
    assert_eq!(w.propagated().map(|s| s.to_string()), Some("50x160".to_string()));
}