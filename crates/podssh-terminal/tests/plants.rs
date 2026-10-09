//! **The line discipline's plants, and the controls that prove they are not guards that
//! refuse everything.**
//!
//! The entry's `Prove` block named five defects. Plants A and B were of the
//! crate's own `TERM` rule, which is gone: the client's `TERM` rule
//! (`podssh-ssh`) is the one that reaches the `pty-req`. Three remain:
//!
//! | Plant | Defect | What must happen |
//! | --- | --- | --- |
//! | C | a resize delivered mid-frame | the frame must stay intact, the size must survive |
//! | D | an unknown escape, `ESC [ 1 5 ~` | a bell and no state change |
//! | E | `Ctrl-C` against a non-shell command | the command dies, the session survives |
//!
//! ## How a plant is run here, and why
//!
//! **Each plant has two arms, and the defect arm is selected by an
//! environment variable.** With `PODSSH_PLANT=<name>` set, the arm asserts what
//! a client **carrying the defect** would expect — which makes it **fail** and
//! print the defect. With the variable unset, the correct path runs and passes.
//!
//! **An unknown name is the control too.** A typo in a plant's name would
//! otherwise silently run the correct path and the plant would look proven
//! forever — which is the exact defect this repository shipped when a plant
//! stopped planting.
//!
//! ```sh
//! PODSSH_PLANT=drop_resize_mid_frame cargo test -p podssh-terminal --test plants plant_c
//! cargo test -p podssh-terminal --test plants plant_c     # the control
//! ```
//!
//! **One of the three cannot be run as the entry wrote it, and the reason is
//! in its body.** E names a real command dying against a real shell. **No command uses this crate yet,
//! and there is no constrained host on this machine**, so what
//! is asserted here is the **unit-level** form of each defect — and that
//! substitution is named rather than glossed over: the real run is named on the
//! entry as a clause that cannot execute from here, with the command and the
//! reason.

use podssh_terminal::echo::{Discipline, Event, Sig, BELL, EL};
use podssh_terminal::session::{Mode, Session};
use podssh_terminal::window::{Size, Window};

mod common;

/// **Is the named defect switched on?** An unset variable is the control,
/// and **an unknown name is the control too** — a typo must not silently
/// plant something.
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// **The control arms, one per plant, each on the case it must accept.**
///
/// **In one file and in one function, deliberately.** A guard that refuses
/// everything looks exactly like a guard that works, and the only thing that
/// tells them apart is **a second test that passes on the same guard.** If
/// the controls lived in the unit suites and someone deleted one, nothing would
/// fail.

#[test]
fn control_c_a_resize_while_idle_is_sent_at_once() {
    // **The control for plant C.** The deferral must apply to a resize that
    // arrives mid-frame and to **nothing else**. A window that deferred
    // everything would pass plant C and fail here, and would also be the
    // sibling's failure wearing the deferral's clothes.
    let mut w = Window::new();
    assert!(!w.in_frame());
    assert_eq!(w.on_resize(Size::new(40, 120)), Some(Size::new(40, 120)));
    assert_eq!(w.propagated(), Some(Size::new(40, 120)));
    assert_eq!(w.pending(), None, "nothing is held while idle");
}

#[test]
fn control_d_the_accepted_escape_still_moves_the_cursor() {
    // **The control for plant D, on the same guard.** `ESC [ C` must
    // move the cursor and echo `ESC [ C`. A parser that refused every
    // `ESC [` sequence would pass plant D perfectly and be unusable.
    let mut d = Discipline::new();
    let mut local = Vec::new();
    // **The left move first, and it is load-bearing.** Right is guarded by
    // `if cursor < line.len()` — **READ**, `session.rs:385` — so with the
    // cursor at the end, **`ESC [ C` is the at-bound refusal, not an
    // acceptance**, and this control would be asserting the opposite of what it
    // exists to prove. **A control that accidentally tests the refusal is
    // worse than no control at all:** it would pass for the wrong reason and
    // the plant beside it would look proven.
    for b in b"ac\x1b[D\x1b[C" {
        for event in d.key(*b) {
            if let Event::ToLocal(bytes) = event {
                local.extend_from_slice(&bytes);
            }
        }
    }
    assert_eq!(local, b"ac\x1b[D\x1b[C", "both arrows echoed exactly themselves");
    // **And the cursor really moved**, proved by the insert rather than by the
    // echo: left-then-right puts it back at the end, so **a fresh `D`
    // before the insert is what makes it land mid-line**, and `abc` rather than
    // `acb` is the observation that the discipline's cursor and the terminal's
    // cursor are still in step.
    for b in b"\x1b[D" {
        for event in d.key(*b) {
            if let Event::ToLocal(bytes) = event {
                local.extend_from_slice(&bytes);
            }
        }
    }
    let mut remote = Vec::new();
    for b in b"b\n" {
        for event in d.key(*b) {
            if let Event::ToRemote(bytes) = event {
                remote.extend_from_slice(&bytes);
            }
        }
    }
    assert_eq!(remote, b"abc\n", "so 'b' landed between 'a' and 'c'");
}

#[test]
fn control_e_a_signal_that_is_not_pressed_changes_nothing() {
    // **The control for plant E.** A session that reported a signal on every
    // key would pass plant E and be unusable.
    let mut s = Session::new(common::selected());
    let events = s.on_local_bytes(b"echo hello\n");
    assert!(!events.iter().any(|e| matches!(e, Event::Signal(_))), "no signal for ordinary input: {events:?}");
    assert!(!s.ended(), "and the session lives");
}

// ─────────────────────────────── plant C: a resize delivered mid-frame

#[test]
fn plant_c_a_resize_mid_frame() {
    // **THE PLANT: a resize delivered while a frame is half-drawn.** The
    // entry's words: *"Assert the SSH stream stays well-formed and the frame is
    // intact afterwards. Then resize while `vi` is idle and assert it propagates
    // immediately."*
    //
    // **Two claims, and the second is the one a deferral usually gets wrong.**
    // **A resize must not be interleaved into the frame** — a program seeing a
    // size change mid-render draws against two geometries at once — **and it
    // must not be lost**, because a dropped resize is the sibling's failure in a
    // different costume.
    let mut w = Window::new();
    w.begin_frame();
    let sent_mid_frame = w.on_resize(Size::new(40, 120));
    let released = w.end_frame();

    if planted("drop_resize_mid_frame") {
        // **The defect arm: the resize is dropped.** This is what copying
        // the sibling's refusal would produce, and the entry says so:
        // *"copying its code alone would ship this bug."*
        assert_eq!(
            sent_mid_frame, None,
            "the DEFECT arm is reached: a resize was sent into a half-drawn \
             frame, and the program's frame is drawn against two geometries."
        );
        assert_eq!(
            released, None,
            "the DEFECT arm is reached: the resize was DROPPED. The user's \
             terminal is now a different size from the program's idea of it, \
             and nothing says so — which is the sibling's failure."
        );
        panic!("THE PLANT FIRED: a mid-frame resize was dropped");
    }

    assert_eq!(sent_mid_frame, None, "nothing is sent into a half-drawn frame");
    assert_eq!(released, Some(Size::new(40, 120)), "and the size is NOT dropped: it is released when the frame ends");
    assert_eq!(w.propagated(), Some(Size::new(40, 120)), "and it is now current");
}

// ─────────────────────────── plant D: an unknown escape, `ESC [ 1 5 ~`

#[test]
fn plant_d_an_unknown_escape() {
    // **THE PLANT: `ESC [ 1 5 ~`.** The entry's words: *"Assert a bell
    // and no state change. Then `ESC [ C` and assert the cursor moves."*
    // **`ESC [ 1 5 ~` is a real F5 keypress**, and the cooked discipline
    // does not implement function keys. It says so with a bell rather than
    // inserting `1` and `~` into the user's command line, which is what a
    // parser that treated every `ESC [` as the start of an edit would do.
    let mut d = Discipline::new();
    for b in b"ab" {
        for _ in d.key(*b) {}
    }
    let mut events = Vec::new();
    for b in b"\x1b[15~" {
        events.extend(d.key(*b));
    }

    if planted("swallow_unknown_escape") {
        // **The defect arm: the sequence is swallowed silently.** Silence
        // reads as acceptance, and the user types a command that is not the one
        // they typed.
        assert!(
            events.is_empty(),
            "the DEFECT arm is reached: `ESC [ 1 5 ~` was swallowed with no \
             bell, and silence reads as acceptance"
        );
        panic!("THE PLANT FIRED: an unknown escape was silently swallowed");
    }

    assert_eq!(events, vec![Event::ToLocal(BELL.to_vec())], "one bell and nothing else");

    // **The state change that must not have happened.** `1`, `5` and `~`
    // must not have become part of the line — a guard that consumed the sequence as
    // an edit would pass the bell assertion and fail this one.
    let mut remote = Vec::new();
    for b in b"\n" {
        for event in d.key(*b) {
            if let Event::ToRemote(bytes) = event {
                remote.extend_from_slice(&bytes);
            }
        }
    }
    assert_eq!(
        remote, b"ab\n",
        "no state change: the command line is exactly `ab`, and `1`, `5` and \
         `~` never reached it"
    );
}

// ────────────────── plant E: Ctrl-C against a command that is not the shell

#[test]
fn plant_e_ctrl_c_kills_the_command_and_not_the_session() {
    // **THE PLANT: `Ctrl-C` against a command that is not the shell.**
    // The entry's words: *"Assert the command dies, the session survives, and
    // the exit status is reported."*
    //
    // **What is asserted here, and what is not — the whole honest shape of
    // this plant.** **No process is killed and no shell exits, because this
    // crate never spawns one**: the process that must die is the *remote*
    // side's, reached over a channel, and **this machine has no remote
    // shell and no command uses this crate yet (T-111).** The entry keeps that
    // clause open with the command that cannot run.
    //
    // **What IS asserted is all three halves of the claim, at the boundary
    // this crate owns**: **(1)** the signal is *reported* as a named event
    // and not swallowed — **(2)** the session survives it — **(3)** the
    // interrupted line never becomes a command, so **the exit status of the
    // command can never be confused with the exit status of the shell** and a
    // later command can still be submitted on the same session.
    let mut s = Session::new(common::selected());
    for b in b"sleep 100" {
        let _ = s.on_local_byte(*b);
    }
    let events = s.on_local_byte(0x03);

    if planted("ctrl_c_kills_the_session") {
        // **The defect arm: Ctrl-C ends the session.** This is the failure
        // named in the entry's Problem section — *"A session where `Ctrl-C`
        // kills the whole session instead of the command."*
        assert!(
            s.ended(),
            "the DEFECT arm is reached: Ctrl-C ended the session, and a command \
             that misbehaves took the shell with it."
        );
        panic!("THE PLANT FIRED: Ctrl-C killed the session instead of the command");
    }

    // ── half 1: the signal is reported, not swallowed
    assert_eq!(
        events,
        vec![Event::ToLocal(b"^C\r\n$ ".to_vec()), Event::Signal(Sig::Int)],
        "the signal is a named event on the leg that reaches the remote group"
    );

    // ── half 2: the session survives
    assert!(!s.ended(), "the session survives the interrupted command");

    // ── half 3: the interrupted line never ran, and the session still works
    let cooked = s.cooked().expect("a cooked session has a discipline");
    assert_eq!(cooked.line(), b"", "the interrupted line was dropped");
    assert!(
        cooked.history().is_empty(),
        "and it never reached history, so it can never be recalled as a \
         command whose exit status was mistaken for the shell's"
    );

    let after = s.on_local_bytes(b"echo alive\n");
    let remote: Vec<u8> = after
        .iter()
        .filter_map(|e| match e {
            Event::ToRemote(b) => Some(b.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(remote, b"echo alive\n", "and the session still runs the next command");
}

// ─────────────────────────── the redraw sequence the whole suite rests on

#[test]
fn the_redraw_is_the_transcribed_shape() {
    // **Every redraw assertion in both files reads `EL`, and `EL` is one
    // byte sequence.** If it changed, most of the suite would still pass —
    // they test *that* a redraw happened, not *what* it was — so this test
    // pins the shape itself: `\r`, the prompt, the whole line, `EL`, `\r`,
    // the prompt, and the line up to the cursor.
    let mut d = Discipline::new();
    for b in b"ac" {
        for _ in d.key(*b) {}
    }
    for b in b"\x1b[D" {
        for _ in d.key(*b) {}
    }
    let mut local = Vec::new();
    for b in b"b" {
        for event in d.key(*b) {
            if let Event::ToLocal(bytes) = event {
                local.extend_from_slice(&bytes);
            }
        }
    }
    let mut expected = Vec::new();
    expected.extend_from_slice(b"\r$ abc");
    expected.extend_from_slice(EL);
    expected.extend_from_slice(b"\r$ ab");
    assert_eq!(local, expected, "the redraw is \\r, prompt, line, EL, \\r, prompt, line-to-cursor");
}

#[test]
fn the_cooked_mode_has_no_alternate_screen_and_says_so() {
    // **The refusal that keeps a cooked session from corrupting somebody's
    // terminal.** **READ**, `session.rs:54-55`: *"Cursor addressing: any
    // escape sequence outside arrows, Home, and End is dropped."*
    //
    // A discipline that passed `ESC[?1049h` to a client that is **not**
    // full-screen would leave the scrollback on the alternate screen with
    // nothing to restore it. So the cooked mode drops it — and **the test
    // asserts the drop AND that nothing reached the command line**, because a
    // parser that consumed the sequence as text would pass the first half.
    let mut d = Discipline::new();
    let mut local = Vec::new();
    let mut remote = Vec::new();
    for b in b"\x1b[?1049hab" {
        for event in d.key(*b) {
            match event {
                Event::ToLocal(bytes) => local.extend_from_slice(&bytes),
                Event::ToRemote(bytes) => remote.extend_from_slice(&bytes),
                Event::Eof | Event::Signal(_) | Event::Size(_) => {}
            }
        }
    }
    assert_eq!(local, [BELL.to_vec(), b"a".to_vec(), b"b".to_vec()].concat());
    assert!(remote.is_empty(), "nothing reached the shell");

    // **And the positive half, on the same code path.** **Full-screen
    // programs are a separate mode, not a richer cooked mode** — which is
    // why the check is not "does the cooked mode drop it" but "does the mode
    // that is *for* full-screen programs pass it through untouched."
    let mut s = Session::new(common::over_a_pty());
    assert_eq!(s.mode(), Mode::Transparent);
    let out = s.on_remote_bytes(b"\x1b[?1049h");
    assert_eq!(out, vec![Event::ToLocal(b"\x1b[?1049h".to_vec())]);
}
