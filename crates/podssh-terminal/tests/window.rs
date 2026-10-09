//! **Window size: a resize is held while a frame is drawn, and never lost.**
//!
//! The sibling refuses window size, because `sshd`'s `ForceCommand` takes the
//! size changes before a byte reaches it. podssh sends `window-change` itself,
//! so these tests pin the opposite: the size goes out at once when idle, waits
//! for the end of a frame, and the last one always arrives.

use podssh_terminal::echo::Event;
use podssh_terminal::passthrough::Passthrough;
use podssh_terminal::session::Session;
use podssh_terminal::window::{Size, Window};

mod common;
use common::{over_a_pty, LocalBytes};

// ───────────────────────────────── window size: the plant and its control

#[test]
fn a_resize_mid_frame_is_deferred_and_the_frame_survives_intact() {
    // **THE PLANT, and it is stated in the terms the entry uses.**
    //
    // The claim: a resize that arrives while a full-screen program is drawing
    // must not be interleaved into the frame, because a program that sees a size
    // change mid-render draws against two geometries at once.
    //
    // The measurements, both of them exact bytes:
    //   * **the frame is intact** — every byte the program drew arrives at the
    //     local side, in order, with nothing inserted and nothing dropped;
    //   * **the size was not lost** — it is released when the frame ends.
    let mut p = Passthrough::new();
    let frame = b"\x1b[2J\x1b[Hrow one\x1b[K\x1b[2Krow two\x1b[K";
    p.begin_frame();

    // Three resizes arrive mid-frame, each between two of the frame's bytes.
    assert_eq!(p.on_resize(Size::new(40, 120)), None, "first: held");
    let mut arrived = p.forward_remote(&frame[..9]).concat_local();
    assert_eq!(p.on_resize(Size::new(45, 150)), None, "second: held");
    arrived.extend_from_slice(&p.forward_remote(&frame[9..]).concat_local());

    // **The frame is intact.** A byte for byte, which is the whole of the
    // assertion: had a resize been interleaved, this would be longer than the
    // input, or shorter.
    assert_eq!(arrived, frame, "the frame arrived whole and in order");
    assert_eq!(arrived.len(), frame.len(), "and not one byte was added");

    // **And the size survived the frame**, released at its end.
    assert_eq!(p.end_frame(), Some(Size::new(45, 150)), "the latest size is released");
}

#[test]
fn a_resize_while_idle_propagates_immediately() {
    // **THE CONTROL for the plant above, on the same guard.** A guard
    // that defers everything looks exactly like a guard that defers correctly,
    // and only the idle case tells them apart. **This is also the clause
    // `stty size` in the `Prove` block depends on**: a size that only ever gets
    // deferred is a window that never resizes.
    let mut p = Passthrough::new();
    assert!(!p.in_frame(), "no frame is open");
    assert_eq!(p.on_resize(Size::new(50, 160)), Some(Size::new(50, 160)), "at once");
    assert!(!p.in_frame(), "and it did not open a frame");

    // **Through the driver too**, so the mode dispatch is covered.
    let mut s = Session::new(over_a_pty());
    assert_eq!(s.on_resize(Size::new(24, 80)), vec![Event::Size(Size::new(24, 80))]);
}

#[test]
fn a_resize_can_never_be_dropped() {
    // **The invariant, over a whole sequence.** Hold any number of
    // resizes across any number of frames and **the last one is always
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
    // **The `stty size` clause of the acceptance, at the only level this
    // crate can reach.** The real command needs the constrained host and a
    // built CLI; what it needs *from here* is the size it would be given.
    // **This is the plant for the whole window-size half**: the sibling's
    // refusal would leave `propagated()` `None` forever and this fails, which is
    // why the sibling's code alone would have shipped the bug.
    let mut w = Window::new();
    assert_eq!(w.propagated(), None, "nothing has been propagated yet");
    let sent = w.on_resize(Size::new(50, 160)).expect("idle: sent at once");
    assert_eq!(sent, w.propagated().expect("and it is now the propagated size"));
    assert_eq!(w.propagated().map(|s| s.to_string()), Some("50x160".to_string()));
}
