//! Window size: honoured, deferred while a frame is half-drawn, never dropped.
//!
//! **This is the one behaviour that is deliberately NOT transcribed from the
//! sibling, and the entry says why.** The reference *refuses* window size,
//! with a reason that does not apply to podssh — **READ**,
//! `.tmp/podbox/crates/podbox-ssh/src/session.rs:47-50`, verbatim:
//!
//! > - Window size (pass-through): size changes arrive as SSH channel requests,
//! >   which `sshd` consumes before any byte reaches this module, so there is
//! >   no refusal path here to ring. Programs that need a size read `$LINES`
//! >   and `$COLUMNS`; the module sets neither.
//!
//! **podssh is not behind `sshd`'s `ForceCommand`.** podssh issues the
//! `window-change` channel request itself, so it is the component that must
//! honour `SIGWINCH` locally and propagate it. **Copying the sibling's refusal
//! would have shipped a window that cannot be resized while a program is
//! running**, which is one of the four failures in the entry's Problem section.
//!
//! ## Why a resize is deferred rather than sent
//!
//! **Interleaving a size change into a half-drawn frame corrupts the
//! stream.** A full-screen program has just emitted a frame's worth of bytes;
//! a `window-change` lands between two of them, the program sees a size change
//! mid-render, and the result is a frame drawn against two geometries at once.
//! So a resize that arrives mid-frame is **held**, and released when the frame
//! ends.
//!
//! **Deferred, not dropped.** A dropped resize is the sibling's failure mode
//! in a different costume: the user's terminal is now a different size from the
//! program's idea of it, and nothing says so. A deferred one is delivered late
//! and the program repaints. **Nothing here can lose a resize**: the pending
//! slot holds exactly one, and a second resize arriving mid-frame *replaces* it,
//! because only the latest size is true.
//!
//! ## What this module deliberately does not do
//!
//! **It never reads the local `TIOCGWINSZ`.** Reading the local size is the
//! caller's job — the CLI owns the terminal — and doing it here would make this
//! crate depend on a file descriptor it does not have. **It never sends
//! anything.** `Window` decides *when* a size change is safe to emit and hands
//! the caller the value; the caller turns it into the SSH channel request, which
//! `podssh-ssh` and not this crate owns.
//!
//! `docs/terminal.md`, "`pty-req` (RFC 4254, section 6.2)", says when it is sent.

/// A window size in rows and columns, as `TIOCGWINSZ` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    /// Terminal rows. **Rows first, then columns**, which is `winsize`'s own
    /// order and the reverse of how a human says "80 by 24".
    pub rows: u16,
    /// Terminal columns.
    pub cols: u16,
}

impl Size {
    /// A size from rows and columns.
    pub const fn new(rows: u16, cols: u16) -> Self {
        Size { rows, cols }
    }

    /// Whether a size is one a program can be shown. **Zero in either axis
    /// is refused here**, because `stty size` prints `0 0` and every terminfo
    /// program divides by it: the failure is a divide, not a message. A caller
    /// that has not measured a size must say so rather than send one.
    pub fn is_usable(self) -> bool {
        self.rows > 0 && self.cols > 0
    }
}

impl std::fmt::Display for Size {
    /// **`rows` then `cols`**, which is what `stty size` prints and what every
    /// user reading a log expects. `Display` is where this convention is fixed,
    /// because it is the only place the two orders can be confused.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}", self.rows, self.cols)
    }
}

/// The window-size half of a session: the last size propagated, and the size
/// waiting for a frame to finish.
///
/// **Two fields, and the split is the whole contract.** `propagated` is the
/// size the program has been told. `pending` is a size that arrived while a
/// frame was open and has not been told yet. **A pending size is never
/// discarded**, only replaced by a newer truth.
#[derive(Debug, Clone, Default)]
pub struct Window {
    /// The last size handed to the caller as safe to send, if any.
    propagated: Option<Size>,
    /// A size that arrived mid-frame, held until the frame closes.
    pending: Option<Size>,
    /// Whether a full-screen frame is open. **Set by the discipline, not
    /// guessed from the bytes**: a `vi` frame is bytes this crate never parses.
    frame_open: bool,
}

impl Window {
    pub fn new() -> Self {
        Window::default()
    }

    /// Mark a full-screen frame as open.
    ///
    /// **The deferral point.** Every resize from here until [`Window::end_frame`]
    /// is held rather than sent. The caller marks a frame, not this crate:
    /// deciding when a full-screen program owns the screen is the driver's
    /// call, made from what the server granted, and never from a guess.
    pub fn begin_frame(&mut self) {
        self.frame_open = true;
    }

    /// Mark the frame as finished.
    ///
    /// **Returns the held size, if any**, and that is the whole of the
    /// deferral: the caller sends it now, and the program repaints at the right
    /// size. **It is `Option<Size>`, never `()`**, so a size that was held
    /// cannot be dropped by a caller that forgets to ask.
    pub fn end_frame(&mut self) -> Option<Size> {
        self.frame_open = false;
        let held = self.pending.take()?;
        self.propagated = Some(held);
        Some(held)
    }

    /// Whether a frame is open right now.
    pub fn in_frame(&self) -> bool {
        self.frame_open
    }

    /// A resize arrived.
    ///
    /// **Returns the size to send now, or `None` when it must wait.**
    /// **Nothing is ever dropped**: a resize during a frame is held, and the
    /// held size is what [`Window::end_frame`] hands back.
    ///
    /// **A resize arriving mid-frame replaces the one already held.** Two
    /// resizes in one frame are not two truths, and sending the first would
    /// propagate a size the user's terminal has already left. **A resize
    /// arriving while idle is returned immediately**, including one that repeats
    /// the current size — the caller's decision to suppress a duplicate is the
    /// caller's, and this type's job is to say when a resize may be sent.
    pub fn on_resize(&mut self, size: Size) -> Option<Size> {
        if self.frame_open {
            self.pending = Some(size);
            None
        } else {
            self.propagated = Some(size);
            Some(size)
        }
    }

    /// The size currently held for a frame that has not closed, if any.
    pub fn pending(&self) -> Option<Size> {
        self.pending
    }

    /// The last size handed over as safe to send.
    pub fn propagated(&self) -> Option<Size> {
        self.propagated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────── the plant: a resize delivered mid-frame

    #[test]
    fn a_resize_mid_frame_is_held_not_sent_and_not_lost() {
        // **The `Prove` plant.** `SIGWINCH` arrives while `vi` is redrawing:
        // the size must not be sent into the middle of the frame, and it must
        // not be discarded either. **Both halves, in one test**, because a
        // deferral that loses the resize passes a test that only checks the
        // first half.
        let mut w = Window::new();
        w.propagated = Some(Size::new(24, 80));
        w.begin_frame();

        assert_eq!(w.on_resize(Size::new(40, 120)), None, "mid-frame must not send");
        assert_eq!(w.pending(), Some(Size::new(40, 120)), "and must not lose it");

        assert_eq!(w.end_frame(), Some(Size::new(40, 120)), "released at frame end");
        assert_eq!(w.pending(), None, "and not held twice");
        assert_eq!(w.propagated(), Some(Size::new(40, 120)));
    }

    #[test]
    fn a_resize_while_idle_propagates_immediately() {
        // **The control for the plant above, on the same guard.** A guard
        // that refuses everything looks exactly like a good guard, so the
        // accepted case is a required half, not a courtesy.
        let mut w = Window::new();
        assert_eq!(w.on_resize(Size::new(50, 160)), Some(Size::new(50, 160)));
        assert_eq!(w.pending(), None, "nothing was held");
        assert_eq!(w.propagated(), Some(Size::new(50, 160)));
    }

    // ─────────── several resizes in one frame: only the latest is true

    #[test]
    fn a_second_resize_in_one_frame_replaces_the_first() {
        // Two resizes in one frame are not two truths. Sending the first
        // would propagate a size the terminal has already left, and holding
        // both would need a queue where only the newest is worth anything.
        let mut w = Window::new();
        w.begin_frame();
        assert_eq!(w.on_resize(Size::new(30, 100)), None);
        assert_eq!(w.on_resize(Size::new(45, 160)), None);
        assert_eq!(w.pending(), Some(Size::new(45, 160)));
        assert_eq!(w.end_frame(), Some(Size::new(45, 160)));
    }

    #[test]
    fn end_frame_with_nothing_pending_releases_nothing() {
        // **The `None` arm of the deferral.** A frame that ended with no
        // resize must not manufacture one: an invented size is worse than a
        // dropped one, because the program repaints against a geometry the
        // terminal never had.
        let mut w = Window::new();
        w.begin_frame();
        assert_eq!(w.end_frame(), None);
        assert!(!w.in_frame());
    }

    #[test]
    fn a_resize_after_a_frame_closed_is_immediate_again() {
        // `frame_open` must actually clear. A window that stuck at "in frame"
        // would defer every resize for the rest of the session, which is the
        // sibling's failure wearing the deferral's clothes.
        let mut w = Window::new();
        w.begin_frame();
        assert_eq!(w.on_resize(Size::new(40, 120)), None);
        assert_eq!(w.end_frame(), Some(Size::new(40, 120)));
        assert_eq!(w.on_resize(Size::new(24, 80)), Some(Size::new(24, 80)));
    }

    #[test]
    fn a_nested_frame_opens_once_and_closes_once() {
        // **`begin_frame` is idempotent and `frame_open` is a flag, not a
        // counter — and that is a known limit, not an oversight.** A full-screen
        // program that draws a frame inside a frame closes both with one
        // `end_frame`, and the inner size is released at the inner close.
        // What that means is written here rather than discovered: a
        // full-screen program's own frame nesting is not modelled, and a caller
        // that needs it must hold its own depth. A counter instead would make
        // the common case — one frame, one close — correct and the nested case
        // silently *defer* the outer frame's size forever, which is the worse
        // failure because it is invisible.
        let mut w = Window::new();
        w.begin_frame();
        w.begin_frame();
        assert!(w.in_frame());
        assert_eq!(w.on_resize(Size::new(40, 120)), None);
        assert_eq!(w.end_frame(), Some(Size::new(40, 120)));
        assert!(!w.in_frame());
    }

    // ─────────── a size nobody measured

    #[test]
    fn a_zero_size_is_not_usable() {
        // `stty size` prints `0 0` and terminfo divides by it. This is a
        // predicate and not an enforcement: refusing here would hide a caller
        // bug behind a `None`, and a `None` that means "held" and a `None` that
        // means "refused" are not the same answer.
        assert!(!Size::new(0, 80).is_usable());
        assert!(!Size::new(24, 0).is_usable());
        assert!(!Size::new(0, 0).is_usable());
        assert!(Size::new(24, 80).is_usable());
    }

    #[test]
    fn size_prints_rows_then_columns() {
        // **Rows first**, which is `winsize`'s order and `stty size`'s, and the
        // reverse of how a person says it. One `Display`, because the two
        // orders are otherwise indistinguishable in a log line.
        assert_eq!(Size::new(24, 80).to_string(), "24x80");
        assert_eq!(Size::new(50, 160).to_string(), "50x160");
    }
}
