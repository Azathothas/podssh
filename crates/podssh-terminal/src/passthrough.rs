//! The second discipline: the remote program owns the screen.
//!
//! ⛔ **A full-screen program is a separate mode, not a richer cooked mode.**
//! ⛔ The cooked discipline in [`crate::echo`] **drops cursor addressing**, and
//! that is not a bug to be softened for `vi` — it is a refusal, transcribed:
//! **READ**, `.tmp/podbox/crates/podbox-ssh/src/session.rs:54-55`, *"any escape
//! sequence outside arrows, Home, and End is dropped"*. ⛔ A discipline that
//! passed `ESC[?1049h` to a client that is *not* full-screen would corrupt the
//! scrollback; one that dropped it from a client that *is* would leave `vi`
//! drawing over the scrollback. ⛔ **There is no middle. Two modes, and the mode
//! is chosen by what the server granted** — see [`crate::session::Session`].
//!
//! ## What the local side still owns
//!
//! Exactly two things, and the list is short on purpose:
//!
//! 1. **Window size**, through [`crate::window`] — held across a frame, never
//!    interleaved into one.
//! 2. **Signal characters**, as bytes — Ctrl-C and Ctrl-\ travel forward
//!    untouched, because a program that owns the screen also needs the
//!    interrupt.
//!
//! ⛔ **Nothing else.** ⛔ **No alternate screen is entered or left here.** ⛔ The
//! program does that itself: it is the thing that knows when it is about to
//! take the screen, and a local side that did it too would restore a screen the
//! program never left. ⛔ Whether podssh's local terminal implements `1049` is
//! **`UNKNOWN`** and is recorded on the entry; ⛔ it does not need to be settled
//! for this mode, because **this mode never asks**.
//!
//! ## What is refused, and loudly
//!
//! ⛔ **The refusals survive the mode change.** ⛔ Ctrl-Z, Ctrl-S and Ctrl-Q
//! ring the bell here from [`crate::echo::refuses`], the same list the cooked
//! mode uses, because a refused operation that answers differently in two modes
//! is a refusal a user cannot learn.

use crate::echo::{Event, Sig};
use crate::refusal::{refusal_bytes, refuses};
use crate::window::{Size, Window};

/// The pass-through discipline.
///
/// ⛔ **Structurally tiny, and that is the design.** A discipline that owns the
/// screen has no line, no cursor and no history: every one of those is the
/// cooked mode's, and holding them here would be holding state nobody reads.
pub struct Passthrough {
    window: Window,
}

impl Passthrough {
    /// A new pass-through session, with no size propagated yet.
    pub fn new() -> Self {
        Passthrough { window: Window::new() }
    }

    /// ⛔ **The whole of the reverse leg.** Every byte the remote side produced
    /// goes to the local side untouched — **no expansion, no redraw, no
    /// substitution**, because the program wrote those bytes for a terminal and
    /// this crate is not one.
    ///
    /// ⛔ **Transcribed in spirit from the sibling's `ShellOut::Bytes`
    /// path** (`session.rs:478-480`, `565-568`) and ⛔ **deliberately different
    /// in one respect: no `onlcr`.** The sibling expands lone `\n` to `\r\n` —
    /// **READ**, `session.rs:629-642` — because its shell runs on a pipe with no
    /// `OPOST`/`ONLCR`. ⛔ Here the far side is a real pty, which already did
    /// the translation; expanding again would put a `\r` before every `\n` and
    /// stair-step the whole screen.
    pub fn forward_remote(&self, bytes: &[u8]) -> Vec<Event> {
        if bytes.is_empty() {
            vec![]
        } else {
            vec![Event::ToLocal(bytes.to_vec())]
        }
    }

    /// ⛔ **The whole of the forward leg, and the one thing this module
    /// interprets.** Two classes and no others:
    ///
    /// - **Signal characters** — Ctrl-C, Ctrl-\ — travel forward as bytes. ⛔
    ///   A program that owns the screen still needs the interrupt, and
    ///   swallowing it would make Ctrl-C do nothing at all inside `vi`.
    /// - **Refusals** — Ctrl-Z, Ctrl-S, Ctrl-Q — ring the bell, from the same
    ///   [`crate::echo::refuses`] list the cooked mode uses. ⛔ Silence here
    ///   would read as acceptance, and a user who cannot tell "not supported"
    ///   from "did nothing" files it in the wrong place.
    ///
    /// ⛔ **Everything else is forwarded verbatim**, which is the entire
    /// contract of this mode: a key, an escape, a paste, a mouse report.
    pub fn forward_local(&mut self, b: u8) -> Vec<Event> {
        if refuses(b) {
            vec![Event::ToLocal(refusal_bytes())]
        } else {
            vec![Event::ToRemote(vec![b])]
        }
    }

    /// The signal characters, named. ⛔ **Exposed so a caller can report them
    /// without duplicating the byte values**, which are the cooked module's
    /// (`session.rs:268-269`) and must not drift from them.
    pub fn signal_bytes() -> [(u8, Sig); 2] {
        [(0x03, Sig::Int), (0x1c, Sig::Quit)]
    }

    /// A full-screen frame began. ⛔ Every resize until
    /// [`Passthrough::end_frame`] is held, not sent into the middle of a frame.
    pub fn begin_frame(&mut self) {
        self.window.begin_frame();
    }

    /// The full-screen frame ended. ⛔ **Returns a size that was held**, which
    /// the caller sends now so the program repaints at the right geometry.
    pub fn end_frame(&mut self) -> Option<Size> {
        self.window.end_frame()
    }

    /// A local resize arrived. ⛔ Returns it when it may be sent now, and
    /// `None` when a frame is open — ⛔ **never dropping it**, which is the
    /// whole difference between this and the sibling's refusal.
    pub fn on_resize(&mut self, size: Size) -> Option<Size> {
        self.window.on_resize(size)
    }

    /// Whether a full-screen frame is open.
    pub fn in_frame(&self) -> bool {
        self.window.in_frame()
    }

    /// The window half, for a caller that wants the held size without asking
    /// for it through the frame calls.
    pub fn window(&self) -> &Window {
        &self.window
    }
}

impl Default for Passthrough {
    fn default() -> Self {
        Passthrough::new()
    }
}

impl std::fmt::Debug for Passthrough {
    /// ⛔ A `Debug` that prints the frame state and nothing else, because a
    /// `Passthrough` holds no line and printing one would suggest it does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passthrough").field("in_frame", &self.window.in_frame()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::quoted;
    use crate::echo::BELL;

    // ─────────── the reverse leg is untouched

    #[test]
    fn remote_bytes_reach_the_local_side_byte_for_byte() {
        // ⛔ **Including a lone `\n`.** ⛔ The sibling expands it to `\r\n`
        // because its shell is on a pipe; here the far side is a real pty that
        // has already done that translation, and expanding again is the
        // stair-step bug. ⛔ This is the plant: change `forward_remote` to expand
        // lone newlines and this assertion fails with a `\r` that is not in the
        // input.
        let p = Passthrough::new();
        let out = p.forward_remote(b"line one\nline two\n");
        assert_eq!(out, vec![Event::ToLocal(b"line one\nline two\n".to_vec())]);
    }

    #[test]
    fn remote_escape_sequences_are_not_interpreted() {
        // ⛔ **The frame a program draws**: alternate screen, cursor addressing,
        // erase. ⛔ The cooked discipline drops all of it; here every byte must
        // arrive, or `vi` has no screen.
        let frame = b"\x1b[?1049h\x1b[2J\x1b[H\x1b[1;1Hline\x1b[0m\x1b[?1049l";
        let p = Passthrough::new();
        assert_eq!(p.forward_remote(frame), vec![Event::ToLocal(frame.to_vec())]);
    }

    #[test]
    fn no_bytes_produce_no_events() {
        // ⛔ An empty forward is not an event carrying an empty vector: an empty
        // `ToLocal` written to a channel is indistinguishable from nothing at
        // all, and a test asserting on the vector would pass either way.
        let p = Passthrough::new();
        assert!(p.forward_remote(b"").is_empty());
    }

    #[test]
    fn a_carriage_return_pair_is_not_rewritten_either() {
        // ⛔ **The pair is the sharpest form of this.** ⛔ The cooked mode
        // swallows the `\n` of a `\r\n` because a *user typed* the pair as one
        // Enter; here the `\r\n` came from the remote program's own `ONLCR`, and
        // swallowing the `\n` would delete a byte a program on the far side
        // wrote deliberately. ⛔ **The same input means different things in
        // the two modes, which is exactly why they are two modes and not one
        // with a flag.** ⛔ One test against both modes is the only way that
        // difference is visible; it lives in `session.rs`, where both exist.
        let p = Passthrough::new();
        assert_eq!(p.forward_remote(b"out\r\n"), vec![Event::ToLocal(b"out\r\n".to_vec())]);
    }

    // ─────────── the forward leg: two classes and no others

    #[test]
    fn ordinary_keys_travel_verbatim() {
        let mut p = Passthrough::new();
        for b in [b'a', b'Z', b' ', 0x7f, 0x1b, b'['] {
            assert_eq!(p.forward_local(b), vec![Event::ToRemote(vec![b])], "byte {b:#x}");
        }
    }

    #[test]
    fn signal_characters_travel_as_bytes() {
        // ⛔ **Ctrl-C must reach a full-screen program.** ⛔ Swallowing it would
        // make the interrupt do nothing inside `vi`, which is the failure this
        // mode exists to avoid.
        let mut p = Passthrough::new();
        assert_eq!(p.forward_local(0x03), vec![Event::ToRemote(vec![0x03])]);
        assert_eq!(p.forward_local(0x1c), vec![Event::ToRemote(vec![0x1c])]);
    }

    #[test]
    fn refusals_bell_from_the_shared_list() {
        // ⛔ **The control for the shared refusal list.** ⛔ A guard that refuses
        // everything looks exactly like a good guard, so the accepted cases are
        // asserted against the same `refuses` the cooked mode uses.
        let mut p = Passthrough::new();
        for b in [0x1au8, 0x11, 0x13] {
            assert!(refuses(b), "byte {b:#x} must be refused in both modes");
            assert_eq!(p.forward_local(b), vec![Event::ToLocal(BELL.to_vec())], "byte {b:#x}");
        }
        for b in [b'a', 0x03, 0x1c, 0x1b, 0x7f] {
            assert!(!refuses(b), "byte {b:#x} must not be refused");
        }
    }

    #[test]
    fn the_signal_bytes_are_the_cooked_modules() {
        // ⛔ Named once in each module and compared here, because a Ctrl-C that
        // is `0x03` in one and something else in the other is a defect no unit
        // test inside either module can see.
        assert_eq!(Passthrough::signal_bytes(), [(0x03, Sig::Int), (0x1c, Sig::Quit)]);
    }

    // ─────────── size is held across a frame, in this mode too

    #[test]
    fn a_resize_during_a_frame_is_held_and_released() {
        let mut p = Passthrough::new();
        p.begin_frame();
        assert!(p.in_frame());
        assert_eq!(p.on_resize(Size::new(50, 160)), None, "held, not interleaved");
        assert_eq!(p.end_frame(), Some(Size::new(50, 160)), "and released");
    }

    #[test]
    fn a_resize_while_idle_goes_out_at_once() {
        let mut p = Passthrough::new();
        assert!(!p.in_frame());
        assert_eq!(p.on_resize(Size::new(30, 100)), Some(Size::new(30, 100)));
        assert!(!p.in_frame(), "a resize does not open a frame");
    }

    // ─────────── what this mode must NOT have done

    #[test]
    fn no_alternate_screen_is_entered_by_the_local_side() {
        // ⛔ **The refusal that matters most here.** ⛔ If this mode entered or
        // left `1049` locally, it would restore a screen the program never left
        // — and `1049` does not nest. ⛔ `forward_remote` is the only path bytes
        // take to the local side, and it emits exactly what it was given.
        let p = Passthrough::new();
        let program_says = b"\x1b[?1049h";
        let out = p.forward_remote(program_says);
        assert_eq!(out, vec![Event::ToLocal(program_says.to_vec())]);
        assert_eq!(quoted(program_says), r#""\x1b[?1049h""#);
    }

    #[test]
    fn debug_does_not_invent_a_line_buffer() {
        // ⛔ A `Passthrough` holds no line, so a `Debug` that mentioned one would
        // send a reader looking for state that is not there.
        let text = format!("{:?}", Passthrough::new());
        assert!(text.contains("Passthrough"), "{text}");
        assert!(!text.contains("line"), "{text}");
    }
}
