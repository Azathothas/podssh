//! The driver: which discipline a session runs, and how the two differ.
//!
//! ⛔ **One binary, two disciplines, and the choice is made here.** ⛔ The mode
//! comes from what the server granted — `pty-req` accepted, and whether the
//! remote program is a shell — and **never from guessing**. ⛔ Guessing is how a
//! session ends up half-way between two screen owners, which is the one state
//! in which neither of them owns it.
//!
//! ## The three modes, and the one that is not a terminal at all
//!
//! | Mode | When | What the caller gets |
//! | --- | --- | --- |
//! | [`Mode::Cooked`] | `pty-req` accepted, the remote program is a shell | echo, editing, history, a static prompt |
//! | [`Mode::Passthrough`] | `pty-req` accepted, the remote program is not a shell | size and signals; every other byte untouched |
//! | [`Mode::NoPty`] | `pty-req` **refused** | ⛔ nothing is emulated |
//!
//! ⛔ **`NoPty` is not a degraded mode and it is not a third screen owner.** ⛔
//! A server that refuses `pty-req` offers no terminal, so podssh says so and
//! offers copy mode: the entry's own words, *"podssh says so and offers copy
//! mode; it does not continue and pretend"*. ⛔ **A `Mode` that could only be
//! one of two screen owners could not express that**, which is why this is a
//! third variant rather than an `Option` a caller has to remember to check.
//!
//! ## Where the two modes agree, and that is worth knowing
//!
//! ⛔ **The refusals are identical in both terminal modes**, from the one list in
//! [`crate::refusal`]. ⛔ **The reverse leg is byte-identical in both**, because a
//! remote program that owns the screen and a shell that owns the line both
//! simply emit bytes. ⛔ **So what actually differs between the modes is the
//! forward leg and the frames** — ⛔ and one difference in the reverse leg that is
//! the sharpest thing this entry has to say:
//!
//! > A `\r\n` pair means **two different things** in the two modes. In cooked it
//! > is a user's Enter and its pair, and the `\n` is swallowed so a command does
//! > not run twice. In pass-through it is a remote program's own `ONLCR`, and
//! > swallowing the `\n` would delete a byte it wrote deliberately.
//!
//! ⛔ **One mode with a flag could not carry both answers**, because the flag
//! would have to be "the last submit was mine", which is a guess about the peer's
//! output discipline. ⛔ That test is `the_two_modes_agree_where_they_must` in the
//! integration suite, because it needs both modes in one place.
//!
//! ## The inherited limit, carried not hidden
//!
//! ⛔ **Ignored signal dispositions are inherited across `fork` and `exec`**, so a
//! command started under a trap-ignoring shell ignores the signal too, and no
//! inner `trap -` undoes an ignore inherited on entry. ⛔ **READ**,
//! `podbox/crates/podbox-ssh/src/session.rs:75-80`, verbatim: *"Killing the
//! command while the shell survives needs a trap handler: trapped signals reset
//! to the default in children while the shell itself runs the handler."* ⛔
//! **podssh inherits this and does not solve it**: it is a property of the remote
//! shell, and the fix is a trap on the remote side, which is not this crate's to
//! install.

use crate::echo::{Discipline, Event};
use crate::passthrough::Passthrough;
use crate::term::{select_term_from_env, TermChoice};
use crate::window::{Size, Window};

/// Which discipline a session runs.
///
/// ⛔ **Every variant is derived from the facts, never constructed by hand.**
/// ⛔ [`Mode::from_grant`] is the only way to name one, so a mode that the server
/// did not justify cannot be written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `pty-req` was **refused**. ⛔ There is no terminal on the far side and
    /// podssh does not emulate one.
    NoPty,
    /// `pty-req` accepted and the remote program is a shell.
    Cooked,
    /// `pty-req` accepted and the remote program is not a shell: it owns the
    /// screen.
    Passthrough,
}

impl Mode {
    /// ⛔ **The choice, and it is a total function of two facts.**
    pub fn from_grant(pty_granted: bool, remote_is_shell: bool) -> Mode {
        match (pty_granted, remote_is_shell) {
            (false, _) => Mode::NoPty,
            (true, true) => Mode::Cooked,
            (true, false) => Mode::Passthrough,
        }
    }

    /// Whether a terminal exists on the far side at all. ⛔ The `NoPty` answer is
    /// the only place a caller may offer copy mode.
    pub fn has_pty(self) -> bool {
        !matches!(self, Mode::NoPty)
    }
}

/// One session: a mode, the discipline it chose, and the size half.
///
/// ⛔ **Holds both disciplines, and only one of them is ever live.** ⛔ That is
/// the point: a `Mode` is decided once at construction and cannot be re-decided
/// from the bytes later, so a session cannot drift from one owner of the screen
/// to another mid-run.
pub struct Session {
    mode: Mode,
    cooked: Discipline,
    pass: Passthrough,
    window: Window,
    term: (String, TermChoice),
    ended: bool,
}

impl Session {
    /// ⛔ **The only constructor, and it takes the two facts.** ⛔ There is no
    /// way to build a `Session` without saying what the server granted, so a
    /// caller cannot skip the decision and get a mode by accident.
    pub fn new(pty_granted: bool, remote_is_shell: bool) -> Session {
        Session::with_term(pty_granted, remote_is_shell, select_term_from_env())
    }

    /// [`Session::new`], with the `TERM` decision supplied rather than read.
    ///
    /// ⛔ **The `TERM` decision is taken once, at construction**, and then never
    /// changes. ⛔ A session that re-derived it per keypress would report a
    /// different answer the moment the environment did, and the `pty-req` it was
    /// sent is not the one it would then be describing.
    pub fn with_term(
        pty_granted: bool,
        remote_is_shell: bool,
        term: (String, TermChoice),
    ) -> Session {
        Session {
            mode: Mode::from_grant(pty_granted, remote_is_shell),
            cooked: Discipline::new(),
            pass: Passthrough::new(),
            window: Window::new(),
            term,
            ended: false,
        }
    }

    /// The mode, decided from what the server granted.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The `TERM` to send on the `pty-req`, and whether it replaced one.
    ///
    /// ⛔ **`None` in [`Mode::NoPty`]**, because a refused `pty-req` carries no
    /// terminal name: the field is where the name would go and there is no
    /// field. ⛔ Returning the name anyway would invite a caller to put it
    /// somewhere it does not belong.
    pub fn term(&self) -> Option<&str> {
        self.mode.has_pty().then_some(self.term.0.as_str())
    }

    /// Whether the user's `TERM` was replaced, and why.
    ///
    /// ⛔ **`None` in [`Mode::NoPty`]**, for the same reason. ⛔ The reason is
    /// carried because a session that reports only the value looks like it
    /// ignored the user.
    pub fn term_choice(&self) -> Option<TermChoice> {
        self.mode.has_pty().then_some(self.term.1)
    }

    /// Whether input has ended.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// One local byte in, its consequences out.
    ///
    /// ⛔ **The one entry point, and the mode decides which discipline runs.**
    /// ⛔ `NoPty` refuses every byte with a bell and forwards nothing: there is
    /// no terminal on the far side to have a line, and emulating one here would
    /// be pretending.
    pub fn on_local_byte(&mut self, b: u8) -> Vec<Event> {
        match self.mode {
            Mode::NoPty => {
                self.ended = true;
                vec![Event::ToLocal(crate::refusal::refusal_bytes())]
            }
            Mode::Cooked => self.cooked.key(b),
            Mode::Passthrough => self.pass.forward_local(b),
        }
    }

    /// Local bytes in, their consequences out, in order.
    ///
    /// ⛔ **Events are accumulated, never dropped** — a caller that received only
    /// the last event would lose a submit that a redraw followed. ⛔ And
    /// [`Event::Eof`] **stops the loop**, so the rest of a buffer that arrived
    /// with an EOF is not interpreted as new lines.
    pub fn on_local_bytes(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        for b in bytes {
            for event in self.on_local_byte(*b) {
                let end = matches!(event, Event::Eof);
                out.push(event);
                if end {
                    self.ended = true;
                    return out;
                }
            }
        }
        out
    }

    /// Remote bytes in, their consequences out.
    ///
    /// ⛔ **Byte-identical in both terminal modes**, and that is deliberate: a
    /// shell and a full-screen program both simply emit bytes, and a discipline
    /// that edited them would be editing output it does not own. ⛔ `NoPty`
    /// forwards nothing at all.
    pub fn on_remote_bytes(&mut self, bytes: &[u8]) -> Vec<Event> {
        match self.mode {
            Mode::NoPty => vec![],
            Mode::Cooked | Mode::Passthrough => self.pass.forward_remote(bytes),
        }
    }

    /// Client EOF: submit a partial line, then end input.
    ///
    /// ⛔ **Transcribed**, `session.rs:530-536`. ⛔ **And it is the same in both
    /// terminal modes**: there is no line to submit in passthrough, so that list
    /// carries only the end.
    pub fn on_eof(&mut self) -> Vec<Event> {
        self.ended = true;
        match self.mode {
            Mode::NoPty => vec![Event::Eof],
            Mode::Cooked => self.cooked.submit_and_end(),
            Mode::Passthrough => vec![Event::Eof],
        }
    }

    /// A local resize arrived. ⛔ **The size to send now, or `None` while a frame
    /// is open** — ⛔ and **never dropped**, which is the whole difference
    /// between this and the sibling's refusal of window size.
    pub fn on_resize(&mut self, size: Size) -> Option<Size> {
        match self.mode {
            Mode::NoPty => None,
            Mode::Cooked => self.window.on_resize(size),
            Mode::Passthrough => self.pass.on_resize(size),
        }
    }

    /// A full-screen frame began. ⛔ **A no-op in the cooked mode**, because a
    /// cooked shell session has no frames: it has lines, and a line is not a
    /// frame. ⛔ Treating one as the other would defer every resize of a session
    /// that never draws a frame.
    pub fn begin_frame(&mut self) {
        if self.mode == Mode::Passthrough {
            self.pass.begin_frame();
        }
    }

    /// The full-screen frame ended. ⛔ Returns a held size, if one.
    pub fn end_frame(&mut self) -> Option<Size> {
        match self.mode {
            Mode::NoPty => None,
            Mode::Cooked => self.window.end_frame(),
            Mode::Passthrough => self.pass.end_frame(),
        }
    }

    /// Whether a full-screen frame is open. ⛔ **False in the cooked mode
    /// always**, and ⛔ **that is the control for the resize deferral**: a cooked
    /// session that could open a frame would defer every resize of a session
    /// that never draws one.
    pub fn in_frame(&self) -> bool {
        matches!(self.mode, Mode::Passthrough) && self.pass.in_frame()
    }

    /// The cooked discipline, for a caller that needs its history or its line.
    ///
    /// ⛔ **`None` outside the cooked mode**, ⛔ so a caller cannot read a line
    /// buffer out of a session that has none. ⛔ This is what a test uses to
    /// assert that an interrupted command never reached history — ⛔ and it is
    /// deliberately an accessor rather than a public field, because a public
    /// field would let a caller mutate the buffer behind the cursor's back.
    pub fn cooked(&self) -> Option<&Discipline> {
        (self.mode == Mode::Cooked).then_some(&self.cooked)
    }
}

impl std::fmt::Debug for Session {
    /// ⛔ **Mode and `TERM`, and not the line buffer.** ⛔ A `Debug` that printed
    /// a live line would put whatever the user last typed into every log that
    /// touches a session — ⛔ and a session's line is exactly where a password
    /// typed into a mistaken prompt would end up.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("mode", &self.mode)
            .field("term", &self.term)
            .field("ended", &self.ended)
            .field("in_frame", &self.in_frame())
            .finish_non_exhaustive()
    }
}