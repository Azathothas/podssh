//! The driver: which discipline a session runs, and how the two differ.
//!
//! **Three facts choose the mode, and the absence of a pty is not one of
//! them.** A pty below the session, or a line discipline below it (as in
//! podbox's server), already echoes and edits; a second echo here shows each
//! key twice. So the discipline runs only when the caller selected it and
//! nothing below echoes: `podssh serve` with no `/dev/ptmx` selects it
//! (T-111), and a client flag may later. **A missing pty alone never selects
//! it**: it says nothing of what the program on the other side expects.
//!
//! ## The two modes
//!
//! | Mode | When | What the caller gets |
//! | --- | --- | --- |
//! | [`Mode::Cooked`] | selected, with no pty and no discipline below | echo, editing, history, a static prompt |
//! | [`Mode::Transparent`] | each other case | each byte both ways as it came; the size held across a frame |
//!
//! ## Where the two modes differ, and that is worth knowing
//!
//! **The forward leg, the frames, and the reverse leg.** In the transparent
//! mode each byte of the program passes as it came. In the cooked mode the
//! program writes to a pipe while the user edits a line, so its output is
//! written around the line, with each `\n` as `\r\n` ([`crate::echo`]'s
//! `output`). And one difference is the sharpest thing this entry has to say:
//!
//! > A `\r\n` pair means **two different things** in the two modes. In cooked it
//! > is a user's Enter and its pair, and the `\n` is swallowed so a command does
//! > not run twice. In the transparent mode it is a remote program's own `ONLCR`,
//! > and swallowing the `\n` would delete a byte it wrote deliberately.
//!
//! **One mode with a flag could not carry both answers**, because the flag
//! would have to be "the last submit was mine", which is a guess about the peer's
//! output discipline. That test is `the_two_modes_agree_where_they_must` in the
//! integration suite, because it needs both modes in one place.
//!
//! ## The inherited limit, carried not hidden
//!
//! **Ignored signal dispositions are inherited across `fork` and `exec`**, so a
//! command started under a trap-ignoring shell ignores the signal too, and no
//! inner `trap -` undoes an ignore inherited on entry. **READ**,
//! `podbox/crates/podbox-ssh/src/session.rs:75-80`, verbatim: *"Killing the
//! command while the shell survives needs a trap handler: trapped signals reset
//! to the default in children while the shell itself runs the handler."*
//! **podssh inherits this and does not solve it**: it is a property of the remote
//! shell, and the fix is a trap on the remote side, which is not this crate's to
//! install.

use crate::echo::{Discipline, Event};
use crate::passthrough::Passthrough;
use crate::window::Size;

/// What lies below the session, and what the caller asked for: the three
/// facts that choose the mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    /// A pty is below: a kernel pty, or a tty that podssh answers for.
    pub pty_below: bool,
    /// A line discipline with no pty is below, as in podbox's server.
    pub discipline_below: bool,
    /// The caller selected this discipline: `podssh serve` with no
    /// `/dev/ptmx`, or a flag.
    pub selected: bool,
}

/// Which discipline a session runs.
///
/// **Every variant is derived from the facts, never constructed by hand.**
/// [`Mode::select`] is the one way to name one, so a mode that the facts did
/// not justify cannot be written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Echo, editing, history and the prompt are done here.
    Cooked,
    /// Each byte passes both ways unchanged, with no echo and no refusal.
    Transparent,
}

impl Mode {
    /// Cooked only when selected with nothing below that echoes: a second
    /// echo shows each key twice, and a missing pty alone says nothing about
    /// the program.
    pub fn select(facts: Facts) -> Mode {
        if facts.selected && !facts.pty_below && !facts.discipline_below {
            Mode::Cooked
        } else {
            Mode::Transparent
        }
    }
}

/// One session: a mode, the discipline it chose, and the size half.
///
/// **Holds both disciplines, and only one of them is ever live.** That is
/// the point: a `Mode` is decided once at construction and cannot be re-decided
/// from the bytes later, so a session cannot drift from one owner of the screen
/// to another mid-run.
pub struct Session {
    mode: Mode,
    cooked: Discipline,
    pass: Passthrough,
    ended: bool,
}

impl Session {
    /// **The only constructor, and it takes the three facts.** There is no
    /// way to build a `Session` without saying what lies below it, so a
    /// caller cannot skip the decision and get a mode by accident.
    pub fn new(facts: Facts) -> Session {
        Session::with_utf8(facts, false)
    }

    /// [`Session::new`], for a terminal that is UTF-8 (`IUTF8` in the modes of
    /// `pty-req`), whose cursor steps over characters rather than bytes.
    pub fn with_utf8(facts: Facts, utf8: bool) -> Session {
        Session {
            mode: Mode::select(facts),
            cooked: Discipline::with_utf8(utf8),
            pass: Passthrough::new(),
            ended: false,
        }
    }

    /// The session, with the terminal's size: as the client measured it, or
    /// as `pty-req` carried it. The cooked discipline needs the width to draw
    /// a line longer than one row; the transparent mode keeps it as the size
    /// already sent with the request.
    pub fn sized(mut self, size: Size) -> Session {
        // The line is empty, so the discipline draws nothing here.
        let _ = self.cooked.resize(size);
        let _ = self.pass.on_resize(size);
        self
    }

    /// The mode, decided from the facts.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether input has ended.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// One local byte in, its consequences out.
    ///
    /// **The one entry point, and the mode decides which discipline runs.**
    /// The transparent mode reads no byte: the pty or the discipline below
    /// acts on each one, Ctrl-C and Ctrl-Z too.
    pub fn on_local_byte(&mut self, b: u8) -> Vec<Event> {
        match self.mode {
            Mode::Cooked => self.cooked.key(b),
            Mode::Transparent => self.pass.forward_local(b),
        }
    }

    /// Local bytes in, their consequences out, in order.
    ///
    /// **Events are accumulated, never dropped** — a caller that received only
    /// the last event would lose a submit that a redraw followed. And
    /// [`Event::Eof`] **stops the loop**, so the rest of a buffer that arrived
    /// with an EOF is not interpreted as new lines. The transparent mode sends
    /// the chunk as one event.
    pub fn on_local_bytes(&mut self, bytes: &[u8]) -> Vec<Event> {
        if self.mode == Mode::Transparent {
            return self.pass.forward_local_bytes(bytes);
        }
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

    /// Whether the cooked discipline holds a key still open: a lone `ESC`, a
    /// key cut short, or a character typed in parts. **The caller then calls
    /// [`Session::on_idle`] when no byte came for [`crate::echo::IDLE`]**,
    /// and the crate reads no clock. Never in the transparent mode, which
    /// reads no key.
    pub fn waiting(&self) -> bool {
        self.mode == Mode::Cooked && self.cooked.waiting()
    }

    /// No local byte came for [`crate::echo::IDLE`] while
    /// [`Session::waiting`]: an open key ends, with one bell for an escape.
    pub fn on_idle(&mut self) -> Vec<Event> {
        match self.mode {
            Mode::Cooked => self.cooked.idle(),
            Mode::Transparent => vec![],
        }
    }

    /// Remote bytes in, their consequences out.
    ///
    /// **As they came in the transparent mode**: a full-screen program owns
    /// the screen, and a discipline that edited its bytes would be editing
    /// output it does not own. **Around the line under edit in the cooked
    /// mode**, with each `\n` as `\r\n`, since the program writes to a pipe
    /// and nothing else would keep its output out of the line. After the end
    /// of input no line is drawn, and only the newlines change.
    pub fn on_remote_bytes(&mut self, bytes: &[u8]) -> Vec<Event> {
        match self.mode {
            Mode::Cooked if bytes.is_empty() => vec![],
            Mode::Cooked if self.ended => vec![Event::ToLocal(crate::echo::output::onlcr(bytes))],
            Mode::Cooked => self.cooked.output(bytes),
            Mode::Transparent => self.pass.forward_remote(bytes),
        }
    }

    /// Client EOF: submit a partial line, then end input.
    ///
    /// **Transcribed**, `session.rs:530-536`. There is no line to submit in
    /// the transparent mode, so that list carries only the end.
    pub fn on_eof(&mut self) -> Vec<Event> {
        self.ended = true;
        match self.mode {
            Mode::Cooked => self.cooked.submit_and_end(),
            Mode::Transparent => vec![Event::Eof],
        }
    }

    /// A local resize arrived. In the transparent mode, **the size to send
    /// now, as [`Event::Size`], or nothing while a frame is open** — and
    /// **never dropped**, which is the whole difference between this and the
    /// sibling's refusal of window size. In the cooked mode nothing below has
    /// a size; the discipline takes the new width, and draws the line again
    /// when the width changed.
    pub fn on_resize(&mut self, size: Size) -> Vec<Event> {
        match self.mode {
            Mode::Cooked => self.cooked.resize(size),
            Mode::Transparent => self.pass.on_resize(size).map(Event::Size).into_iter().collect(),
        }
    }

    /// A full-screen frame began. **A no-op in the cooked mode**, because a
    /// cooked shell session has no frames: it has lines, and a line is not a
    /// frame. Treating one as the other would defer every resize of a session
    /// that never draws a frame.
    pub fn begin_frame(&mut self) {
        if self.mode == Mode::Transparent {
            self.pass.begin_frame();
        }
    }

    /// The full-screen frame ended. Returns a held size, if one: never in the
    /// cooked mode, which holds no frame.
    pub fn end_frame(&mut self) -> Option<Size> {
        match self.mode {
            Mode::Cooked => None,
            Mode::Transparent => self.pass.end_frame(),
        }
    }

    /// Whether a full-screen frame is open. **False in the cooked mode
    /// always**, and **that is the control for the resize deferral**: a cooked
    /// session that could open a frame would defer every resize of a session
    /// that never draws one.
    pub fn in_frame(&self) -> bool {
        matches!(self.mode, Mode::Transparent) && self.pass.in_frame()
    }

    /// The cooked discipline, for a caller that needs its history or its line.
    ///
    /// **`None` outside the cooked mode**, so a caller cannot read a line
    /// buffer out of a session that has none. This is what a test uses to
    /// assert that an interrupted command never reached history — and it is
    /// deliberately an accessor rather than a public field, because a public
    /// field would let a caller mutate the buffer behind the cursor's back.
    pub fn cooked(&self) -> Option<&Discipline> {
        (self.mode == Mode::Cooked).then_some(&self.cooked)
    }
}

impl std::fmt::Debug for Session {
    /// **The mode, and not the line buffer.** A `Debug` that printed a live
    /// line would put whatever the user last typed into every log that touches
    /// a session — and a session's line is exactly where a password typed into
    /// a mistaken prompt would end up.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("mode", &self.mode)
            .field("ended", &self.ended)
            .field("in_frame", &self.in_frame())
            .finish_non_exhaustive()
    }
}
