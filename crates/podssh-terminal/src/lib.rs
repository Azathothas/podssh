//! E07 — the userspace line discipline, for a host with no pty.
//!
//! ⛔ **This crate never touches the network.** It owns echo, line editing,
//! history, signal characters, `TERM` selection, and window size. The bytes
//! arrive over SSH from [`podssh-core`] and leave again; nothing here dials,
//! reads a socket, or knows a relay exists.
//!
//! ## Where the bytes come from
//!
//! The relay has no pty, tty, terminal, isatty or termios concept anywhere in
//! its 15 477 bytes — **MEASURED**, grep over the live `llms-full.txt` (see the
//! entry's Premise). So the pty question is never "what does the relay give us"
//! but "does the SSH **server** grant a pty, and can podssh present one
//! locally". When `/dev/ptmx` does not open on the local host, the answer has to
//! be yes: podssh implements the terminal itself, in userspace, in Rust, with
//! no `LD_PRELOAD` and no C compiler.
//!
//! ## Two disciplines, one binary
//!
//! The mode is **chosen by what the server granted**, never by guessing:
//!
//! | Mode | When | Who owns the screen |
//! | --- | --- | --- |
//! | [`echo::Discipline`] | `pty-req` accepted, the remote program is a shell | podssh: echo, editing, history, a static prompt |
//! | [`passthrough::Passthrough`] | `pty-req` accepted, the remote program is not a shell | the remote side, whole |
//!
//! ⛔ **A full-screen program is a separate mode, not a richer cooked mode.** The
//! echo discipline **drops** cursor addressing, because a discipline that
//! interprets sequences it has not tested corrupts somebody's terminal. A `vi`
//! cannot run under those rules, so `vi` gets the other mode — where podssh
//! owns only window size and signals, and touches no other byte.
//!
//! ## What was transcribed, and what was not
//!
//! ⭐ **The echo discipline is a transcription, not an invention.** podbox ships
//! this exact discipline server-side and its byte rules are pinned by ~40 named
//! tests — **READ**, `.tmp/podbox/crates/podbox-ssh/src/session.rs:1`. Every
//! constant here cites the line it came from, and every refusal is in the
//! catalogue below.
//!
//! ⛔ **One behaviour is deliberately NOT transcribed.** The sibling *refuses*
//! window size, because `sshd`'s `ForceCommand` consumes size changes before any
//! byte reaches it — **READ**, `session.rs:47-50`. ⛔ podssh is not behind
//! `ForceCommand`: podssh issues `window-change` itself. So [`window`] honours
//! a resize and **defers** one that arrives mid-frame rather than dropping it.
//! Copying the sibling's refusal would have shipped that bug.
//!
//! ## The refusal rule
//!
//! ⛔ **A refusal rings the bell and changes nothing.** Silence would read as
//! acceptance, and a user who cannot tell "not supported" from "did nothing"
//! will file it as a bug in the wrong place.
//!
//! ## The 500-line rule
//!
//! The reference is 1132 lines in one file and is not to be copied as one. Each
//! module below holds one thing and names it:
//!
//! - [`bytes`] — rendering bytes legibly, so a failing assertion names them
//! - [`echo`] — the line under edit: the byte rules, transcribed
//! - [`term`] — `TERM` selection and the `''|dumb|unknown` predicate
//! - [`window`] — window size, deferred while a frame is mid-draw
//! - [`passthrough`] — the second discipline, for a program that owns the screen
//! - [`refusal`] — the refusal catalogue both disciplines answer from
//! - [`session`] — the driver that chooses between them
//!
//! [`podssh-core`]: https://docs.rs/podssh-core

pub mod bytes;
pub mod echo;
pub mod escape;
pub mod passthrough;
pub mod refusal;
pub mod session;
pub mod term;
pub mod window;

pub use echo::{Discipline, Event, Sig, BELL, EL, HISTORY_CAP, LINE_CAP, PROMPT};
pub use passthrough::Passthrough;
pub use refusal::{Refusal, REFUSALS};
pub use session::{Mode, Session};
pub use term::{TermChoice, TERM_ENV, TERM_OVERRIDE_ENV, TERM_PREDICATE_USABLE};
pub use window::{Size, Window};