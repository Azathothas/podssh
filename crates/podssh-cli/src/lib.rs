//! podssh's command line: one tree, two renderers, and refusals that name a
//! real flag.
//!
//! ⛔ **The seam is argv in, a typed command out**, and it is one seam:
//! [`tree::parse`] is the only way a command is selected, and [`dispatch`]
//! turns the result into an exit code. Everything else in this crate is a
//! renderer or a table, so there is exactly one place where a wrong command
//! line can be mistaken for a right one.
//!
//! ⛔ **`podssh` with no subcommand never connects.** `06-cli.md`:17 makes it
//! an error that explains itself, and the two-stage handler in [`refuse`] is
//! why `podssh example.org` says `Try: podssh ssh example.org` and never says
//! `doctor`.
//!
//! ⛔ **E32 (`man.rs`) owns the roff emitter and the parity gate and renders
//! [`flags::VERBS`] rather than growing a second table.** The flags of `chat`,
//! `cp`, `mv`, `relay` and `man` are defined here so they parse and are
//! refused correctly; their behaviour is E33, E36, E35 and E32's.

pub mod clap_error;
pub mod dispatch;
pub mod exit_codes;
// ⛔ **E24's fault table, as code.** ⛔ `exit_codes.rs` holds the two
// candidate usage constants and names the fork; `exitmap.rs` holds the whole
// table, the collision guard, and the tests that decide `2` versus `64`.
// ⛔ Two modules because they answer different questions: `exit_codes.rs` is
// "what does this crate emit today", `exitmap.rs` is "what the contract says".
pub mod exitmap;
pub mod flags;
pub mod help;
// ⛔ **E32's two modules, and they are separate because they are separate
// concerns**: `man.rs` emits roff from the tree and never reads a file,
// `pager.rs` shows the emitted bytes a screenful at a time and is a function
// rather than a `Command` — ⛔ there is no child process on `podssh man` at
// all, and `docs/spec/02-architecture.md`:108-121 is why that matters.
pub mod man;
pub mod non_interactive;
pub mod pager;
pub mod proxy;
pub mod refuse;
pub mod relay;
pub mod relay_token;
pub mod suggest;
pub mod token_cache;
pub mod tree;
// `podssh ts` links the vendored tailscale-rs fork, which needs a C toolchain,
// so it is compiled only with the `ts` feature (see Cargo.toml).
#[cfg(feature = "ts")]
pub mod ts;

// ⛔ **E12 and E13's credential paths live under this crate and nowhere else**,
// and `security/mod.rs` explains why: a token type that cannot be rendered and
// a trust store that refuses a wrong key are only worth having if every caller
// goes through them. ⛔ That module was written with `#[path = "..."]` so E31
// could own this file while it was being edited, and its own header says the
// `#[path]` attributes come out the moment this line exists — ⛔ leaving one in
// place after it stops being necessary is a second read path for the same
// code, and two read paths drift.
pub mod security;

pub use flags::{FlagKind, FlagRow, Verb, VERBS};
pub use tree::{parse, Parsed};