//! podssh's command line: one tree, two renderers, and refusals that name a
//! real flag.
//!
//! **The seam is argv in, a typed command out**, and it is one seam:
//! [`tree::parse`] is the only way a command is selected, and [`dispatch`]
//! turns the result into an exit code. Everything else in this crate is a
//! renderer or a table, so there is exactly one place where a wrong command
//! line can be mistaken for a right one.
//!
//! **`podssh` with no subcommand never connects.** `docs/cli.md` makes it
//! an error that explains itself ("A word with no subcommand"): the two-stage handler in
//! [`refuse`] is why `podssh example.org` says `Try: podssh ssh example.org` and never says
//! `doctor`.
//!
//! `podssh man` ([`man`]) renders the same tables as `--help`, with the
//! facts, notes and examples beside them, as text or as roff. The flags of
//! `chat`, `cp`, `mv` and `relay` are defined so they parse and are refused
//! correctly; those commands are not implemented yet.

// A dependency that no code uses fails the build (the tests have their own).
#![cfg_attr(not(test), deny(unused_crate_dependencies))]

pub mod clap_error;
pub mod cp;
pub mod dispatch;
pub mod doctor;
pub mod exit_codes;
// **The fault table of the exit codes, as code.** `exit_codes.rs` holds the two
// candidate usage constants and names the fork; `exitmap.rs` holds the whole
// table, the collision guard, and the tests that decide `2` versus `64`.
// Two modules because they answer different questions: `exit_codes.rs` is
// "what does this crate emit today", `exitmap.rs` is "what the contract says".
pub mod exitmap;
// Tables, one flag to a row: rustfmt would spread each row over many lines.
#[rustfmt::skip]
pub mod flags;
pub mod help;
pub mod keygen;
pub mod layered;
// The manual (`man/`) and the pager that shows it on a terminal.
pub mod man;
pub mod node;
// `podssh node --iroh`: the iroh road, with the feature `iroh` only.
#[cfg(feature = "iroh")]
pub mod node_iroh;
pub mod non_interactive;
pub mod operator;
pub mod pager;
mod pairs;
pub mod parsed;
pub mod pins;
pub mod positionals;
pub mod proxy;
pub mod refuse;
pub mod relay_cmd;
pub mod relay_settings;
pub mod relay_spec;
pub mod sftp;
pub mod ssh;
pub mod status;
pub mod suggest;
pub mod tree;
// `podssh ts` links the vendored tailscale-rs fork, which needs a C toolchain,
// so it is compiled only with the `ts` feature (see Cargo.toml).
#[cfg(feature = "ts")]
pub mod ts;

pub use flags::{FlagKind, FlagRow, Verb, VERBS};
pub use tree::{parse, Parsed};
