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

pub mod agent;
pub mod channel;
pub mod chat;
pub mod clap_error;
pub mod config_import;
// `podssh containers`: the containers of a host, and --exec (T-190).
pub mod containers;
pub mod cp;
pub mod dispatch;
pub mod doctor;
// `podssh each`: one command on many hosts at once (T-183).
pub mod each;
// `podssh edit`: one far file, changed in an editor here (T-149).
pub mod edit;
// The report of a failure, to the program of `PODSSH_ERROR_PROGRAM` (T-195).
pub mod error_program;
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
// `podssh health`: the facts of the far host, over one exec (T-189).
pub mod health;
// The hosts of a word: braces and groups (T-184).
pub mod hosts;
// `podssh job`: jobs on a far host, each in its tmux (T-193).
pub mod job;
pub mod keygen;
pub mod keygen_cert;
pub mod keygen_change;
pub mod keygen_convert;
pub mod keygen_hosts;
pub mod keygen_sign;
pub mod keygen_sk;
pub mod layered;
// The manual (`man/`) and the pager that shows it on a terminal.
pub mod man;
// `podssh mcp`: the commands as tools for an agent (T-055).
pub mod mcp;
pub mod node;
pub mod node_args;
// `podssh node --install`: the node as a service of this user (T-121).
pub mod node_install;
// The flags of `podssh node` that each road reads: the keys, the resume
// deadline (T-306).
pub mod node_flags;
// `podssh node NAME udp:HOST:PORT`: a UDP target, one flow for each session.
pub mod node_udp;
// `podssh node --iroh`: the iroh road, with the feature `iroh` only.
#[cfg(feature = "iroh")]
pub mod node_iroh;
// `podssh node --quick-tunnel`: a quick tunnel of Cloudflare's, which podssh
// makes itself (T-300).
pub mod node_quick;
// `podssh node --temporary`: the far end of `podssh ssh --upgrade` (T-167).
pub mod node_temp;
pub mod non_interactive;
pub mod operator;
pub mod pager;
mod pairs;
pub mod parsed;
pub mod ping;
pub mod pins;
pub mod pipe;
pub mod play;
pub mod positionals;
pub mod proxy;
pub mod refuse;
pub mod relay_cmd;
pub mod relay_diag;
mod relay_diag_text;
pub mod relay_settings;
pub mod relay_spec;
// `podssh session`: a session that outlives each call of an agent (T-186).
pub mod session;
// `podssh run`: copy a project, then run a command in it (T-192).
pub mod run_cmd;
pub mod session_log;
pub mod settings;
pub mod sftp;
// Commands of the settings file, shown and asked before they run (T-187).
pub mod snippets;
pub mod ssh;
pub mod status;
pub mod suggest;
pub mod tree;
// `podssh ts` links the vendored tailscale-rs fork, which needs a C toolchain,
// so it is compiled only with the `ts` feature (see Cargo.toml).
#[cfg(feature = "ts")]
pub mod ts;
// The line of a temporary node to `podssh ssh --upgrade` (T-167).
mod upgrade_line;
// The commit that a release build names in `--version` (T-210).
pub mod version;

pub use flags::{FlagKind, FlagRow, Verb, VERBS};
pub use tree::{parse, Parsed};
