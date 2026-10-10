//! `podssh chat` between two podssh ends (T-099): one conversation over the
//! end-to-end channel of a road (T-088), with the protocol of
//! `podssh_core::chat`. Each line of stdin is a message, and each message of
//! the peer a line of stdout; `/file`, `/accept` and `/decline` act on files;
//! notices go to stderr, or each event to stdout as JSON with `--jsonl`. A
//! file is written only once the user accepts it, and nothing that arrives is
//! run.

mod args;
pub mod converse;
pub mod files;
pub mod input;
mod iroh;
pub mod lines;
mod listen;
pub mod output;
mod reach;
mod run;
mod talk;

pub use args::ChatArgs;
pub use converse::{converse, converse_until, Ended, Once, Options, Summary};
pub use lines::Lines;
pub use run::run_chat;
