//! What `clap` puts in the context of an `UnknownArgument` error.
//!
//! ⛔ `src/clap_error.rs` reads `ContextKind::SuggestedArg` and not
//! `ContextKind::Suggested`, and this probe is the measurement behind that
//! sentence: `cargo run -p podssh-cli --example probe_clap`.
//! ⛔ It parses the typo `tests/plants.rs` uses, through the real verb command
//! [`podssh_cli::tree::verb_command`] builds, so the context printed here is
//! the context the crate's own parser produces.

use clap::error::ContextKind;
use podssh_cli::flags::VERBS;
use podssh_cli::tree::verb_command;

fn main() {
    let ssh = VERBS
        .iter()
        .find(|v| v.name == "ssh")
        .expect("ssh is a verb");
    let err = verb_command(ssh)
        .try_get_matches_from(["ssh", "--StrictHostKeyChekcing=no", "host"])
        .expect_err("the typo must be an unknown argument");
    for kind in [
        ContextKind::InvalidArg,
        ContextKind::SuggestedArg,
        ContextKind::Usage,
        ContextKind::Suggested,
    ] {
        match err.get(kind) {
            Some(value) => println!("{kind:?} = {value:?}"),
            None => println!("{kind:?} = <absent>"),
        }
    }
}
