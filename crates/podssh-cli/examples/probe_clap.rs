//! What `clap` puts in the kind and the context of an error.
//!
//! ⛔ `src/clap_error.rs` reads `ContextKind::SuggestedArg` and not
//! `ContextKind::Suggested`, and this probe is the measurement behind that
//! sentence: `cargo run -p podssh-cli --example probe_clap`.
//! ⛔ It parses the typo `tests/plants.rs` uses, through the real verb command
//! [`podssh_cli::tree::verb_command`] builds, so the context printed here is
//! the context the crate's own parser produces.
//!
//! With arguments, it parses those instead, the first being the verb:
//! `cargo run -p podssh-cli --example probe_clap -- ssh -p` shows how a flag
//! with no value arrives (GitHub #8).

use clap::error::ContextKind;
use podssh_cli::flags::VERBS;
use podssh_cli::tree::verb_command;

fn main() {
    let given: Vec<String> = std::env::args().skip(1).collect();
    let argv: Vec<String> = if given.is_empty() {
        ["ssh", "--StrictHostKeyChekcing=no", "host"].iter().map(|s| s.to_string()).collect()
    } else {
        given
    };
    let verb = VERBS.iter().find(|v| v.aliases.contains(&argv[0].as_str())).expect("the first argument is a verb");
    let err = match verb_command(verb).try_get_matches_from(&argv) {
        Ok(_) => {
            println!("{argv:?} parses with no error");
            return;
        }
        Err(e) => e,
    };
    println!("kind = {:?}", err.kind());
    for kind in [
        ContextKind::InvalidArg,
        ContextKind::InvalidValue,
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
