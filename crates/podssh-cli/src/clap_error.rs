//! `clap`'s errors, rebuilt as podssh's own messages — and **never rendered**.
//!
//! `docs/cli.md`, "Options of `podssh ssh`", asks for an unknown flag to be *"an error
//! that names the nearest real flag"*, and the sibling prints a full usage
//! block instead (`src/main.c:277`), which buries the one line the user needs.
//! `clap`'s own renderer adds a `Usage:` header and a
//! `For more information, try '--help'` trailer, so **nothing here calls
//! `render()`**: the error's *context* is read and podssh's words are built
//! from it.
//!
//! **Its own module because it is a different question from parsing.** The
//! tree decides what a command line means; this decides how a refusal reads.
//! `docs/architecture.md`, "Design rules", is the reason the two are not one file: it
//! puts a hard 500-line cap on source, *"Split a file by responsibility"* — and
//! `tree.rs` reached it.
//!
//! `was_given` stayed in [`crate::tree`]: it reads `ArgMatches`, not an
//! error, and moving it here would be a module boundary drawn by line count
//! rather than by what the code is about.

use crate::flags::FlagKind;
use crate::tree::Parsed;
use clap::error::{ContextKind, ContextValue, ErrorKind};

/// **Rebuild a `clap` error as podssh's own message, with no usage block.**
///
/// `clap 4.6`'s context is a `FlatMap<ContextKind, ContextValue>` and
/// `ContextValue` is an enum, not a list — MEASURED 2026-10-02 by reading
/// `clap_builder-4.6.7/src/error/context.rs` and `.../format.rs` in this
/// machine's cargo registry. The two shapes read here are
/// `ContextValue::String(_)` for the offending token and
/// `ContextValue::StyledStrs(_)` for the suggestions `strsim` produced.
pub fn rebuild_error(verb: &str, e: &clap::Error) -> Parsed {
    match e.kind() {
        ErrorKind::DisplayHelp => Parsed::Help(""),
        ErrorKind::DisplayVersion => Parsed::Version,
        ErrorKind::InvalidSubcommand => {
            let token = string_ctx(e, ContextKind::InvalidSubcommand);
            let verdict = crate::suggest::diagnose_no_subcommand(&token);
            Parsed::Usage(crate::refuse::unknown_verb(&token, &verdict))
        }
        ErrorKind::UnknownArgument => {
            let given = string_ctx(e, ContextKind::InvalidArg);
            // **The suggestion key is `SuggestedArg`, and that was measured
            // rather than assumed.** `cargo run -p podssh-cli --example
            // probe_clap` against `clap 4.6.7` in the build image, 2026-10-05,
            // prints for `ssh --StrictHostKeyChekcing=no host`:
            //   InvalidArg   = String("--StrictHostKeyChekcing")
            //   SuggestedArg = String("--StrictHostKeyChecking")
            //   Usage        = StyledStr("Usage: ssh --StrictHostKeyChecking …")
            //   Suggested    = StyledStrs(["to pass '--StrictHostKeyChekcing' as
            //                   a value, use '-- --StrictHostKeyChekcing'"])
            // `ContextKind::Suggested` is a **different** key: it carries
            // clap's `--` tip, not the nearest flag, so reading it would lose
            // the suggestion the refusal exists to name.
            // And `Usage` is present in the context, which is why this code
            // reads the context and never `e.render()`s: rendering is what
            // prints the block that buries the one line the user needs.
            //
            // `strsim`'s Damerau-Levenshtein found this at distance 2. A
            // hand-rolled function in the same place would have had to be
            // written and then measured to be as good, and the entry records
            // that a hand-rolled edit distance in this position was already
            // measured to be wrong for `example.org`.
            if !flag_shaped(&given) {
                return Parsed::Usage(crate::refuse::bad_invocation(verb, e.kind(), &given));
            }
            let suggestion = string_ctx_opt(e, ContextKind::SuggestedArg);
            Parsed::Usage(crate::refuse::unknown_flag(&given, suggestion.as_deref()))
        }
        // A known flag with no value: an invalid value that is empty, with
        // `InvalidArg` as `--long <VALUE>`, also when `-p` was typed (measured
        // with the `probe_clap` example, clap 4.6.7, 2026-10-08; GitHub #8).
        // A refused flag refuses as with a value, which would change nothing.
        ErrorKind::InvalidValue if matches!(e.get(ContextKind::InvalidValue), Some(ContextValue::String(v)) if v.is_empty()) =>
        {
            let given = string_ctx(e, ContextKind::InvalidArg);
            let long = given.strip_prefix("--").and_then(|s| s.split(' ').next()).unwrap_or_default();
            let row = crate::flags::verb_for(verb).and_then(|v| v.flags.iter().find(|r| r.long == long));
            match row {
                Some(r) if r.kind == FlagKind::Refused => {
                    Parsed::Usage(crate::refuse::refused(verb, &r.usage_form(), r.instead.unwrap_or(""), r.help))
                }
                Some(r) => Parsed::Usage(crate::refuse::missing_value(verb, r)),
                None => unknown(verb, e, &given),
            }
        }
        _ => unknown(verb, e, &string_ctx(e, ContextKind::InvalidArg)),
    }
}

/// Today's message for any other error: an unknown flag when the token was
/// written as a flag, else a bad invocation.
fn unknown(verb: &str, e: &clap::Error, given: &str) -> Parsed {
    if !flag_shaped(given) {
        return Parsed::Usage(crate::refuse::bad_invocation(verb, e.kind(), given));
    }
    let suggestion = string_ctx_opt(e, ContextKind::SuggestedArg);
    Parsed::Usage(crate::refuse::unknown_flag(given, suggestion.as_deref()))
}

/// **Whether a token was written as a flag.**
///
/// **`clap` uses the same context key for the two, and the shape is the only
/// thing that separates them**: an unknown flag's name and a positional's *usage
/// string* both arrive in `ContextKind::InvalidArg`. Reporting the second as
/// the first told the user a flag they never typed does not exist — `podssh cp a`
/// printed `unknown flag '[paths] [paths]...'`, and `podssh man ssh extra`
/// printed `unknown flag 'extra'`. `-` alone is a positional (stdin), not a
/// flag.
fn flag_shaped(token: &str) -> bool {
    token.starts_with('-') && token != "-"
}

/// Read a `ContextValue::String` out of a `clap` error, or `""`.
fn string_ctx(e: &clap::Error, kind: ContextKind) -> String {
    match e.get(kind) {
        Some(ContextValue::String(s)) => s.clone(),
        Some(ContextValue::Strings(v)) => v.first().cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

/// Read the first suggestion out of a `clap` error as plain text.
///
/// `clap 4.6` carries a flag suggestion under `ContextKind::SuggestedArg` as
/// a plain `ContextValue::String` — MEASURED 2026-10-05 in the build image by
/// `cargo run -p podssh-cli --example probe_clap` against `clap 4.6.7`, which
/// printed `SuggestedArg = String("--StrictHostKeyChecking")`. A subcommand
/// suggestion arrives under `SuggestedSubcommand` instead, and the two are
/// read by the same function because the shape is identical.
fn string_ctx_opt(e: &clap::Error, kind: ContextKind) -> Option<String> {
    match e.get(kind)? {
        ContextValue::String(s) => non_empty(s.clone()),
        ContextValue::StyledStr(s) => non_empty(s.to_string()),
        ContextValue::Strings(v) => v.first().and_then(|s| non_empty(s.clone())),
        _ => None,
    }
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}
