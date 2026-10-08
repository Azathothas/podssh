//! The command tree. ⛔ **This is the single definition both renderers walk**:
//! `--help` is [`crate::help`]'s projection of it and `podssh man` is E32's.
//!
//! ⛔ **Why this is a table of [`Verb`]s and not a `clap` derive tree.** Two
//! reasons, and both are in the entry:
//!
//! 1. ⛔ **`-P` means different things on different verbs**, MEASURED on this
//!    machine against OpenSSH_10.3p1: `ssh` usage prints `[-P tag]`, `scp`
//!    usage prints `[-P port]`, `sftp -h` prints `[-P port]`. ⛔ A single
//!    `#[derive(Parser)]` struct cannot express that, because `clap` resolves a
//!    short flag per command — so `ssh` and `cp` genuinely need separate
//!    builders, which is what [`verb_command`] returns.
//! 2. ⛔ **E32 must render the tree without editing it.** A `derive` tree is
//!    Rust syntax; a sibling module cannot walk it without a macro. [`Verb`] is
//!    data, so `man.rs` walks [`crate::flags::VERBS`] and gets every flag,
//!    alias and help string with no second list to keep in step.
//!
//! ⛔ **The tree is built for parsing, not for help.** Help is rendered by
//! [`crate::help`] from [`crate::flags::VERBS`] so that the two cannot
//! disagree, and `clap`'s own help output is never printed.

use crate::flags::{FlagKind, FlagRow, Verb};
use clap::{Arg, ArgAction, ArgMatches, Command};

/// ⛔ **The two flags OpenSSH lets a user repeat, and neither takes a value.**
///
/// ⛔ `-v` increments a level; `-q` *"increase[s] the quietness"*. ⛔ Every other
/// row is a value, a switch, or a refusal — and a refusal is refused on its
/// first occurrence.
fn counted(long: &str) -> bool {
    // `-tt` is how OpenSSH forces a pty without a local terminal.
    matches!(long, "verbose" | "quiet" | "force-tty")
}

/// Value flags a user may give more than once, each value kept, in order.
fn appended(long: &str) -> bool {
    matches!(long, "option" | "identity-file")
}

/// A pod name in the parser's grammar. ⛔ `ssh`/`cp` take their own so that a
/// token the top level did not consume is reported against the verb the user
/// actually typed, naming that verb's flags.
fn add_flag(cmd: Command, row: &'static FlagRow, keep_each: bool) -> Command {
    let mut arg = Arg::new(row.long).long(row.long).help(row.help);
    // ⛔ A row that takes an argument is `Set`; a boolean is `SetTrue`; `-v` and
    // `-q` are **counts**.
    //
    // ⛔ **A count is not decoration.** `06-cli.md`:65 makes `-v`/`-q` parity
    // flags, `ssh -v -v -v` is how a user raises verbosity, and OpenSSH's own
    // words for `-q` are *"Multiple -q options increase the quietness"*. ⛔ The
    // first version of this function had a `Count` arm guarded on
    // `row.arg.is_some()`, and **neither row declares an argument value** — so
    // the arm was unreachable and a repeated flag was refused as
    // `unknown flag '--verbose'`, which is a flag that is not unknown, only
    // repeated.
    //
    // ⛔ A counted flag declares **no** argument value (`flags.rs`: `-v` and `-q`
    // are the two rows with `arg: None` and a counted spelling), and the `None`
    // arm below is where they are matched.
    arg = match row.arg {
        // `ssh` keeps each value of a repeated flag, and `ssh::args` picks one
        // the way OpenSSH does, or refuses the repeat.
        Some(a) if keep_each || appended(row.long) => arg.value_name(a).num_args(1).action(ArgAction::Append),
        Some(a) => arg.value_name(a).num_args(1).action(ArgAction::Set),
        None if counted(row.long) => arg.action(ArgAction::Count),
        None => arg.action(ArgAction::SetTrue),
    };
    // ⛔ Refused rows are **still declared**, so `ssh -L 8080:db:5432` reaches
    // a refusal naming `-W` rather than being reported as an *unknown* flag,
    // which is a different and worse message.
    if let Some(c) = row.short {
        arg = arg.short(c);
    }
    cmd.arg(arg)
}

/// Build one verb's parser from its flag rows.
pub fn verb_command(verb: &'static Verb) -> Command {
    let mut cmd = Command::new(verb.name)
        .about(verb.about)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            // ⛔ The universal option's spelling and sentence come from
            // [`crate::flags::HELP_FLAG`], so the parser, `--help` and the man
            // page cannot describe it differently.
            Arg::new(crate::flags::HELP_FLAG.long)
                .long(crate::flags::HELP_FLAG.long)
                .action(ArgAction::SetTrue)
                .help(crate::flags::HELP_FLAG.help),
        );
    for row in verb.flags {
        cmd = add_flag(cmd, row, verb.name == "ssh");
    }
    cmd = crate::positionals::add(cmd, verb.name);
    for alias in verb.aliases {
        cmd = cmd.alias(*alias);
    }
    cmd
}

pub use crate::parsed::Parsed;

/// Parse a whole `argv` **after** the program name.
///
/// ⛔ **The two-stage no-subcommand handler lives here and nowhere else**, and
/// its order is load-bearing: `podssh example.org` must be answered as a host,
/// and no distance function gets a vote before the shape stage has run. See
/// [`crate::refuse`].
pub fn parse<I, S>(args: I) -> Parsed
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let argv: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();

    // ⛔ Stage zero: no arguments at all. Never an implicit ssh.
    if argv.is_empty() {
        return Parsed::NoArguments(crate::refuse::no_arguments());
    }

    let first = match argv[0].to_str() {
        Some(s) => s.to_string(),
        // A non-UTF-8 first token cannot be a verb podssh knows.
        None => {
            return Parsed::UnknownVerb(crate::refuse::unknown_verb(
                "<non-utf8>",
                &crate::suggest::NoSubcommand::NoMatch,
            ))
        }
    };

    // ⛔ The global flags, read before any subcommand is selected, so
    // `podssh --help` never needs a verb. A word after them is answered or
    // refused, never dropped (GitHub #10).
    match first.as_str() {
        "-h" | "--help" => return top_help(&first, &argv[1..]),
        "-V" | "--version" => {
            return match argv.get(1) {
                None => Parsed::Version,
                Some(word) => Parsed::Usage(crate::refuse::extra_word(&first, &word.to_string_lossy())),
            }
        }
        _ => {}
    }

    // ⛔ A leading `-` at the top level names no verb and has no verb to name
    // a flag against, so it is reported with no guess rather than a wrong one.
    if first.starts_with('-') {
        return Parsed::Usage(crate::refuse::unknown_flag(&first, None));
    }

    let Some(verb) = crate::flags::verb_for(&first) else {
        // ⛔ Both stages, in order, and the verdict carries the message.
        let verdict = crate::suggest::diagnose_no_subcommand(&first);
        return Parsed::UnknownVerb(crate::refuse::unknown_verb(&first, &verdict));
    };

    parse_verb(verb, &argv[1..])
}

/// `podssh --help` alone, or with one word that names a verb: that verb's
/// help, as `podssh VERB --help` gives it. Any other word is refused.
fn top_help(flag: &str, rest: &[std::ffi::OsString]) -> Parsed {
    let mut words = rest.iter().map(|w| w.to_string_lossy().into_owned());
    let Some(word) = words.next() else { return Parsed::Help("") };
    let Some(verb) = crate::flags::verb_for(&word) else {
        if word.starts_with('-') {
            return Parsed::Usage(crate::refuse::extra_word(flag, &word));
        }
        let verdict = crate::suggest::diagnose_no_subcommand(&word);
        return Parsed::UnknownVerb(crate::refuse::unknown_verb(&word, &verdict));
    };
    match words.next() {
        None => Parsed::Help(verb.name),
        Some(extra) => Parsed::Usage(crate::refuse::extra_word(&format!("{flag} {}", verb.name), &extra)),
    }
}

/// ⛔ **The per-verb half.** ⛔ This is where `-P` means port on `cp` and a Tag
/// on `ssh`, because the two verbs have different `clap` commands.
pub fn parse_verb(verb: &'static Verb, rest: &[std::ffi::OsString]) -> Parsed {
    // ⛔ `--jsonl` under `proxy` never reaches `clap`: it is refused here with
    // the reason, because the generic unknown-flag text cannot say why JSON
    // cannot go where the SSH byte stream goes. Exact spellings only — a
    // positional that merely contains the substring is somebody's hostname.
    if verb.name == "proxy"
        && rest.iter().any(|a| a == "--jsonl" || a.to_str().is_some_and(|s| s.starts_with("--jsonl=")))
    {
        return Parsed::Usage(crate::non_interactive::refuse_jsonl_in_proxy().message);
    }

    // ⛔ `--ts-mode` values are closed: auto tun socks tcp relay. Anything else
    // is usage 64 now, not a fallthrough to auto later. Both spellings
    // (`--ts-mode bogus` and `--ts-mode=bogus`); a `--ts-mode` with no usable
    // value falls through to clap, which reports the missing value itself.
    if verb.name == "ts" {
        let mut mode_value: Option<String> = None;
        let mut rest_iter = rest.iter().peekable();
        while let Some(a) = rest_iter.next() {
            let Some(s) = a.to_str() else { continue };
            if let Some(v) = s.strip_prefix("--ts-mode=") {
                mode_value = Some(v.to_string());
            } else if s == "--ts-mode" {
                if let Some(next) = rest_iter.peek() {
                    if let Some(ns) = next.to_str() {
                        if !ns.starts_with('-') {
                            mode_value = Some(ns.to_string());
                        }
                    }
                }
            }
        }
        if let Some(m) = mode_value {
            if !matches!(m.as_str(), "auto" | "tun" | "socks" | "tcp" | "relay") {
                return Parsed::Usage(format!(
                    "podssh ts: --ts-mode {m} is not a mode. Use one of: auto, tun, socks, tcp, relay."
                ));
            }
        }
    }

    let matches = match verb_command(verb).try_get_matches_from(
        std::iter::once(std::ffi::OsString::from(verb.name)).chain(rest.iter().cloned()),
    ) {
        Ok(m) => m,
        Err(e) => return crate::clap_error::rebuild_error(verb.name, &e),
    };

    if matches.get_flag("help") {
        return Parsed::Help(verb.name);
    }

    // ⛔ Refused flags are found by their id — one per row, shared by the short
    // and long spelling — so `-L` and `--forward-local` refuse identically.
    let mut refused: Vec<(String, &'static str, &'static str)> = Vec::new();
    for row in verb.flags {
        if row.kind == FlagKind::Refused && was_given(&matches, row.long) {
            refused.push((row.usage_form(), row.instead.unwrap_or(""), row.help));
        }
    }

    // ⛔ `-P` on `ssh` is a Tag: accepted, ignored, and it says so rather than
    // failing silently. On `cp`/`mv` it is the port and needs no notice.
    let tag = if verb.name == "ssh" {
        matches.get_one::<String>("tag").filter(|t| !t.is_empty()).cloned()
    } else {
        None
    };

    // The refusal list is carried over rather than dropped: `MAN_FLAGS` has no
    // `Refused` row today, and a flag that refuses must refuse rather than be
    // a field nothing reads.
    if verb.name == "man" {
        return Parsed::Man {
            section: matches.get_one::<String>("section").cloned(),
            no_pager: matches.get_flag("no-pager"),
            roff: matches.get_flag("roff"),
            json: matches.get_flag("json"),
            refused,
        };
    }

    if verb.name == "proxy" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Proxy {
            target: get("target"),
            port: get("port"),
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            refused,
        };
    }

    if verb.name == "status" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Status {
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            destination: get("destination"),
            refused,
        };
    }

    if verb.name == "node" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Node(Box::new(crate::node::NodeArgs {
            name: get("name"),
            target: get("target"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            pair_file: get("pair-file"),
            refused,
        }));
    }

    if verb.name == "relay" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Relay(Box::new(crate::relay_cmd::RelayArgs {
            subcommand: get("subcommand"),
            args: matches.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            operator_file: get("operator-file"),
            refused,
        }));
    }

    if verb.name == "doctor" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Doctor {
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            json: matches.get_flag("json"),
            full: matches.get_flag("full"),
            refused,
        };
    }

    // ⛔ **`ts` carries its behaviour inputs** (E39): every flag value the
    // dispatch needs, read here where `clap` owns them. `--ts-mode` was
    // validated above, so absence here means `auto` — the default, not a
    // guess. Only rows `TS_FLAGS` declares are read.
    if verb.name == "ts" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Ts {
            destination: get("destination"),
            args: matches
                .get_many::<String>("args")
                .map(|v| v.cloned().collect())
                .unwrap_or_default(),
            w_target: get("stdio-forward"),
            mode: get("ts-mode").unwrap_or_else(|| "auto".to_string()),
            proxy: get("ts-proxy"),
            auth_key_file: get("ts-auth-key-file"),
            state: get("ts-state"),
            ephemeral: matches.get_flag("ts-ephemeral"),
            relay: get("ts-relay"),
            wait_allowlist: get("ts-wait-allowlist"),
            refused,
            timeout: get("timeout"),
            jsonl: matches.get_flag("jsonl"),
        };
    }

    // ⛔ E33's carried values: only rows the verb's table declares are read,
    // so `matches.get_flag` never panics on a verb that lacks the row and no
    // verb invents a flag the flag-table gate has not seen in the spec.
    let has_timeout = verb.flags.iter().any(|r| r.long == "timeout");
    let timeout = has_timeout
        .then(|| matches.get_one::<String>("timeout").cloned())
        .flatten();
    let jsonl = verb.flags.iter().any(|r| r.long == "jsonl") && matches.get_flag("jsonl");

    if verb.name == "ssh" {
        if let Some(refusal) = crate::ssh::args::repeated(&matches) {
            return Parsed::Usage(refusal);
        }
    }
    let ssh = (verb.name == "ssh").then(|| Box::new(crate::ssh::args::SshArgs::from_matches(&matches)));
    let keygen = (verb.name == "keygen").then(|| Box::new(crate::keygen::KeygenArgs::from_matches(&matches)));
    Parsed::Command { verb: verb.name, refused, tag, timeout, jsonl, ssh, keygen }
}

/// Whether an argument id was actually supplied, under either spelling.
///
/// ⛔ A boolean flag that was not given is still present in `ArgMatches` with
/// the value `false`, so "contains the id" is not enough — the value has to be
/// read, or the flag has to be true.
fn was_given(m: &ArgMatches, id: &str) -> bool {
    if let Ok(Some(v)) = m.try_get_one::<bool>(id) {
        return *v;
    }
    if let Ok(Some(_)) = m.try_get_one::<String>(id) {
        return true;
    }
    if let Ok(Some(v)) = m.try_get_one::<u8>(id) {
        return *v > 0;
    }
    m.try_contains_id(id).unwrap_or(false)
}