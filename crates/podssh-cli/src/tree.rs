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
fn add_flag(cmd: Command, row: &'static FlagRow) -> Command {
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
        Some(a) if appended(row.long) => arg.value_name(a).num_args(1).action(ArgAction::Append),
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
        cmd = add_flag(cmd, row);
    }
    // Positionals. `ssh` is `[user@]host [command...]`; `cp`/`mv` are
    // `SRC... DST`.
    cmd = match verb.name {
        // As OpenSSH: options may follow the destination, and the first word
        // after it starts the command, which takes everything after it
        // (`podssh ssh host ls -la` runs `ls -la`). Repeating a flag is
        // allowed; the last value wins, as in OpenSSH's own parser.
        "ssh" => cmd
            .args_override_self(true)
            .arg(Arg::new("destination").help("[user@]host"))
            .arg(
                Arg::new("remote-command")
                    .num_args(1..)
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true)
                    .help("command to run on the remote host"),
            ),
        "cp" | "mv" => cmd.arg(Arg::new("paths").num_args(2..).help("SRC... DST")),
        "chat" => cmd
            .arg(Arg::new("channel").help("channel to join"))
            .arg(Arg::new("message").num_args(0..).help("message to send")),
        "man" => cmd.arg(Arg::new("section").help("section to render, or none")),
        "relay" => cmd
            .arg(Arg::new("subcommand").help("status, info, spec, trace, pair, revoke"))
            .arg(Arg::new("args").num_args(0..).help("arguments for the subcommand")),
        "node" | "operator" => cmd.arg(Arg::new("name").help("node name")),
        "proxy" => cmd
            .arg(Arg::new("target").help("destination"))
            .arg(Arg::new("port").help("port")),
        "status" | "doctor" | "keygen" => cmd,
        // ⛔ `ts` takes all three 4b forms already in 4a so the parse is stable
        // while behaviour lands: bare (status), `[user@]host` (E01 session),
        // `-W` (byte pipe). Every form refuses naming E39 until then.
        "ts" => cmd
            .arg(Arg::new("destination").help("[user@]host"))
            .arg(
                Arg::new("args")
                    .num_args(0..)
                    .last(true)
                    .help("command to run on the remote host"),
            ),
        _ => cmd.arg(Arg::new("args").num_args(0..)),
    };
    for alias in verb.aliases {
        cmd = cmd.alias(*alias);
    }
    cmd
}

/// ⛔ **What the parse produced.** ⛔ Every variant here is a decision that had
/// to be made deliberately, and each names the rule that made it.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// `podssh --help`, or `podssh <verb> --help`. The payload is the section
    /// name, empty for the top level.
    Help(&'static str),
    /// `podssh --version`.
    Version,
    /// A verb was selected. ⛔ `refused` non-empty means the user asked for
    /// something this release does not do, and it is a refusal.
    Command {
        verb: &'static str,
        /// `(flag as written, what to use instead, why)`. ⛔ Owned because
        /// `FlagRow::usage_form` builds a `String`: the spelling carries the
        /// metavariable, and the table is `&'static` data that must not be
        /// copied per parse. ⛔ The third element is the row's own reason, so
        /// `-R` is refused *"remote forwarding is not in the first release"*
        /// rather than with `-L`'s listener sentence, which contradicted the
        /// `-W` this message recommends beside it.
        refused: Vec<(String, &'static str, &'static str)>,
        /// `-P TAG` on `ssh`: accepted, ignored, and it says so.
        tag: Option<String>,
        /// `--timeout DURATION`, verbatim. ⛔ `None` when the flag was absent
        /// **and** when the verb has no `--timeout` row — E33's gate enforces
        /// only where the tree could have supplied the flag, so `ssh` (no row;
        /// adding one needs a spec row first) carries nothing and is
        /// unaffected by the gate.
        timeout: Option<String>,
        /// `--jsonl`. Verbs without the row never set it; `proxy` never
        /// carries it because `proxy --jsonl` is refused at parse (below).
        jsonl: bool,
        /// `ssh`'s whole command line; `None` for every other verb.
        ssh: Option<Box<crate::ssh::args::SshArgs>>,
        /// `keygen`'s; `None` for every other verb.
        keygen: Option<Box<crate::keygen::KeygenArgs>>,
    },
    /// A usage error. ⛔ The message never contains a usage block.
    Usage(String),
    /// `podssh` with no subcommand at all.
    NoArguments(String),
    /// `podssh <token>` where `<token>` is not a verb.
    UnknownVerb(String),
    /// ⛔ **`podssh man`, and it is its own variant because it is the one verb
    /// with behaviour in this release** (E32). ⛔ It carries the two facts the
    /// tree must hand the renderer — which section, and whether the user asked
    /// for `--no-pager` — and ⛔ `refused` so that a `Refused` row added to
    /// `MAN_FLAGS` later refuses instead of being silently dropped, which is
    /// the security bug `06-cli.md`:84-85 names.
    Man {
        /// The section named on the command line, or `None` for the whole page.
        section: Option<String>,
        /// `--no-pager`: write to stdout and exit rather than paging.
        no_pager: bool,
        refused: Vec<(String, &'static str, &'static str)>,
    },
    /// `podssh proxy`: the positionals and options the byte pipe needs.
    Proxy {
        /// `HOST`, or `HOST:PORT` when no port follows.
        target: Option<String>,
        port: Option<String>,
        /// `--relay-host`.
        relay_host: Option<String>,
        /// `--relay-addr`.
        relay_addr: Option<String>,
        /// `--ca-file`.
        ca_file: Option<String>,
        refused: Vec<(String, &'static str, &'static str)>,
    },
    /// `podssh doctor`: the relay settings to check, as `proxy` takes them.
    Doctor {
        relay_host: Option<String>,
        relay_addr: Option<String>,
        ca_file: Option<String>,
        refused: Vec<(String, &'static str, &'static str)>,
    },
    /// ⛔ **`podssh ts`, and it is its own variant because it carries behaviour
    /// inputs no other verb has** (E39). Like `Man`, the refusal list rides
    /// along so a `Refused` row added to `TS_FLAGS` later refuses instead of
    /// being silently dropped. `mode` is the validated closed value (`auto`
    /// when the flag was absent — absence means auto, never a guess).
    Ts {
        /// `[user@]host` positional, or `None` for the bare status form.
        destination: Option<String>,
        /// Trailing command words for the host form.
        args: Vec<String>,
        /// `-W` / `--stdio-forward` `HOST:PORT` for the byte-pipe form.
        w_target: Option<String>,
        /// Validated `--ts-mode`: `auto` `tun` `socks` `tcp` `relay`.
        mode: String,
        /// `--ts-proxy` URL, verbatim.
        proxy: Option<String>,
        /// `--ts-auth-key-file` path, verbatim.
        auth_key_file: Option<String>,
        /// `--ts-state` path, verbatim.
        state: Option<String>,
        /// `--ts-ephemeral`.
        ephemeral: bool,
        /// `--ts-relay` host override.
        relay: Option<String>,
        /// `--ts-wait-allowlist` duration, verbatim.
        wait_allowlist: Option<String>,
        refused: Vec<(String, &'static str, &'static str)>,
        /// `--timeout DURATION`, verbatim.
        timeout: Option<String>,
        /// `--jsonl`.
        jsonl: bool,
    },
}

impl Parsed {
    /// Whether this outcome writes only to stderr. ⛔ E31's plant 6 is a
    /// `println!` in the dispatch, and the assertion is that no byte reaches
    /// stdout on any of these paths.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Parsed::Usage(_) | Parsed::NoArguments(_) | Parsed::UnknownVerb(_)
        )
    }

    /// ⛔ Whether this outcome requires a refusal rather than dispatch. ⛔ A
    /// `Command` carrying a `Refused` flag is a refusal too — an unimplemented
    /// flag is never a stub that exits 0 (`06-cli.md`:244-245).
    pub fn needs_refusal(&self) -> bool {
        match self {
            Parsed::Command { refused, .. } => !refused.is_empty(),
            Parsed::Man { refused, .. } => !refused.is_empty(),
            Parsed::Proxy { refused, .. } => !refused.is_empty(),
            Parsed::Doctor { refused, .. } => !refused.is_empty(),
            Parsed::Ts { refused, .. } => !refused.is_empty(),
            other => other.is_error(),
        }
    }
}

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
    // `podssh --help` never needs a verb.
    match first.as_str() {
        "-h" | "--help" => return Parsed::Help(""),
        "-V" | "--version" => return Parsed::Version,
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

    // ⛔ **`man` is the one verb with behaviour in this release, so it gets its
    // own variant** (E32). ⛔ The refusal list is carried over rather than
    // dropped: `MAN_FLAGS` has no `Refused` row today, and a flag that refuses
    // must refuse rather than be a field nothing reads — which is the sibling's
    // `--json` failure the entry records in `src/main.c:283-287`.
    if verb.name == "man" {
        return Parsed::Man {
            section: matches.get_one::<String>("section").cloned(),
            no_pager: matches.get_flag("no-pager"),
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

    if verb.name == "doctor" {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        return Parsed::Doctor {
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
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