//! What the parse of a command line produced: [`Parsed`]. The parser is in
//! [`crate::tree`], which re-exports this type; it is a module of its own so
//! that each file stays short.

/// **What the parse produced.** Every variant here is a decision that had
/// to be made deliberately, and each names the rule that made it.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// `podssh --help`, or `podssh <verb> --help`. The payload is the section
    /// name, empty for the top level.
    Help(&'static str),
    /// `podssh --version`.
    Version,
    /// A verb was selected. `refused` non-empty means the user asked for
    /// something this release does not do, and it is a refusal.
    Command {
        verb: &'static str,
        /// `(flag as written, what to use instead, why)`. Owned because
        /// `FlagRow::usage_form` builds a `String`: the spelling carries the
        /// metavariable, and the table is `&'static` data that must not be
        /// copied per parse. The third element is the row's own reason, so
        /// `-R` is refused with "remote forwarding is not implemented yet",
        /// not with `-L`'s listener sentence.
        refused: Vec<(String, &'static str, &'static str)>,
        /// `-P TAG` on `ssh`: accepted, ignored, and it says so.
        tag: Option<String>,
        /// `--timeout DURATION`, verbatim. `None` when the flag was absent
        /// **and** when the verb has no `--timeout` row — the `--timeout` gate enforces
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
    /// A usage error. The message never contains a usage block.
    Usage(String),
    /// `podssh` with no subcommand at all.
    NoArguments(String),
    /// `podssh <token>` where `<token>` is not a verb.
    UnknownVerb(String),
    /// `podssh man`: which section, how to write it, and the refusals, so
    /// that a `Refused` row added to `MAN_FLAGS` later refuses instead of
    /// being dropped.
    Man {
        /// The section named on the command line, or `None` for the whole manual.
        section: Option<String>,
        /// `--no-pager`: write to stdout, never through a pager.
        no_pager: bool,
        /// `--roff`: the man(7) page instead of text.
        roff: bool,
        /// `--json`: the tables as JSON.
        json: bool,
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
    /// `podssh status`: the relay settings in effect, and the destination
    /// whose host key it looks up.
    Status {
        relay_host: Option<String>,
        relay_addr: Option<String>,
        destination: Option<String>,
        refused: Vec<(String, &'static str, &'static str)>,
    },
    /// `podssh node NAME TARGET` (T-083).
    Node(Box<crate::node::NodeArgs>),
    /// `podssh operator NAME` (T-084).
    Operator(Box<crate::operator::OperatorArgs>),
    /// `podssh relay SUBCOMMAND NAME` (T-083).
    Relay(Box<crate::relay_cmd::RelayArgs>),
    /// `podssh doctor`: the relay settings to check, as `proxy` takes them.
    Doctor {
        relay_host: Option<String>,
        relay_addr: Option<String>,
        ca_file: Option<String>,
        /// `--json`: one JSON object at the end, in place of the text.
        json: bool,
        /// `--full`: the login check too.
        full: bool,
        refused: Vec<(String, &'static str, &'static str)>,
    },
    /// **`podssh ts`, and it is its own variant because it carries behaviour
    /// inputs no other verb has** (Tailscale). Like `Man`, the refusal list rides
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
    /// Whether this outcome writes only to stderr. Plant 6 (`tests/binary_streams.rs`) is a
    /// `println!` in the dispatch, and the assertion is that no byte reaches
    /// stdout on any of these paths.
    pub fn is_error(&self) -> bool {
        matches!(self, Parsed::Usage(_) | Parsed::NoArguments(_) | Parsed::UnknownVerb(_))
    }

    /// Whether this outcome requires a refusal rather than dispatch. A
    /// `Command` carrying a `Refused` flag is a refusal too — an unimplemented
    /// flag is never a stub that exits 0 (`docs/cli.md`, "Exit codes").
    pub fn needs_refusal(&self) -> bool {
        match self {
            Parsed::Command { refused, .. } => !refused.is_empty(),
            Parsed::Man { refused, .. } => !refused.is_empty(),
            Parsed::Proxy { refused, .. } => !refused.is_empty(),
            Parsed::Doctor { refused, .. } => !refused.is_empty(),
            Parsed::Status { refused, .. } => !refused.is_empty(),
            Parsed::Node(args) => !args.refused.is_empty(),
            Parsed::Operator(args) => !args.refused.is_empty(),
            Parsed::Relay(args) => !args.refused.is_empty(),
            Parsed::Ts { refused, .. } => !refused.is_empty(),
            other => other.is_error(),
        }
    }
}
