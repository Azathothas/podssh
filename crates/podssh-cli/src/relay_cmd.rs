//! `podssh relay` (T-083): the pairs of the reverse road, by a label that the
//! user chooses. `pair NAME` makes a pair on the relay's control host and
//! keeps it under NAME; `revoke NAME` stops it and forgets it; `status NAME`
//! asks whether its node is online. stdout carries the answer, one line, with
//! the label and never a token. `spec` checks the relay's document against
//! podssh's facts (`relay_spec.rs`, T-060). `status` with no NAME, `info` and
//! `trace` ask the relay about itself (`relay_diag.rs`, T-058). `status
//! --pair-file FILE` asks for the pair of an operator's file, on a host that
//! stores none, and `--json` gives a pair's state as one object (T-591).
//! `pair --renew NAME` renews the stored pair at podssh's relay role
//! (`relay_renew.rs`, T-592). `pair NAME --code` gives the operator's part
//! by a short code, which `join NAME` takes on the operator's host
//! (`relay_code.rs`, T-086). `halt NAME` and `resume NAME` keep the stored
//! pair's operators out at podssh's relay role, and let them in again
//! (`relay_halt.rs`, T-647).

use std::io::Write;

use podssh_relay::pair::{self, Pair, PairError};
use podssh_relay::relay::{self, Relay};
use podssh_ws::dial::ProxyChoice;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_settings::Refusal;

/// What `podssh relay` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    /// The control host of a new pair; one host.
    pub relay_host: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// `pair`: a new file for the operator's part of the pair.
    pub operator_file: Option<String>,
    /// `pair --renew`: the stored pair renewed at its relay, not a new one
    /// (T-592).
    pub renew: bool,
    /// `pair --once`: a connect token that takes one upgrade alone (T-226).
    pub once: bool,
    /// `halt --reason`: the words that each operator hears (T-647).
    pub reason: Option<String>,
    /// `pair --code`: the operator's part given by a short code (T-086).
    pub code: bool,
    /// `pair --code` and `join`: the mailboxes where the two ends meet.
    pub pair_mailbox: Option<String>,
    /// `pair --code`: the node's allowlist, which takes the operator's key.
    pub allow: Option<String>,
    /// `join`: this operator's key file.
    pub client_key: Option<String>,
    /// `status`: the pair, or its operator's part, in a file, in place of the
    /// store (T-591).
    pub pair_file: Option<String>,
    /// `spec`: a copy of the relay's document to check, read instead of the
    /// live one.
    pub document: Option<String>,
    /// `status` with no NAME, `info`, `trace` and `rank`: one JSON object.
    pub json: bool,
    /// `rank` (T-606): the rounds of probes of each host, the pings of each
    /// probe, the target of its sessions, the rank kept read back, or
    /// forgotten.
    pub rounds: Option<String>,
    pub count: Option<String>,
    pub target: Option<String>,
    pub cached: bool,
    pub forget: bool,
    /// `serve`: the relay as a role of podssh (T-169).
    pub serve: crate::relay_serve::ServeArgs,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl RelayArgs {
    /// The arguments of `podssh relay` from the parse of its command line.
    pub(crate) fn from_matches(
        matches: &clap::ArgMatches,
        refused: Vec<(String, &'static str, &'static str)>,
    ) -> RelayArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        RelayArgs {
            subcommand: get("subcommand"),
            args: matches.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
            relay_host: get("relay-host"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            operator_file: get("operator-file"),
            renew: matches.get_flag("renew"),
            once: matches.get_flag("once"),
            reason: get("reason"),
            code: matches.get_flag("code"),
            pair_mailbox: get("pair-mailbox"),
            allow: get("allow"),
            client_key: get("client-key"),
            pair_file: get("pair-file"),
            document: get("document"),
            json: matches.get_flag("json"),
            rounds: get("rounds"),
            count: get("count"),
            target: get("target"),
            cached: matches.get_flag("cached"),
            forget: matches.get_flag("forget"),
            serve: crate::relay_serve::ServeArgs::from_matches(matches),
            refused,
        }
    }

    /// Whether a flag of `rank` alone was given.
    fn rank_flags(&self) -> bool {
        self.rounds.is_some() || self.count.is_some() || self.target.is_some() || self.cached || self.forget
    }
}

/// Run the verb; returns the process exit code.
pub fn run_relay(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let sub = args.subcommand.as_deref();
    let target = matches!(sub, Some("info" | "trace"));
    if let Some(extra) = args.args.get(if target { 2 } else { 1 }) {
        let takes = if target { "info and trace take HOST PORT" } else { "a subcommand takes one NAME" };
        let _ = writeln!(err, "podssh relay: {extra:?} is one word too many: {takes}");
        return EXIT_USAGE;
    }
    if args.json && !(target || matches!(sub, Some("status" | "rank"))) {
        let _ = writeln!(err, "podssh relay: --json goes with status, info, trace and rank");
        return EXIT_USAGE;
    }
    if args.rank_flags() && sub != Some("rank") {
        let _ = writeln!(
            err,
            "podssh relay: --rounds, --count, --target, --cached and --forget go with `podssh relay rank` only"
        );
        return EXIT_USAGE;
    }
    if args.operator_file.is_some() && sub != Some("pair") {
        let _ = writeln!(err, "podssh relay: --operator-file goes with `podssh relay pair NAME` only");
        return EXIT_USAGE;
    }
    if args.renew && sub != Some("pair") {
        let _ = writeln!(err, "podssh relay: --renew goes with `podssh relay pair --renew NAME` only");
        return EXIT_USAGE;
    }
    if args.once && (sub != Some("pair") || args.renew) {
        let _ = writeln!(err, "podssh relay: --once goes with `podssh relay pair NAME` only, a new pair");
        return EXIT_USAGE;
    }
    if args.reason.is_some() && sub != Some("halt") {
        let _ = writeln!(err, "podssh relay: --reason goes with `podssh relay halt NAME` only");
        return EXIT_USAGE;
    }
    if let Some(refused) = crate::relay_code::misplaced(args) {
        let _ = writeln!(err, "podssh relay: {refused}");
        return EXIT_USAGE;
    }
    if args.pair_file.is_some() && sub != Some("status") {
        let _ = writeln!(err, "podssh relay: --pair-file goes with `podssh relay status [NAME]` only");
        return EXIT_USAGE;
    }
    if args.document.is_some() && sub != Some("spec") {
        let _ = writeln!(err, "podssh relay: --document goes with `podssh relay spec` only");
        return EXIT_USAGE;
    }
    if args.serve.any() && sub != Some("serve") {
        let _ = writeln!(err, "podssh relay: --listen, --cert, --key, --acme, --acme-directory, --port-file, --mint, --allow-private, --routes, --keepalive, --pairs, --cleartext, --deployment, --list-key, --resume-deadline, --resume-budget, --resume-host, --http2 and --quic go with `podssh relay serve` only");
        return EXIT_USAGE;
    }
    let name = args.args.first().map(String::as_str);
    let done = match (sub, name) {
        // The stored pair, renewed at podssh's relay role (T-592).
        (Some("pair"), Some(label)) if args.renew => crate::relay_renew::run(args, label, out, err),
        // The operator's part by a short code, and its other end (T-086).
        (Some("pair"), Some(label)) if args.code => crate::relay_code::give(args, label, out, err),
        (Some("join"), Some(label)) => crate::relay_code::join(args, label, out, err),
        (Some("pair"), Some(label)) => make(args, label, out, err).map(|_| ()),
        (Some("revoke"), Some(label)) => revoke(args, label, out, err),
        // The owner keeps the operators out, and lets them in again (T-647).
        (Some("halt"), Some(label)) => crate::relay_halt::halt(args, label, out, err),
        (Some("resume"), Some(label)) => crate::relay_halt::resume(args, label, out, err),
        (Some("status"), Some(label)) => crate::relay_status::pair(args, Some(label), out),
        (Some(sub @ ("pair" | "revoke" | "join" | "halt" | "resume")), None) => {
            Err(Refusal::usage(format!("missing NAME: `podssh relay {sub} NAME`, where NAME is the label of a pair")))
        }
        // The pair of an operator's file, with no label in the store.
        (Some("status"), None) if args.pair_file.is_some() => crate::relay_status::pair(args, None, out),
        (Some("status"), None) => return crate::relay_diag::status(args, out, err),
        (Some("spec"), None) => return crate::relay_spec::run(args, out, err),
        (Some("serve"), None) => return crate::relay_serve::run(args, err),
        (Some("serve"), Some(word)) => {
            Err(Refusal::usage(format!("serve takes no NAME, and {word:?} would be dropped: `podssh relay serve --listen ADDR:PORT ...`")))
        }
        (Some("spec"), Some(word)) => {
            Err(Refusal::usage(format!("spec takes no NAME, and {word:?} would be dropped: `podssh relay spec`")))
        }
        (Some("rank"), None) => return crate::relay_rank::run(args, out, err),
        (Some("rank"), Some(word)) => Err(Refusal::usage(format!(
            "rank takes no NAME, and {word:?} would be dropped: `podssh relay rank`, or --relay-host HOSTS for other hosts"
        ))),
        (Some("info"), _) => return crate::relay_diag::info(args, out, err),
        (Some("trace"), _) => return crate::relay_diag::trace(args, out, err),
        (Some(other), _) => Err(Refusal::usage(format!(
            "there is no subcommand {other:?}; the subcommands are pair, join, revoke, halt, resume, status, info, \
             trace, rank, spec and serve"
        ))),
        (None, _) => Err(Refusal::usage(
            "missing SUBCOMMAND: pair NAME, join NAME, revoke NAME, halt NAME, resume NAME, status [NAME], info \
             [HOST PORT], trace HOST PORT, rank, spec or serve",
        )),
    };
    match done {
        Ok(()) => 0,
        Err(refusal) => refusal.report("relay", err),
    }
}

/// A current-thread runtime for one call.
pub(crate) fn block_on<T>(work: impl std::future::Future<Output = T>) -> Result<T, Refusal> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| Refusal {
        message: format!("could not start the async runtime: {e}"),
        code: Fault::SessionFault.code(),
    })?;
    let done = runtime.block_on(work);
    runtime.shutdown_background();
    Ok(done)
}

/// `pair NAME`: a new pair, stored under NAME; its operator's part in a new
/// file when one is named. The pair, for `--code` to give (T-086).
pub(crate) fn make(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<Pair, Refusal> {
    pairs::check_label(label)?;
    if let Some(file) = &args.operator_file {
        if std::path::Path::new(file).exists() {
            return Err(Refusal::usage(format!("--operator-file {file} exists; podssh never replaces it")));
        }
    }
    // The next pair in the last 24 h of a pair's life, which its node takes
    // at the expiry (T-395); before them, a second pair would leave the first
    // with no holder for days.
    let renew_from = old_enough();
    // The pair that the next one replaces while it lives, kept again if the
    // next one cannot be.
    let mut living = None;
    match pair::load(label) {
        Ok(Some(old)) if old.expires_ms > renew_from => {
            return Err(Refusal::config(format!(
                "a pair is stored under {label:?} until {}; stop it first with `podssh relay revoke {label}`, or \
                 make the next one in its last 24 hours",
                pairs::utc(old.expires_ms)
            )))
        }
        Ok(Some(old)) if old.expires_ms > pairs::now_ms() => {
            let _ = writeln!(
                err,
                "podssh relay: the pair under {label:?} expires at {}: the next one takes its place in the store, and \
                 its node takes it at that expiry; the old one cannot be stopped now, and ends then",
                pairs::utc(old.expires_ms)
            );
            living = Some(old);
        }
        Ok(Some(_)) => {
            let _ = writeln!(err, "podssh relay: the pair under {label:?} had expired; it is replaced");
        }
        Ok(None) => {}
        Err(e) => return Err(pairs::refusal(&e)),
    }
    crate::pins::apply(args.relay_addr.as_deref())?;
    let relays = crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok())?;
    let control = relays.primary().clone();
    pairs::online()?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&control, &trust, &proxy);
    let (made, once) = block_on(pair::once::create_with(&ctx, args.once))?.map_err(|e| pairs::refusal(&e))?;
    // A relay that does not offer --once made a pair whose token takes each
    // upgrade (T-226): it is stopped, as it is not the one asked for.
    if args.once && !once {
        let _ = block_on(pair::stop(&ctx, &made));
        return Err(Refusal {
            message: format!(
                "the relay {} makes no connect token of one upgrade (podssh relay serve does); the pair that it made \
                 was stopped",
                control.host
            ),
            code: Fault::RelayUnreachable.code(),
        });
    }
    if let Err(why) = keep(label, &made, args.operator_file.as_deref()) {
        // A pair that nobody holds would keep its name for 72 hours.
        let _ = block_on(pair::stop(&ctx, &made));
        let _ = match &living {
            Some(old) => pair::store(label, old).map(|_| ()),
            None => pair::remove(label),
        };
        return Err(Refusal::config(format!("{why}; the new pair was stopped")));
    }
    if let Some(file) = &args.operator_file {
        let _ = writeln!(err, "podssh relay: the operator's part is in {file}, which only its owner can read");
    }
    if once {
        let _ = writeln!(
            err,
            "podssh relay: its connect token takes one upgrade: one operator's session, with no resume; a token that \
             leaks after it is worth nothing"
        );
    }
    // One line on stdout, as scripts read it; the way past the expiry on
    // stderr (T-591).
    let _ = writeln!(out, "{label}: expires {}", pairs::utc(made.expires_ms));
    let _ = writeln!(
        err,
        "podssh relay: in its last 24 h, podssh relay pair {label} --operator-file NEW makes the next pair, which \
         the node takes at the expiry; NEW goes to each operator"
    );
    Ok(made)
}

/// The expiry after which a stored pair may have its next one: the last
/// part of its life, in which its node says the expiry
/// (`node_expiry::RENEW_WINDOW`).
fn old_enough() -> i64 {
    let window = i64::try_from(crate::node_expiry::RENEW_WINDOW.as_millis()).unwrap_or(i64::MAX);
    pairs::now_ms().saturating_add(window)
}

/// Store `pair` under `label`, then write its operator's part.
fn keep(label: &str, pair: &Pair, operator_file: Option<&str>) -> Result<(), String> {
    pair::store(label, pair).map_err(|e| e.to_string())?;
    if let Some(file) = operator_file {
        pair::write_operator_file(std::path::Path::new(file), pair)
            .map_err(|e| format!("--operator-file {file}: {e}"))?;
    }
    Ok(())
}

/// `revoke NAME`: stop the pair, and forget it. A relay that refuses the stop
/// token has stopped the pair already, or forgotten it: the copy goes too.
fn revoke(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    let stored = match pair::load(label) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Err(Refusal::config(format!("no pair is stored under {label:?}"))),
        Err(e) => return Err(pairs::refusal(&e)),
    };
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    let control: Relay = stored.relay.clone();
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&control, &trust, &proxy);
    match block_on(pair::revoke(&ctx, label))? {
        Ok(answer) if answer.stopped => {
            let _ = writeln!(out, "{label}: stopped; its node was online");
        }
        Ok(_) => {
            let _ = writeln!(out, "{label}: stopped");
        }
        Err(PairError::Forbidden) => {
            let _ = writeln!(err, "podssh relay: the relay refused the stop token (403): the pair had ended already");
            let _ = writeln!(out, "{label}: stopped");
        }
        Err(e @ PairError::Connect(_)) => {
            let mut refusal = pairs::refusal(&e);
            refusal.message.push_str(&format!(
                "; the copy under {label:?} is kept: its stop token is the one way to stop the pair before it expires"
            ));
            return Err(refusal);
        }
        Err(e) => return Err(pairs::refusal(&e)),
    }
    Ok(())
}
