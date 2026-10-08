//! `podssh relay` (T-083): the pairs of the reverse road, by a label that the
//! user chooses. `pair NAME` makes a pair on the relay's control host and
//! keeps it under NAME; `revoke NAME` stops it and forgets it; `status NAME`
//! asks whether its node is online. stdout carries the answer, one line, with
//! the label and never a token. `status` with no NAME, `info`, `spec` and
//! `trace` are T-058's, and refuse.

use std::io::Write;

use podssh_relay::pair::{self, Pair, PairError};
use podssh_relay::relay::{self, Relay};
use podssh_ws::dial::ProxyChoice;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
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
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_relay(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let sub = args.subcommand.as_deref();
    if let Some(extra) = args.args.get(1) {
        let _ = writeln!(err, "podssh relay: {extra:?} is one word too many: a subcommand takes one NAME");
        return EXIT_USAGE;
    }
    if args.operator_file.is_some() && sub != Some("pair") {
        let _ = writeln!(err, "podssh relay: --operator-file goes with `podssh relay pair NAME` only");
        return EXIT_USAGE;
    }
    let name = args.args.first().map(String::as_str);
    let done = match (sub, name) {
        (Some("pair"), Some(label)) => make(args, label, out, err),
        (Some("revoke"), Some(label)) => revoke(args, label, out, err),
        (Some("status"), Some(label)) => status(args, label, out),
        (Some(sub @ ("pair" | "revoke")), None) => Err(Refusal::usage(format!(
            "missing NAME: `podssh relay {sub} NAME`, where NAME is the label of a pair"
        ))),
        (Some("status"), None) => {
            let _ = writeln!(
                err,
                "podssh: 'relay status' with no NAME, the relay's own state, is not implemented yet; nothing was \
                 done. `podssh relay status NAME` gives the state of the pair under NAME."
            );
            return EXIT_NOT_IMPLEMENTED;
        }
        (Some(sub @ ("info" | "spec" | "trace")), _) => {
            let _ = writeln!(err, "{}", crate::refuse::not_implemented(&format!("relay {sub}")));
            return EXIT_NOT_IMPLEMENTED;
        }
        (Some(other), _) => Err(Refusal::usage(format!(
            "there is no subcommand {other:?}; the subcommands are pair, revoke and status"
        ))),
        (None, _) => Err(Refusal::usage("missing SUBCOMMAND: pair NAME, revoke NAME or status NAME")),
    };
    match done {
        Ok(()) => 0,
        Err(refusal) => refusal.report("relay", err),
    }
}

/// A current-thread runtime for one call.
fn block_on<T>(work: impl std::future::Future<Output = T>) -> Result<T, Refusal> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Refusal { message: format!("could not start the async runtime: {e}"), code: Fault::SessionFault.code() })?;
    let done = runtime.block_on(work);
    runtime.shutdown_background();
    Ok(done)
}

/// `pair NAME`: a new pair, stored under NAME; its operator's part in a new
/// file when one is named.
fn make(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    if let Some(file) = &args.operator_file {
        if std::path::Path::new(file).exists() {
            return Err(Refusal::usage(format!("--operator-file {file} exists; podssh never replaces it")));
        }
    }
    match pair::load(label) {
        Ok(Some(old)) if old.expires_ms > pairs::now_ms() => {
            return Err(Refusal::config(format!(
                "a pair is stored under {label:?} until {}; stop it first with `podssh relay revoke {label}`",
                pairs::utc(old.expires_ms)
            )))
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
    let made = block_on(pair::create(&ctx))?.map_err(|e| pairs::refusal(&e))?;
    if let Err(why) = keep(label, &made, args.operator_file.as_deref()) {
        // A pair that nobody holds would keep its name for 72 hours.
        let _ = block_on(pair::stop(&ctx, &made));
        let _ = pair::remove(label);
        return Err(Refusal::config(format!("{why}; the new pair was stopped")));
    }
    if let Some(file) = &args.operator_file {
        let _ = writeln!(err, "podssh relay: the operator's part is in {file}, which only its owner can read");
    }
    let _ = writeln!(out, "{label}: expires {}", pairs::utc(made.expires_ms));
    Ok(())
}

/// Store `pair` under `label`, then write its operator's part.
fn keep(label: &str, pair: &Pair, operator_file: Option<&str>) -> Result<(), String> {
    pair::store(label, pair).map_err(|e| e.to_string())?;
    if let Some(file) = operator_file {
        pair::write_operator_file(std::path::Path::new(file), pair).map_err(|e| format!("--operator-file {file}: {e}"))?;
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

/// `status NAME`: whether the pair's node is online, and its sessions.
fn status(args: &RelayArgs, label: &str, out: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    let stored = pairs::stored(label)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&stored.relay, &trust, &proxy);
    let presence = block_on(pair::status(&ctx, &stored))?.map_err(|e| pairs::refusal(&e))?;
    let until = pairs::utc(stored.expires_ms);
    let _ = match (presence.online, presence.sessions) {
        (true, 1) => writeln!(out, "{label}: online, 1 session; expires {until}"),
        (true, n) => writeln!(out, "{label}: online, {n} sessions; expires {until}"),
        (false, _) => writeln!(out, "{label}: offline; expires {until}"),
    };
    Ok(())
}
