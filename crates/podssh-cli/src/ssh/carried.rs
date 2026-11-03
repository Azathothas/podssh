//! `podssh ssh --carrier ADDR node://NAME` (T-595), and `cp`, `scp` and
//! `sftp` to `node://NAME` on one: the node at the other end of a stream
//! that exists already, with no relay and no pair. This process serves the
//! relay role's side of the node's socket (`crate::carrier`), and each
//! session is a leg of its own to it; a command's connections share the one
//! stream, which ends with the command. The carrier is the node's one road,
//! so no other road races it, and NAME is a label alone, under which the
//! node's key is pinned. The session runs in the layer and the end-to-end
//! channel as on the pair's road ([`super::node::run_on`]).

use std::sync::Arc;

use podssh_relay::reverse::operator;
use podssh_ssh::{Log, Options, EXIT_FAILURE};
use tokio::sync::oneshot;

use super::args::SshArgs;
use super::node::{Leg, SCHEME};
use super::resolve::{Resolved, Transport};
use super::transport::{NotReached, Reached};
use crate::exitmap::sysexits;
use crate::layered::{carry_through, Line};
use crate::relay_settings::Refusal;

/// Each direction of the pipe between the SSH client and the leg.
const PIPE: usize = 256 * 1024;

/// Why a client of a node takes no `--carrier stdio`.
const OWN_STDIO: &str = "stdin and stdout are this command's own here, its session's or its lines'";

/// `--carrier` of a `node://NAME` destination: the flags of a relay, of a
/// pair and of each other road have nothing to apply to (64), and stdio is
/// this command's own. Checked as the destination resolves to a node, so
/// that its words come before those of a node's other roads.
pub(super) fn flags(args: &SshArgs) -> Result<(), String> {
    let Some(text) = args.carrier.as_deref() else { return Ok(()) };
    let refused = [
        (args.pair_file.is_some(), "--pair-file"),
        (args.relay_host.is_some(), "--relay-host"),
        (args.relay_failover.is_some(), "--relay-failover"),
        (args.relay_addr.is_some(), "--relay-addr"),
        (args.ca_file.is_some(), "--ca-file"),
        (args.direct, "--direct"),
        (args.iroh_ticket.is_some(), "--iroh-ticket"),
        (args.derp_ticket.is_some(), "--derp-ticket"),
        (args.derp_server.is_some(), "--derp-server"),
        (args.opentunnel_name.is_some(), "--opentunnel-name"),
        (args.forwarder.is_some(), "--forwarder"),
        (args.shadowsocks.is_some(), "--shadowsocks"),
        (args.via.is_some(), "--via"),
        (args.vless.is_some(), "--vless"),
        (args.wstunnel.is_some(), "--wstunnel"),
        (args.exit.is_some(), "--exit"),
        (args.upgrade, "--upgrade"),
    ];
    if let Some((_, flag)) = refused.into_iter().find(|(given, _)| *given) {
        return Err(format!("{flag} does not go with --carrier: the node's one road is the stream of {text}"));
    }
    crate::carrier::for_a_client(text, OWN_STDIO).map(|_| ()).map_err(|refusal| refusal.message)
}

/// `--carrier` beside a destination that is no node, or beside `--exit`,
/// whose road is a node's too: the stream reaches a node alone (64).
pub(super) fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    let on_one = matches!(&resolved.transport, Transport::Node { carrier: Some(_), .. });
    if args.carrier.is_some() && !on_one {
        let why = if args.exit.is_some() {
            "--exit does not go with --carrier: an exit over a carrier is not built yet"
        } else {
            "--carrier is for a node://NAME destination: the node at the other end of the stream"
        };
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// SSH to the node at the other end of the carrier `text`, under the label
/// `label`: the channel, the stream, a first leg, then the session as on the
/// pair's road; at the end the node hears the Close, and the program of the
/// stream ends.
pub(super) async fn connect(label: &str, text: &str, ask: &crate::channel::Ask, opts: &Options, log: Arc<Log>) -> i32 {
    let shown = format!("{SCHEME}{label}");
    // The node's key, pinned under the label: a stream that another key
    // answers is seen.
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = match ask.operator(crate::channel::Expect::Pinned(label.to_string()), &say_line) {
        Ok(channel) => channel,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let client = match crate::carrier::shared(text) {
        Ok(client) => client,
        Err(refusal) => {
            log.error(&format!("{shown}: {}", refusal.message));
            podssh_ssh::outcome::failed("connect");
            return EXIT_FAILURE;
        }
    };
    log.verbose(&format!("connecting to {shown} over the carrier {text}"));
    let config = client.config();
    let (link_end, leg_end) = tokio::io::duplex(PIPE);
    let code = match operator::start(&config, leg_end).await {
        Ok(leg) => {
            let first = Leg { config: &config, link_end, leg, expires_ms: None };
            super::node::run_on(first, channel, opts, log.clone(), &shown, crate::carrier::said).await
        }
        Err(e) => {
            log.error(&format!("{shown}: {}", crate::carrier::refusal_of(&e).message));
            podssh_ssh::outcome::failed("connect");
            EXIT_FAILURE
        }
    };
    crate::carrier::end_shared().await;
    code
}

/// The stream to the node at the other end of the carrier `text`, for a
/// copy: a task carries it over a leg of the role, in the layer when the
/// node offers it, as [`super::node::reach`] carries one over the pair's
/// road. Each connection of the command is a leg of the one stream, which
/// ends with the command (`crate::ssh::transport::settled`).
pub async fn reach(label: &str, text: &str, ask: &crate::channel::Ask, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let shown = format!("{SCHEME}{label}");
    let refused =
        |refusal: Refusal| NotReached { lines: vec![format!("{shown}: {}", refusal.message)], code: refusal.code };
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = ask
        .operator(crate::channel::Expect::Pinned(label.to_string()), &say_line)
        .map_err(|why| refused(Refusal::config(why)))?;
    let client = crate::carrier::shared(text).map_err(refused)?;
    log.verbose(&format!("connecting to {shown} over the carrier {text}"));
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (started, has_started) = oneshot::channel();
    let (ended, done) = oneshot::channel();
    let (task_shown, task_log) = (shown.clone(), log.clone());
    tokio::spawn(async move {
        let config = client.config();
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let leg = match operator::start(&config, leg_end).await {
            Ok(leg) => {
                let _ = started.send(Ok(()));
                leg
            }
            Err(e) => {
                let _ = started.send(Err(crate::carrier::refusal_of(&e)));
                return;
            }
        };
        let say = |line: Line| match line {
            Line::Always(text) => task_log.info(&format!("{task_shown}: {text}")),
            Line::Verbose(text) => task_log.verbose(&format!("{task_shown}: {text}")),
        };
        let pin_say = {
            let (log, shown) = (task_log.clone(), task_shown.clone());
            move |line: String| log.info(&format!("{shown}: {line}"))
        };
        let carried = carry_through(&config, link, leg, theirs, None, &say, channel, pin_say).await;
        // A clean end says nothing: the copy closed its connection.
        if let Some((_, why)) = crate::carrier::judged(&carried) {
            task_log.error(&format!("{task_shown}: {why}"));
        }
        let _ = ended.send(());
    });
    match has_started.await {
        Ok(Ok(())) => Ok(Reached { stream: Box::new(ours), relay: None, direct_proxy: None, layer: Some(done) }),
        Ok(Err(refusal)) => Err(refused(refusal)),
        Err(_) => Err(NotReached {
            lines: vec![format!("{shown}: the leg's task ended before it started")],
            code: sysexits::EX_SOFTWARE,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(carrier: Option<&str>) -> SshArgs {
        SshArgs { destination: Some("node://box".into()), carrier: carrier.map(str::to_string), ..SshArgs::default() }
    }

    #[test]
    fn a_carrier_takes_no_flag_of_another_road_and_no_stdio() {
        assert!(flags(&args(None)).is_ok(), "no carrier, nothing to check");
        assert!(flags(&args(Some("exec:cat"))).is_ok());
        let base = || args(Some("exec:cat"));
        let given: [(&str, SshArgs); 6] = [
            ("--pair-file", SshArgs { pair_file: Some("x".into()), ..base() }),
            ("--relay-host", SshArgs { relay_host: Some("relay.example".into()), ..base() }),
            ("--direct", SshArgs { direct: true, ..base() }),
            ("--iroh-ticket", SshArgs { iroh_ticket: Some("t".into()), ..base() }),
            ("--derp-ticket", SshArgs { derp_ticket: Some("t".into()), ..base() }),
            ("--exit", SshArgs { exit: Some("gw".into()), ..base() }),
        ];
        for (flag, args) in given {
            let why = flags(&args).unwrap_err();
            assert!(why.starts_with(&format!("{flag} does not go with --carrier")), "{flag}: {why}");
        }
        for bad in ["stdio", "-", "tcp:127.0.0.1:22"] {
            let why = flags(&args(Some(bad))).unwrap_err();
            assert!(why.starts_with(&format!("--carrier {bad}")), "{bad}: {why}");
        }
    }
}
