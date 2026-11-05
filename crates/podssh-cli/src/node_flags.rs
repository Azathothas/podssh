//! The flags of `podssh node` that each road reads: the node's key and
//! allowlist, each by its two names (T-087, T-163), and the resume deadline
//! (T-306); the sessions readied ahead of the pair's road (T-650); and those
//! that the iroh road refuses. Apart from `node.rs` for the length of that
//! file.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

use podssh_relay::reverse::Settings;

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The node's key and allowlist, by their names of T-087 or of T-163.
pub(crate) struct KeyFlags {
    pub key: Option<String>,
    pub ephemeral: bool,
    pub allow: Option<PathBuf>,
}

/// The flags of the node's key and allowlist; each by one of its two names.
pub(crate) fn key_flags(args: &NodeArgs) -> Result<KeyFlags, Refusal> {
    let both = |a: &str, b: &str| Refusal::usage(format!("{a} and {b} are one flag by two names: give one"));
    if args.key.is_some() && args.iroh_key.is_some() {
        return Err(both("--key", "--iroh-key"));
    }
    if args.allow.is_some() && args.iroh_allow.is_some() {
        return Err(both("--allow", "--iroh-allow"));
    }
    Ok(KeyFlags {
        key: args.key.clone().or_else(|| args.iroh_key.clone()),
        ephemeral: args.ephemeral_key || args.iroh_ephemeral,
        allow: args.allow.as_ref().or(args.iroh_allow.as_ref()).map(PathBuf::from),
    })
}

/// The flags of the node's sessions, before anything connects: how long it
/// keeps a lost one, and how many its relay readies ahead.
pub(crate) fn sessions(args: &NodeArgs) -> Result<(), Refusal> {
    deadline(args)?;
    SPARES.store(spares(args)?, Ordering::SeqCst);
    Ok(())
}

/// The number of `--spares`, for the pair's road of this run.
static SPARES: AtomicU8 = AtomicU8::new(0);

/// `--spares N` (T-650): the sessions that the pair's relay role keeps
/// readied ahead for the node's operators, 0 to 16, none without it. Each
/// other road has no relay role to ask, or runs a pair's road of its own
/// beside it, so the flag is refused with them.
pub(crate) fn spares(args: &NodeArgs) -> Result<u8, Refusal> {
    let Some(text) = args.spares.as_deref() else { return Ok(0) };
    let piping = matches!(crate::piping_road::want(), Ok(crate::piping_road::Want::Asked(_)));
    let roads = [
        (args.iroh, "--iroh"),
        (args.derp, "--derp"),
        (args.opentunnel, "--opentunnel"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.carrier.is_some(), "--carrier"),
        (args.temporary.is_some(), "--temporary"),
        (piping, "PODSSH_PIPING"),
    ];
    if let Some((_, flag)) = roads.iter().find(|(on, _)| *on) {
        let why =
            format!("--spares is for the pair's road, whose relay readies sessions ahead: give it without {flag}");
        return Err(Refusal::usage(why));
    }
    let most = podssh_relay::reverse::spares::MOST;
    match text.trim().parse::<u8>() {
        Ok(n) if n <= most => Ok(n),
        _ => Err(Refusal::usage(format!("--spares {text:?}: a whole number from 0 to {most}"))),
    }
}

/// The settings of the pair's road: a lost socket taken again for as long as
/// the layer keeps a session (T-261), and the sessions of `--spares`, whose
/// line goes to `say` (T-650).
pub(crate) fn pair_settings(say: &crate::node_expiry::Say) -> Settings {
    let say = say.clone();
    podssh_relay::reverse::spares::tell(move |line: &str| say(line.to_string()));
    let rejoin = crate::layered::settings().resume_deadline;
    Settings { rejoin, spares: SPARES.load(Ordering::SeqCst), ..Settings::default() }
}

/// `--resume-deadline TIME` (T-306): how long the node keeps a session whose
/// link is lost, and names to its clients, on each road; 10 minutes with
/// none. A node with no layer, or the temporary node, keeps no session so.
pub(crate) fn deadline(args: &NodeArgs) -> Result<(), Refusal> {
    let Some(text) = args.resume_deadline.as_deref() else { return Ok(()) };
    if args.temporary.is_some() {
        return Err(Refusal::usage("--resume-deadline does not go with --temporary, which keeps the defaults"));
    }
    if args.plain {
        return Err(Refusal::usage("--resume-deadline is a time of the resumable layer, which --plain turns off"));
    }
    crate::layered::set_far_deadline(crate::layered::parse_deadline(text).map_err(Refusal::usage)?);
    Ok(())
}

/// The flags that the iroh road refuses: `--plain`, as it always runs the
/// layer; a UDP TARGET, the pair's road's alone (T-168), in a build with the
/// iroh road or without it; and `--opentunnel`, another road (T-531).
pub(crate) fn iroh_checks(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain && args.iroh {
        return Err(Refusal::usage("--plain is for the pair's road: the iroh road always runs the resumable layer"));
    }
    if args.iroh && args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:")) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the iroh road carries TCP only"));
    }
    if args.iroh && args.opentunnel {
        return Err(Refusal::usage("--iroh and --opentunnel are two roads: give one; run a second node for the other"));
    }
    Ok(())
}

/// The lines of the layer's budget of replay buffers (T-586), on the node's
/// stderr beside its others, which a detached node's log keeps: a refusal,
/// once a minute at most, and the budget past three quarters. The client
/// that is refused hears why; the node's own user must too.
pub(crate) fn tell_budget(args: &NodeArgs) {
    let label = args.name.clone().unwrap_or_default();
    podssh_relay::session::budget::tell(move |line: &str| podssh_ssh::err_line!("podssh node: {label}: {line}"));
}

/// The mode of a node with the layer, as its first line says it: with the
/// time for which it keeps a lost session.
pub(crate) fn layer_mode() -> String {
    let kept = podssh_relay::session::deadline::span(crate::layered::settings().resume_deadline);
    format!("with the resumable layer, which keeps a lost session {kept}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(spares: &str) -> NodeArgs {
        NodeArgs { name: Some("lab".into()), spares: Some(spares.into()), ..NodeArgs::default() }
    }

    /// T-650: a whole number from 0 to 16, none without the flag, and the
    /// pair's road alone.
    #[test]
    fn spares_are_a_number_to_sixteen_on_the_pairs_road_alone() {
        assert_eq!(spares(&NodeArgs::default()), Ok(0), "none without the flag");
        assert_eq!(spares(&asked("4")), Ok(4));
        assert_eq!(spares(&asked("16")), Ok(16));
        assert_eq!(spares(&asked("0")), Ok(0));
        for bad in ["17", "-1", "four", "", "4.5"] {
            match spares(&asked(bad)) {
                Err(refusal) => {
                    assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{bad}");
                    assert!(refusal.message.contains("from 0 to 16"), "{bad}: {}", refusal.message);
                }
                Ok(n) => panic!("{bad:?} took {n}"),
            }
        }
        let other_roads = [
            (NodeArgs { iroh: true, ..asked("2") }, "--iroh"),
            (NodeArgs { derp: true, ..asked("2") }, "--derp"),
            (NodeArgs { quick_tunnel: true, ..asked("2") }, "--quick-tunnel"),
            (NodeArgs { carrier: Some("stdio".into()), ..asked("2") }, "--carrier"),
        ];
        for (args, flag) in other_roads {
            match spares(&args) {
                Err(refusal) => assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message),
                Ok(n) => panic!("{flag} took {n}"),
            }
        }
    }
}
