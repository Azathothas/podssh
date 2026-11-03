//! `--exit NAME` of `podssh ssh` and the copies (T-431): the road to the
//! first hop starts at NAME, a node of the user's net that lends its egress
//! (`podssh node --exit`), in place of the relay. The transport is the
//! node's own (`Transport::Node`), so each of its roads carries it, raced
//! as for `node://NAME`, and the session resumes on any of them; the
//! channel's word names the first hop, `HOST:PORT`, in place of a route, and
//! the SSH client checks that host's key under its own name, as on the
//! relay. Here so that the resolver stays one file.

use podssh_ws::Trust;

use super::args::SshArgs;
use super::resolve::{Env, Resolved, Transport};
use crate::relay_settings::Refusal;

/// What a destination of a node's own road says, refused with `--exit`.
const ITS_OWN: &str = "--exit NAME starts the road to a host at the node NAME, in place of the relay: it goes \
                       with no node://, iroh:, derp:, cf://, iap:// or eice:// destination, no cf:// hop of -J, \
                       no --direct and no road of another server";

/// The road of a run that resolved to the relay: the exit's, when
/// `--exit` names one. Its word comes once the first hop is known
/// ([`fill`]).
pub(super) fn or_exit(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let Some(name) = args.exit.as_deref() else { return Ok(relay) };
    if matches!(relay, Transport::Relay { family: Some(_), .. }) {
        let why = "-4 and -6 choose the family that the relay dials; an exit resolves its target itself";
        return Err(Refusal::usage(why));
    }
    crate::pairs::check_label(name)?;
    let race = super::iroh::race(args, name)?;
    let derp = super::derp::race(args)?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    if let (Some(iroh), Some(ticket)) = (&race, &derp.ticket) {
        super::iroh::same_node(&iroh.ticket, ticket)?;
    }
    let trust = super::resolve::ca_file(args, env).map_or(Trust::Default, |file| Trust::File(file.into()));
    let channel = super::iroh::channel_ask(args).map_err(Refusal::usage)?;
    let (label, pair_file) = (name.to_string(), args.pair_file.clone());
    // The exit over a carrier is T-596's: `--carrier` is refused beside it.
    let opentunnel = super::opentunnel::Race::default();
    Ok(Transport::Node { label, pair_file, trust, race, derp, opentunnel, channel, carrier: None })
}

/// The exit's word, the first hop of the run (`-J`'s first, else the
/// destination, with its `HostName` and port), once the resolver knows it;
/// `--exit` beside a road of its own is refused.
pub(super) fn fill(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let Some(name) = args.exit.as_deref() else { return Ok(()) };
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let (host, port) = (first.host.clone(), first.port);
    // A node's own destination is shown as node://NAME, never a host.
    let to_node = opts.destination.host.starts_with(super::node::SCHEME);
    match &mut resolved.transport {
        Transport::Node { label, channel, .. } if label.as_str() == name && channel.route.is_none() && !to_node => {
            *channel = channel.clone().to_exit(&host, port).map_err(Refusal::usage)?;
            Ok(())
        }
        _ => Err(Refusal::usage(ITS_OWN)),
    }
}

/// Whether the road of `transport` starts at an exit: a node's, whose word
/// is a target (it holds a ':', which no route's name does).
pub fn is_exit(transport: &Transport) -> bool {
    matches!(transport, Transport::Node { channel, .. } if channel.route.as_deref().is_some_and(|w| w.contains(':')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(words: &[&str]) -> Result<Resolved, Refusal> {
        let mut args = SshArgs { destination: Some(words[0].into()), ..SshArgs::default() };
        args.exit = Some("lab".into());
        args.jump = words.get(1).map(|j| j.to_string());
        let env = Env { home: None, user: Some("me".into()), ..Env::default() };
        super::super::resolve::resolve_or_refuse(&args, &env)
    }

    #[test]
    fn the_exit_s_word_is_the_first_hop_and_the_host_key_the_host_s() {
        let r = resolved(&["git@github.com"]).unwrap();
        assert!(is_exit(&r.transport));
        match &r.transport {
            Transport::Node { label, channel, .. } => {
                assert_eq!((label.as_str(), channel.route.as_deref()), ("lab", Some("github.com:22")))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.options.destination.host, "github.com", "the host key is looked up under the host");
        let r = resolved(&["me@[2001:db8::1]:2222", "hop.example:2200"]).unwrap();
        match &r.transport {
            Transport::Node { channel, .. } => assert_eq!(channel.route.as_deref(), Some("hop.example:2200")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_exit_beside_a_road_of_its_own_is_refused() {
        for dest in ["node://lab", "node://other"] {
            let refusal = resolved(&[dest]).unwrap_err();
            assert!(refusal.code == 64 && refusal.message.contains("--exit NAME starts the road"), "{dest}");
        }
    }
}
