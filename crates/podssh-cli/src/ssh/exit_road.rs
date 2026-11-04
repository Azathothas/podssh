//! `--exit NAME` of `podssh ssh` and the copies (T-431): the road to the
//! first hop starts at NAME, a node of the user's net that lends its egress
//! (`podssh node --exit`), in place of the relay. The transport is the
//! node's own (`Transport::Node`), so each of its roads carries it, raced
//! as for `node://NAME`, and the session resumes on any of them; the
//! channel's word names the first hop, `HOST:PORT`, in place of a route, and
//! the SSH client checks that host's key under its own name, as on the
//! relay. With `--carrier ADDR` (T-614), the exit is the node at the other
//! end of that stream, its one road, as for `node://NAME --carrier`. Here so
//! that the resolver stays one file.

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
    crate::exit::auto::flags(name, args.pair_file.as_deref(), args.carrier.as_deref())?;
    if let Some(text) = args.carrier.as_deref() {
        return carried(args, name, text);
    }
    let trust = super::resolve::ca_file(args, env).map_or(Trust::Default, |file| Trust::File(file.into()));
    let channel = super::iroh::channel_ask(args).map_err(Refusal::usage)?;
    let (label, pair_file) = (name.to_string(), args.pair_file.clone());
    let derp = super::derp::Race { ticket: None, servers: Vec::new(), fallback: false };
    let opentunnel = Box::default();
    let mut transport =
        Transport::Node { label, pair_file, trust, race: None, derp, opentunnel, channel, carrier: None };
    // `--exit auto` (T-432) knows its exit once the first hop is known: its
    // roads are read then ([`fill`]).
    if !crate::exit::auto::is_auto(name) {
        roads(args, &mut transport)?;
    }
    Ok(transport)
}

/// The roads of the exit that `transport` names: an iroh ticket kept under
/// its name, and DERP's; before anything connects.
fn roads(args: &SshArgs, transport: &mut Transport) -> Result<(), Refusal> {
    let Transport::Node { label, race, derp, .. } = transport else { return Ok(()) };
    let found = super::iroh::race(args, label)?;
    let servers = super::derp::race(args)?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    if let (Some(iroh), Some(ticket)) = (&found, &servers.ticket) {
        super::iroh::same_node(&iroh.ticket, ticket)?;
    }
    (*race, *derp) = (found, servers);
    Ok(())
}

/// The exit at the other end of the carrier `text` (T-614): the stream is
/// its one road, so a flag of another road is refused in the carrier's words
/// first, and no road is read that the run would not take (a ticket kept
/// under NAME, the transit's and DERP's variables).
fn carried(args: &SshArgs, name: &str, text: &str) -> Result<Transport, Refusal> {
    super::carried::flags(args).map_err(|why| Refusal::usage(format!("--exit {name}: {why}")))?;
    let channel = super::iroh::channel_ask(args).map_err(Refusal::usage)?;
    let derp = super::derp::Race { ticket: None, servers: Vec::new(), fallback: false };
    Ok(Transport::Node {
        label: name.to_string(),
        pair_file: None,
        trust: Trust::Default,
        race: None,
        derp,
        opentunnel: Box::default(),
        channel,
        carrier: Some(text.to_string()),
    })
}

/// The exit's word, the first hop of the run (`-J`'s first, else the
/// destination, with its `HostName` and port), once the resolver knows it;
/// `--exit` beside a road of its own is refused.
pub(super) fn fill(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let Some(asked) = args.exit.as_deref() else { return Ok(()) };
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let (host, port) = (first.host.clone(), first.port);
    // A node's own destination is shown as node://NAME, never a host.
    let to_node = opts.destination.host.starts_with(super::node::SCHEME);
    let mut name = asked.to_string();
    if let (true, false, Transport::Node { label, .. }) =
        (crate::exit::auto::is_auto(asked), to_node, &mut resolved.transport)
    {
        let picked = crate::exit::auto::pick(&host)?;
        resolved.notes.push(picked.line(&host));
        name = picked.name;
        *label = name.clone();
        roads(args, &mut resolved.transport)?;
    }
    let name = name.as_str();
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

    /// With `--carrier` (T-614), the stream is the exit's one road: no other
    /// races it, and a flag of another road, or stdio, is refused.
    #[test]
    fn the_exit_over_a_carrier_is_its_one_road() {
        let env = Env { home: None, user: Some("me".into()), ..Env::default() };
        let on = |carrier: &str, pair_file: Option<&str>| {
            let mut args = SshArgs { destination: Some("git@github.com".into()), ..SshArgs::default() };
            args.exit = Some("lab".into());
            args.carrier = Some(carrier.into());
            args.pair_file = pair_file.map(String::from);
            super::super::resolve::resolve_or_refuse(&args, &env)
        };
        match on("exec:cat", None).unwrap().transport {
            Transport::Node { label, channel, carrier, race, .. } => {
                assert_eq!((label.as_str(), channel.route.as_deref()), ("lab", Some("github.com:22")));
                assert_eq!((carrier.as_deref(), race), (Some("exec:cat"), None), "the stream alone");
            }
            other => panic!("{other:?}"),
        }
        let paired = ("exec:cat", Some("x"), "--pair-file does not go with --carrier");
        for (carrier, pair_file, says) in [paired, ("stdio", None, "--carrier stdio")] {
            let refusal = on(carrier, pair_file).unwrap_err();
            assert!(refusal.code == 64 && refusal.message.contains(says), "{carrier}: {}", refusal.message);
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
