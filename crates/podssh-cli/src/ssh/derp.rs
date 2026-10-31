//! `podssh ssh [USER@]derp:TICKET[/ROUTE]` (T-379): SSH to the TCP service of
//! a podssh node over the DERP road (`podssh node --derp`), through
//! Tailscale's servers for tailcat or those of `--derp-server`. The ticket
//! names the node's home server, its key there, and its identity, which the
//! end-to-end channel checks; this client's key on the servers is new for
//! each run, so the node lets in the identity that the channel proves, by
//! its allowlist. The host key is recorded under `derp:` and the node's key,
//! which stays when the ticket changes with the node's home. With
//! `node://NAME`, `--derp-ticket` races the road with the others; a ticket
//! so given is kept under NAME, and a later run that names none falls back
//! on it (the operator's ruling Q50), unless `PODSSH_DERP` is `no`.

use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::derp::{self, dial, servers, Dialer, Server, Ticket};
use podssh_relay::session::hearing::WAIT;
use podssh_relay::session::resume::Note;
use podssh_relay::session::Hearing;
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};

use super::args::SshArgs;
use super::node::Ask;
use super::resolve::Transport;
use crate::layered::Line;
use crate::relay_settings::Refusal;

/// The form of a DERP destination: `derp:TICKET`, or `USER@derp:TICKET`.
pub const SCHEME: &str = derp::ticket::SCHEME;

/// Each direction of the pipe between the SSH client and the layer.
const PIPE: usize = 256 * 1024;

/// Whether `destination` names a node over the DERP road. `derp:PORT`, all
/// digits, is the host `derp` and a port: a ticket starts with a letter.
pub fn is_derp(destination: &str) -> bool {
    let host = destination.rsplit_once('@').map_or(destination, |(_, host)| host);
    host.strip_prefix(SCHEME).is_some_and(|rest| !rest.is_empty() && !rest.bytes().all(|b| b.is_ascii_digit()))
}

/// A DERP destination: the user, the ticket, the name of the node in the
/// messages and the known hosts, and the route of the node (T-089).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub user: Option<String>,
    pub ticket: Ticket,
    pub shown: String,
    pub route: Option<String>,
}

/// `[USER@]derp:TICKET[/ROUTE]` as its parts; `None` for each other
/// destination. A ticket that is not one is refused here.
pub fn destination(text: &str) -> Result<Option<Destination>, String> {
    if !is_derp(text) {
        return Ok(None);
    }
    let (user, named) = match text.rsplit_once('@') {
        Some(("", _)) => return Err(format!("{text:?}: empty user name")),
        Some((user, named)) => (Some(user.to_string()), named),
        None => (None, text),
    };
    let (word, route) = match named.split_once('/') {
        Some((word, route)) => {
            podssh_ws::names::check_node_name(route).map_err(|_| format!("{text:?}: {route:?} is not a route"))?;
            (word, Some(route.to_string()))
        }
        None => (named, None),
    };
    let ticket = Ticket::parse(word)?;
    let node = shown(&ticket);
    let shown = route.as_ref().map_or_else(|| node.clone(), |r| format!("{node}/{r}"));
    Ok(Some(Destination { user, ticket, shown, route }))
}

/// The node's name: `derp:` and its Ed25519 key in hex, which stays when its
/// home, and so its ticket, changes.
pub fn shown(ticket: &Ticket) -> String {
    format!("{SCHEME}{}", ticket.node.hex())
}

/// The servers to try after a ticket's: `--derp-server`, else
/// `PODSSH_DERP_SERVER`, else tailcat's fleet. A bad flag is a usage error
/// (64), a bad variable a configuration error (78), as for the relay.
pub(crate) fn servers(flag: Option<&str>) -> Result<Vec<Server>, Refusal> {
    match servers::from_environment(flag) {
        Ok((list, _)) => Ok(list),
        Err(why) if flag.is_some() => Err(Refusal::usage(format!("--derp-server: {why}"))),
        Err(why) => Err(Refusal::config(format!("{}: {why}", servers::ENV))),
    }
}

/// What reaches a node of the DERP road: the road alone, with no `-J`,
/// `-W`, `-p`, `HostName`, `-4`, `-6`, `--direct` or `--pair-file`; and the
/// end-to-end channel, which is the node's only door.
pub(super) fn transport(dest: &Destination, r: &Ask<'_>, trust: Trust) -> Result<Transport, Refusal> {
    let why = if r.args.direct {
        Some("--direct cannot reach a node of the DERP road: only the road can")
    } else if r.jumps > 0 {
        Some("a node of the DERP road cannot be reached through a -J hop")
    } else if r.forward {
        Some("-W over the DERP road is not implemented")
    } else if r.port {
        Some("a node has no port: its TARGET is set where the node runs")
    } else if r.host_name {
        Some("-o HostName cannot apply to a node")
    } else if r.family.is_some() {
        Some("-4 and -6 do not apply to the DERP road, which sends to a key")
    } else if r.args.pair_file.is_some() {
        Some("--pair-file is for node://NAME; the DERP road needs no pair")
    } else if r.args.no_e2e {
        Some(
            "--no-e2e cannot go with the DERP road: a DERP server lets any key send, so the node lets in the key \
             that the end-to-end channel proves",
        )
    } else {
        None
    };
    if let Some(why) = why {
        return Err(Refusal::usage(format!("{}: {why}", dest.shown)));
    }
    let list = servers(r.args.derp_server.as_deref())?;
    let channel = super::iroh::channel_ask(r.args)
        .and_then(|ask| ask.to_route(dest.route.as_deref()))
        .map_err(|why| Refusal::usage(format!("{}: {why}", dest.shown)))?;
    let servers = servers::for_client_in(&dest.ticket.server, &list);
    Ok(Transport::Derp { ticket: dest.ticket.clone(), servers, trust, channel })
}

/// The DERP road of a `node://NAME` destination: the ticket of
/// `--derp-ticket`, or none; the servers after the ticket's; and whether a
/// ticket kept under NAME may be dialled when none is given (Q50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    pub ticket: Option<Ticket>,
    pub servers: Vec<Server>,
    pub fallback: bool,
}

/// The DERP road of one run to a node: its ticket, the servers in the
/// order that they are tried, and whether the user gave the ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub ticket: Ticket,
    pub servers: Vec<Server>,
    pub asked: bool,
}

impl Race {
    /// The road of a run to the node of `label`: the ticket given, else the
    /// one kept under the label when the fallback is on; else none.
    pub(crate) fn road(&self, label: &str) -> Option<Road> {
        let (ticket, asked) = match &self.ticket {
            Some(ticket) => (ticket.clone(), true),
            None if self.fallback => (kept(label)?, false),
            None => return None,
        };
        let servers = servers::for_client_in(&ticket.server, &self.servers);
        Some(Road { ticket, servers, asked })
    }
}

/// `--derp-ticket` and `--derp-server` of a `node://NAME` destination, and
/// `PODSSH_DERP`, checked before anything connects.
pub(super) fn race(args: &SshArgs) -> Result<Race, Refusal> {
    let ticket = match &args.derp_ticket {
        Some(text) => Some(Ticket::parse(text).map_err(|why| Refusal::usage(format!("--derp-ticket: {why}")))?),
        None => None,
    };
    let servers = servers(args.derp_server.as_deref())?;
    let fallback = crate::node_derp::fallback_on()?;
    Ok(Race { ticket, servers, fallback })
}

/// The file of the ticket kept under `label`, in the cache.
fn ticket_file(label: &str) -> String {
    format!("derp-{}.ticket", podssh_relay::cache::safe_name(label))
}

/// Keep `ticket` under `label`, for the fallback of a later run. A ticket is
/// an address, not a credential; it goes in a private file as the pins do.
pub(crate) fn keep(label: &str, ticket: &Ticket) -> Result<PathBuf, String> {
    podssh_relay::cache::store_file(&ticket_file(label), format!("{ticket}\n").as_bytes())
}

/// The ticket kept under `label`, when one is and it reads as one.
pub(crate) fn kept(label: &str) -> Option<Ticket> {
    let text = podssh_relay::cache::load_file(&ticket_file(label))?;
    Ticket::parse(text.trim()).ok()
}

/// A dialer of the node of `ticket` over `servers`, through the proxy of the
/// environment; its lines go to `-v` under `shown`.
pub(crate) fn dialer(
    ticket: &Ticket,
    servers: &[Server],
    trust: &Trust,
    log: &Arc<Log>,
    shown: &str,
) -> Result<Dialer, String> {
    let say: derp::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    let dial = dial::tls(trust.clone(), ProxyChoice::FromEnvironment);
    Dialer::with_servers(ticket, servers.to_vec(), dial, say).map_err(|e| e.to_string())
}

/// SSH over the DERP road to the node of `ticket`, trying `servers` in turn.
pub(super) async fn connect(
    ticket: &Ticket,
    servers: &[Server],
    trust: &Trust,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let shown = shown(ticket);
    if let Err(refusal) = crate::pairs::online() {
        log.error(&format!("{shown}: {}", refusal.message));
        return EXIT_FAILURE;
    }
    // The channel of T-088, to the node that the ticket names.
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = match ask.operator(crate::channel::Expect::Ticket(ticket.node), &say_line) {
        Ok(channel) => channel,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let me = channel.as_ref().map(|c| c.identity.clone());
    let dialer = match dialer(ticket, servers, trust, &log, &shown) {
        Ok(dialer) => dialer,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let through: Vec<String> = dialer.servers().iter().map(ToString::to_string).collect();
    log.verbose(&format!("connecting to {shown} over the DERP road, through {}", through.join(", then ")));
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    };
    let note = |note: Note| {
        if !crate::layered::folded(&note, Some(&opts.silence)) {
            say(crate::layered::line_of(note));
        }
    };
    // The iroh road's features and no spare link: a spare link of DERP goes
    // through the same connection as the silent one.
    let settings = crate::layered::iroh_settings(derp::FEATURES);
    // The far end's silence, for a notice (T-302).
    let hearing = Arc::new(Hearing::default());
    let read = hearing.clone();
    opts.silence.attach(move || read.silent(tokio::time::Instant::now(), WAIT));
    let pin_say = {
        let (log, shown) = (log.clone(), shown.clone());
        move |line: String| log.info(&format!("{shown}: {line}"))
    };
    let (layer_app, session) = crate::channel::around(layer_end, channel, pin_say);
    let session = async move {
        match session {
            Some(session) => session.await.err(),
            None => None,
        }
    };
    // The SSH client and the layer in one task: when the client closes its
    // end, the layer sends `CLOSE` on the link that it has.
    let (code, carried, failed) = tokio::join!(
        Box::pin(podssh_ssh::run(ssh_end, opts, None, log.clone())),
        Box::pin(derp::client::carry_heard(&dialer, layer_app, settings, note, hearing)),
        session
    );
    if let Some(server) = dialer.server().await {
        log.verbose(&format!("{shown}: the DERP server {server} carried the session"));
    }
    if let Some((fault, why)) = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref())) {
        log.error(&format!("{shown}: {why}"));
        crate::ssh::result::channel_failed(&fault);
        dialer.close().await;
        return EXIT_FAILURE;
    }
    if code == EXIT_FAILURE {
        let why = match carried {
            Err(why) => Some(why),
            Ok(outcome) => crate::layered::why_ended(outcome),
        };
        if let Some(why) = why {
            log.error(&format!("{shown}: {why}"));
        }
    }
    dialer.close().await;
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::derp::Key;
    use podssh_relay::identity::PublicKey;

    fn ticket() -> Ticket {
        Ticket { node: PublicKey([7; 32]), derp: Key([8; 32]), server: Server::parse("tc302a.ipn.dev").unwrap() }
    }

    #[test]
    fn a_derp_destination_is_read_with_its_user_and_route_and_a_port_is_a_host_s() {
        let text = ticket().to_string();
        let dest = destination(&format!("tester@{text}/web")).unwrap().unwrap();
        assert_eq!(dest.user.as_deref(), Some("tester"));
        assert_eq!(dest.route.as_deref(), Some("web"));
        assert_eq!(dest.ticket, ticket());
        assert_eq!(dest.shown, format!("derp:{}/web", PublicKey([7; 32]).hex()));
        assert_eq!(destination("derp:22").unwrap(), None, "the host derp and a port");
        assert_eq!(destination("example.org").unwrap(), None);
        assert!(destination("derp:notaticket").is_err());
        assert!(destination(&format!("@{text}")).is_err(), "an empty user");
    }
}
