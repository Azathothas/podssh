//! `podssh ssh [USER@]iroh:TICKET` (T-162, T-163): SSH to the TCP service of
//! a podssh node over the iroh road. The road is in a build with the feature
//! `iroh` only: without it, an iroh destination is refused before anything
//! connects, and the refusal names the feature. The node's host key is
//! recorded under `iroh:` and the node's key, which stays when the node's
//! ticket changes with its home relay.

#[cfg(feature = "iroh")]
pub(crate) mod dial;
#[cfg(feature = "iroh")]
mod race;

use super::node::Ask;
use super::resolve::Transport;
use crate::relay_settings::Refusal;
use podssh_ws::Trust;

/// The form of an iroh destination: `iroh:TICKET`, or `USER@iroh:TICKET`.
pub const SCHEME: &str = "iroh:";

/// Whether `destination` names a far end over the iroh road.
pub fn is_iroh(destination: &str) -> bool {
    let host = destination.rsplit_once('@').map_or(destination, |(_, host)| host);
    host.starts_with(SCHEME)
}

/// Why this build has no iroh road, for `what` that needs it.
pub fn not_built(what: &str) -> String {
    format!(
        "{what}: the iroh road is not in this build; build podssh with --features iroh \
         (cargo build -p podssh-cli --features iroh)"
    )
}

/// Why `destination` cannot be reached by this build.
pub fn refusal(destination: &str) -> String {
    not_built(destination)
}

/// An iroh destination: the user, the ticket as given, and the name of the
/// node in the messages and the known hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub user: Option<String>,
    pub ticket: String,
    pub shown: String,
}

/// `[USER@]iroh:TICKET` as its parts; `None` for each other destination. A
/// ticket that is not one is refused here, before anything connects.
pub fn destination(text: &str) -> Result<Option<Destination>, String> {
    if !is_iroh(text) {
        return Ok(None);
    }
    let (user, ticket) = match text.rsplit_once('@') {
        Some(("", _)) => return Err(format!("{text:?}: empty user name")),
        Some((user, ticket)) => (Some(user.to_string()), ticket),
        None => (None, text),
    };
    Ok(Some(Destination { user, ticket: ticket.to_string(), shown: shown(ticket)? }))
}

/// The node's name: `iroh:` and its key.
#[cfg(feature = "iroh")]
fn shown(ticket: &str) -> Result<String, String> {
    podssh_iroh::ticket::parse(ticket).map(|addr| format!("{SCHEME}{}", podssh_iroh::keys::name(&addr.id)))
}

#[cfg(not(feature = "iroh"))]
fn shown(ticket: &str) -> Result<String, String> {
    Err(not_built(ticket))
}

/// What reaches the node: the iroh road alone, with no `-J`, `-W`, `-p`,
/// `HostName`, `-4`, `-6` or `--direct`, which a node has no use for yet;
/// and the relays to try after the ticket's.
pub(super) fn transport(dest: &Destination, r: &Ask<'_>, trust: Trust) -> Result<Transport, Refusal> {
    let why = if r.args.direct {
        Some("--direct cannot reach a node of the iroh road: only the road can")
    } else if r.jumps > 0 {
        Some("a node of the iroh road cannot be reached through a -J hop yet")
    } else if r.forward {
        Some("-W over the iroh road is not implemented yet")
    } else if r.port {
        Some("a node has no port: its TARGET is set where the node runs")
    } else if r.host_name {
        Some("-o HostName cannot apply to a node")
    } else if r.family.is_some() {
        Some("-4 and -6 do not apply to the iroh road, which dials a key")
    } else if r.args.pair_file.is_some() {
        Some("--pair-file is for node://NAME; the iroh road needs no pair")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(Refusal::usage(format!("{}: {why}", dest.shown)));
    }
    let relays = relays(r.args.iroh_relay.as_deref())?;
    let channel = channel_ask(r.args).map_err(|why| Refusal::usage(format!("{}: {why}", dest.shown)))?;
    let key = channel.client_key.clone();
    Ok(Transport::Iroh { ticket: dest.ticket.clone(), key, relays, trust, channel })
}

/// The end-to-end channel that the command line asks of a node (T-088).
pub(crate) fn channel_ask(args: &super::args::SshArgs) -> Result<crate::channel::Ask, String> {
    crate::channel::Ask::of(args.client_key.as_deref(), args.iroh_key.as_deref(), args.node_key.as_deref(), args.no_e2e)
}

/// The iroh road of a race with a pair's reverse road (T-164): the node's
/// ticket, this client's key file, and the relays after the ticket's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    pub ticket: String,
    pub key: Option<String>,
    pub relays: Vec<String>,
}

/// `--iroh-ticket` of a `node://NAME` destination, checked before anything
/// connects.
pub(super) fn race(args: &super::args::SshArgs) -> Result<Option<Race>, Refusal> {
    let Some(ticket) = &args.iroh_ticket else { return Ok(None) };
    shown(ticket).map_err(Refusal::usage)?;
    let relays = relays(args.iroh_relay.as_deref())?;
    let key = args.client_key.clone().or_else(|| args.iroh_key.clone());
    Ok(Some(Race { ticket: ticket.clone(), key, relays }))
}

/// The relays of `--iroh-relay`, else of the variable, else of the table: a
/// bad flag is a usage error (64), a bad variable a configuration error
/// (78), as the relay's own flag and variable are.
#[cfg(feature = "iroh")]
pub(crate) fn relays(flag: Option<&str>) -> Result<Vec<String>, Refusal> {
    match podssh_iroh::relays::from_environment(flag) {
        Ok((list, _)) => Ok(list.iter().map(ToString::to_string).collect()),
        Err(why) if flag.is_some() => Err(Refusal::usage(why)),
        Err(why) => Err(Refusal::config(why)),
    }
}

#[cfg(not(feature = "iroh"))]
pub(crate) fn relays(_: Option<&str>) -> Result<Vec<String>, Refusal> {
    Ok(Vec::new())
}

/// SSH over the iroh road to the node of `ticket`.
#[cfg(feature = "iroh")]
pub(super) async fn connect(
    ticket: &str,
    key: Option<&str>,
    relays: &[String],
    trust: &Trust,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    dial::connect(ticket, key, relays, trust, ask, opts, log).await
}

#[cfg(not(feature = "iroh"))]
pub(super) async fn connect(
    ticket: &str,
    _: Option<&str>,
    _: &[String],
    _: &Trust,
    _: &crate::channel::Ask,
    _: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    log.error(&not_built(ticket));
    podssh_ssh::EXIT_FAILURE
}

/// SSH to the node of a pair, raced with its iroh road (T-164).
#[cfg(feature = "iroh")]
pub(super) async fn race_connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    race_road: &Race,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    race::connect(label, pair_file, trust, race_road, ask, opts, log).await
}

#[cfg(not(feature = "iroh"))]
pub(super) async fn race_connect(
    _: &str,
    _: Option<&str>,
    _: &Trust,
    _: &Race,
    _: &crate::channel::Ask,
    _: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    log.error(&not_built("--iroh-ticket"));
    podssh_ssh::EXIT_FAILURE
}
