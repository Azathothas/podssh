//! `podssh ssh [USER@]iroh:TICKET` (T-162, T-163): SSH to the TCP service of
//! a podssh node over the iroh road. The road is in a build with the feature
//! `iroh` only: without it, an iroh destination is refused before anything
//! connects, and the refusal names the feature. The node's host key is
//! recorded under `iroh:` and the node's key, which stays when the node's
//! ticket changes with its home relay.

#[cfg(feature = "iroh")]
mod dial;

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
    podssh_iroh::ticket::parse(ticket).map(|addr| format!("{SCHEME}{}", podssh_iroh::keys::fingerprint(&addr.id)))
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
    Ok(Transport::Iroh { ticket: dest.ticket.clone(), key: r.args.iroh_key.clone(), relays, trust })
}

/// The relays of `--iroh-relay`, else of the variable, else of the table: a
/// bad flag is a usage error (64), a bad variable a configuration error
/// (78), as the relay's own flag and variable are.
#[cfg(feature = "iroh")]
fn relays(flag: Option<&str>) -> Result<Vec<String>, Refusal> {
    match podssh_iroh::relays::from_environment(flag) {
        Ok((list, _)) => Ok(list.iter().map(ToString::to_string).collect()),
        Err(why) if flag.is_some() => Err(Refusal::usage(why)),
        Err(why) => Err(Refusal::config(why)),
    }
}

#[cfg(not(feature = "iroh"))]
fn relays(_: Option<&str>) -> Result<Vec<String>, Refusal> {
    Ok(Vec::new())
}

/// SSH over the iroh road to the node of `ticket`.
#[cfg(feature = "iroh")]
pub(super) async fn connect(
    ticket: &str,
    key: Option<&str>,
    relays: &[String],
    trust: &Trust,
    opts: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    dial::connect(ticket, key, relays, trust, opts, log).await
}

#[cfg(not(feature = "iroh"))]
pub(super) async fn connect(
    ticket: &str,
    _: Option<&str>,
    _: &[String],
    _: &Trust,
    _: &podssh_ssh::options::Options,
    log: std::sync::Arc<podssh_ssh::Log>,
) -> i32 {
    log.error(&not_built(ticket));
    podssh_ssh::EXIT_FAILURE
}
