//! The remote ends of `podssh pipe` (T-175): each opens its road and gives
//! an end; the pump does not know the road (`docs/architecture.md`). The
//! settings of the roads come from the flags of `pipe`, as `proxy` and
//! `ssh` take them, and are read only when an address needs them. With
//! `--exit NAME`, `relay:` starts at that exit of the net (T-431).

use std::io::Write;

use podssh_relay::failover::Mode;
use podssh_relay::relay::{self, RelayList};
use podssh_ws::{ProxyChoice, Trust};

use super::address::Address;
use super::pump::End;
use super::web::Template;
use super::PipeArgs;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// The roads' settings, read once both addresses are checked.
#[derive(Clone)]
pub struct Settings {
    pub relays: Option<RelayList>,
    /// How the relay hosts are tried (T-220).
    pub failover: Mode,
    pub trust: Trust,
    /// What an SSH hop, a node and the iroh road read: `pipe`'s flags.
    pub ssh: crate::ssh::args::SshArgs,
    /// `--via`: the second proxy that carries `tcp:` (T-439).
    pub via: Option<crate::via::Road>,
}

/// Whether `address` leaves this host.
pub fn is_remote(address: &Address) -> bool {
    matches!(
        address,
        Address::Relay { .. }
            | Address::Tcp { .. }
            | Address::Ssh { .. }
            | Address::Node(_)
            | Address::UdpNode(_)
            | Address::Iroh(_)
            | Address::Ws(_)
    )
}

/// The settings that the remote addresses of `args` need: the pins of
/// `--relay-addr`, the relay hosts, the trust.
pub fn settings(args: &PipeArgs, addresses: [&Address; 2]) -> Result<Settings, Refusal> {
    crate::pins::apply(args.ssh.relay_addr.as_deref())?;
    // The template of a proxy's other side is the road of each request (T-367).
    let relay = |a: &&Address| matches!(a, Address::Relay { .. } | Address::Template(Template::Relay));
    if args.ssh.exit.is_some() && !addresses.iter().any(relay) {
        return Err(Refusal::usage("--exit NAME starts relay:HOST:PORT and relay:%h:%p at the exit: name one of them"));
    }
    let relays = if addresses.iter().any(relay) {
        Some(crate::relay_settings::relays(args.ssh.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok())?)
    } else {
        None
    };
    let failover = crate::relay_settings::failover(
        args.ssh.relay_failover.as_deref(),
        std::env::var(podssh_relay::failover::MODE_ENV).ok(),
    )?;
    let ca_file = crate::settings::ca_file(args.ssh.ca_file.as_deref());
    let trust = match ca_file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    if addresses.iter().any(|a| matches!(a, Address::Ssh { .. } | Address::Template(Template::Ssh(_)))) {
        super::ssh::check_options(&args.ssh.options)?;
    }
    // The flag alone: `tcp:` is TCP from this host, which PODSSH_VIA leaves.
    let tcp = addresses.iter().any(|a| matches!(a, Address::Tcp { .. }));
    let via = match args.ssh.via.is_some() && tcp {
        true => crate::via::chosen(&crate::via::Flags::of(&args.ssh), trust.clone())?,
        false => None,
    };
    Ok(Settings { relays, failover, trust, ssh: args.ssh.clone(), via })
}

/// Open a remote end: the end, or the exit code once its lines are written.
pub async fn open(address: &Address, settings: &Settings, err: &mut dyn Write) -> Result<End, i32> {
    let mut say = |line: &str| {
        let _ = writeln!(err, "podssh pipe: {line}");
    };
    match address {
        Address::Relay { host, port } if settings.ssh.exit.is_some() => {
            let name = settings.ssh.exit.as_deref().unwrap_or_default();
            let to = crate::exit::open::To::of_ssh(name, &settings.ssh);
            crate::exit::open::open(&to, host, *port).await.map_err(|refused| {
                say(&format!("relay:{}: --exit {name}: {}", podssh_ws::dial::authority(host, *port), refused.line));
                refused.code
            })
        }
        Address::Relay { host, port } => {
            let relays = settings.relays.as_ref().expect("the relay hosts, read with the addresses");
            let road = super::relay::Road { relays, trust: &settings.trust, failover: settings.failover };
            super::relay::open(&road, host, *port, &mut say).await
        }
        Address::Tcp { host, port } => match &settings.via {
            Some(road) => crate::via::pipe::open(road, host, *port, &mut say).await,
            None => tcp(host, *port, &mut say).await,
        },
        Address::Ssh { hops, host, port } => super::ssh::open(hops, host, *port, &settings.ssh, &mut say).await,
        Address::Node(label) => super::node::open(label, &settings.ssh, &mut say).await,
        Address::UdpNode(label) => super::datagram::open_node(label, &settings.ssh, &mut say).await,
        Address::Iroh(ticket) => super::iroh::open(ticket, &settings.ssh, &settings.trust, &mut say).await,
        Address::Ws(url) => super::ws::open(url, &settings.trust, &mut say).await,
        _ => unreachable!("a local address"),
    }
}

/// `tcp:HOST:PORT`: TCP from this host, through `HTTPS_PROXY` when it is
/// set, as `ssh --direct` dials. TCP has a half-close, so each direction
/// ends by itself.
async fn tcp(host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    tcp_dial(host, port).await.map_err(|e| {
        say(&tcp_failure(host, port, e.as_ref()));
        e.as_ref().map_or(EX_UNAVAILABLE, dial_code)
    })
}

/// The stream of `tcp:HOST:PORT`, or the error of its dial: `None` when
/// `PODSSH_OFFLINE` forbids each connection.
pub(super) async fn tcp_dial(host: &str, port: u16) -> Result<End, Option<podssh_ws::DialError>> {
    if podssh_relay::open::offline() {
        return Err(None);
    }
    let timeout = podssh_relay::open::CONNECT_TIMEOUT;
    let stream = podssh_ws::dial::dial(host, port, &ProxyChoice::FromEnvironment, timeout).await.map_err(Some)?;
    let _ = stream.set_nodelay(true);
    let (read, write) = tokio::io::split(stream);
    Ok(End::plain(Box::new(read), Box::new(write)))
}

/// The line of a dial of `tcp:` that failed, or that `PODSSH_OFFLINE` forbade.
pub(super) fn tcp_failure(host: &str, port: u16, e: Option<&podssh_ws::DialError>) -> String {
    match e {
        None => format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV),
        Some(e) => format!("could not connect to {}: {e}", podssh_ws::dial::authority(host, port)),
    }
}

/// The sysexits code of a dial that failed, as `proxy` gives it.
pub(super) fn dial_code(e: &podssh_ws::DialError) -> i32 {
    use podssh_ws::DialError;
    match e {
        DialError::BadProxy(_) | DialError::InvalidTarget(_) => EX_CONFIG,
        DialError::ProxyRefused { status: 403 | 407, .. } => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}
