//! Encrypted Client Hello (T-642): `pod_tls::ech`, in the process's context
//! ([`crate::tls::context`]), over podssh's dial and its resolvers of DNS
//! over HTTPS. The name of a host that publishes a list in its HTTPS record
//! goes sealed inside the ClientHello, and the hello in the clear names the
//! list's public name (`cloudflare-ech.com` in Cloudflare's).
//!
//! **Only when the user asks for it** (`PODSSH_ECH`, or the settings file's
//! `ECH`): the record is read before the session's connection, which behind
//! a proxy no resolver of podssh's makes otherwise (the call of T-642's
//! Decision, for the operator to confirm under Q86). The list is read from
//! the resolvers of DNS over HTTPS through the same proxy
//! ([`crate::resolve::https`]), once for each name and TTL. The dial is
//! podssh's ([`crate::dial::dialer`]).

use std::net::SocketAddr;
use std::time::Duration;

use pod_core::{BoxFuture, Target};
use tokio::time::Instant;

use crate::client::{ConnectError, RelayStream};
use crate::dial::ProxyChoice;
use crate::tls::{self, Trust};

pub use pod_tls::ech::{Cache, Clock, Lookup, Mode, Outcome, Published, Why, READ_WITHIN, SEALED_WAIT};

/// The variable that asks for ECH.
pub const ECH_ENV: &str = "PODSSH_ECH";

/// How the user asks for strict ECH, in the words of a refusal.
pub const STRICT: &str = "PODSSH_ECH=strict";

/// [`Mode::parse`] of this process's variable, its name in a refusal.
pub fn mode_from_env() -> Result<Option<Mode>, String> {
    Mode::parse(std::env::var(ECH_ENV).ok().as_deref()).map_err(|why| format!("{ECH_ENV}: {why}"))
}

/// Set the process's mode: a command does, from [`ECH_ENV`], then its
/// settings file.
pub fn set_mode(mode: Mode) {
    tls::context().ech().set_mode(mode);
}

/// The process's mode: the one set, else the variable's, else off.
pub fn mode() -> Mode {
    tls::context().ech().mode()
}

/// Whether a connection to `server_name` under `trust` is to be sealed in
/// this process.
pub fn wanted(server_name: &str, trust: &Trust) -> bool {
    tls::context().ech().wanted(server_name, trust)
}

/// What ECH did for `name`'s last connection in this process.
pub fn outcome(name: &str) -> Option<Outcome> {
    tls::context().ech().outcome(name)
}

/// TCP to `host:port` through `proxy`, then TLS for `server_name` with the
/// roots of `trust`, offering `alpn`: sealed where the process asks for it
/// and the name publishes a list, else a plain hello as always; and the
/// address that the TCP reached.
pub async fn open(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
    alpn: &[&[u8]],
) -> Result<(RelayStream, Option<SocketAddr>), ConnectError> {
    let target = Target::new(host, port);
    // The dial's error goes as the cause, so that the road gives it back as
    // it was ([`tls::connect_error`]).
    let dial = crate::dial::dialer(proxy, false);
    let records = Records(proxy.clone());
    let route =
        pod_tls::ech::Route { target: &target, server_name, trust, dial: &dial, records: &records, limit, alpn };
    pod_tls::ech::open(tls::context(), &route).await.map_err(|e| tls::connect_error(e, limit))
}

/// The read of a name's HTTPS record through podssh's way out: the
/// resolvers of DNS over HTTPS, through the proxy of the road.
#[derive(Debug, Clone)]
pub struct Records(pub ProxyChoice);

impl pod_tls::ech::Records for Records {
    fn ech_list<'a>(&'a self, name: &'a str, deadline: Instant) -> BoxFuture<'a, Result<Option<Published>, String>> {
        Box::pin(crate::resolve::https::doh_https(name, &self.0, deadline))
    }
}
