//! Turning a host name into addresses without trusting that this host's
//! resolver works: `pod-dns` of PodUtils/podcrates, with podssh's settings.
//! In order ([`ORDER`]): an IP literal; the addresses pinned for the name
//! ([`set_pins`]: podssh's `--relay-addr` and `PODSSH_RELAY_ADDR`); the
//! system resolver; the addresses that carried a session within [`FRESH`]
//! ([`set_remembered`]: podssh keeps them in its cache, T-344); DNS over
//! HTTPS to the public resolvers of `pod-services`, asked straight at each
//! resolver's address, in each form that it serves; the older addresses that
//! carried a session, last.
//!
//! With an HTTP proxy none of this runs for the target: the proxy is given the
//! name and resolves it. TLS to the target always checks the target's name, so
//! a wrong pinned, resolved or remembered address fails the handshake instead
//! of connecting somewhere else.
//!
//! pod-dns keeps no process state: the pins and the cache are values of a
//! resolver. podssh keeps one resolver for the process ([`resolver`]), which
//! each dialer of [`crate::dial`] takes, and makes it again when the pins
//! change.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use pod_dns::Way;
use tokio::time::Instant;

use crate::cut::Missed;
use crate::dial::ProxyChoice;

pub use pod_dns::{
    https, parse_pins, split, wire, Doh, Form, Found, Remembered, Source, Srv, FRESH, NXDOMAIN, SOURCE_WAIT,
};

/// The sources, in the order asked.
pub const ORDER: [Source; 6] = Source::ORDER;

/// The pins and the remembered addresses that the process gave, and the
/// resolver made of them.
struct State {
    pins: Vec<(String, IpAddr)>,
    remembered: Vec<Remembered>,
    resolver: Option<Arc<pod_dns::Resolver>>,
}

static STATE: RwLock<State> = RwLock::new(State { pins: Vec::new(), remembered: Vec::new(), resolver: None });

/// podssh's settings of the resolver: `pins`, its user agent, and pod-dns's
/// defaults, which are podssh's (the resolvers of `pod-services` in turns,
/// each by its name first through a proxy, 5 s for a resolver and 3 s for
/// its connection, NXDOMAIN ends the lookup, the cache on).
pub fn settings(pins: Vec<(String, IpAddr)>) -> pod_dns::Settings {
    pod_dns::Settings { pins, user_agent: crate::dial::user_agent(), ..pod_dns::Settings::default() }
}

/// The resolver of `pins`: DNS over HTTPS straight at each resolver's
/// address, through a dial with no proxy whose own resolver asks no DNS over
/// HTTPS.
fn make(pins: Vec<(String, IpAddr)>, remembered: Vec<Remembered>) -> Arc<pod_dns::Resolver> {
    let settings = settings(pins);
    let plain = Arc::new(pod_dns::Resolver::new(settings.clone()));
    let direct = pod_proxy::Dialer::new(crate::dial::settings(&ProxyChoice::Direct, false), plain);
    let resolver = pod_dns::Resolver::new(settings).with_doh(crate::tls::context().clone(), Arc::new(direct));
    resolver.memory().set_remembered(remembered);
    Arc::new(resolver)
}

/// The process's resolver.
pub fn resolver() -> Arc<pod_dns::Resolver> {
    if let Some(resolver) = &STATE.read().unwrap_or_else(PoisonError::into_inner).resolver {
        return resolver.clone();
    }
    let mut state = STATE.write().unwrap_or_else(PoisonError::into_inner);
    let State { pins, remembered, resolver } = &mut *state;
    resolver.get_or_insert_with(|| make(pins.clone(), remembered.clone())).clone()
}

/// Replace the process-wide pins. The resolver is made again: the record of
/// the dialer's connections starts empty.
pub fn set_pins(pins: Vec<(String, IpAddr)>) {
    let mut state = STATE.write().unwrap_or_else(PoisonError::into_inner);
    state.pins = pins;
    state.resolver = None;
}

/// The addresses pinned for `host`, in the order given.
pub fn pinned(host: &str) -> Vec<IpAddr> {
    resolver().settings().pinned(host)
}

/// Replace the remembered addresses.
pub fn set_remembered(list: Vec<Remembered>) {
    let mut state = STATE.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(resolver) = &state.resolver {
        resolver.memory().set_remembered(list.clone());
    }
    state.remembered = list;
}

/// The remembered addresses of `host`, the newest first.
pub fn remembered(host: &str) -> Vec<Remembered> {
    resolver().memory().remembered(host)
}

/// The source of `addr`, when the dialer connected to it for `host` lately.
pub fn dialed(host: &str, addr: SocketAddr) -> Option<Source> {
    resolver().memory().dialed(host, addr)
}

/// The address of the last connection that the dialer made for `host`, and
/// its source.
pub fn last_dialed(host: &str) -> Option<(SocketAddr, Source)> {
    resolver().memory().last_dialed(host)
}

/// The addresses to try for `host:port`, from the first source that gives
/// any; the error names every source that was tried.
pub async fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    resolve_from(host, port, deadline, None).await.map(|found| found.addrs)
}

/// The addresses of the first source after `after` that gives any.
pub async fn resolve_from(host: &str, port: u16, deadline: Instant, after: Option<Source>) -> Result<Found, String> {
    resolver().find(host, port, deadline, after).await
}

/// The resolvers of DNS over HTTPS, in the order asked.
pub fn doh_resolvers() -> Vec<Doh> {
    resolver().settings().resolvers.clone()
}

/// One resolver, straight at its address, as `podssh doctor` asks it: the
/// addresses and the form that gave them, or why none came, with how its
/// connection ended (T-604).
pub async fn doh_ask_kept(doh: &Doh, host: &str, deadline: Instant) -> Result<(Vec<IpAddr>, Form), Missed> {
    let resolver = resolver();
    match resolver.way() {
        Some(way) => way.ask(doh, host, deadline).await,
        None => Err(Missed::words(format!("{}: DNS over HTTPS is not asked", doh.ip))),
    }
}

/// The SRV records of `name`, from the resolvers in turn, through `proxy`
/// when one is set, as podssh reaches anything else (T-339): through a proxy
/// that resolves names, each resolver by its name first (T-405).
pub async fn doh_srv(name: &str, proxy: &ProxyChoice, deadline: Instant) -> Result<Vec<Srv>, String> {
    let resolver = resolver();
    let dial = crate::dial::dialer(proxy, false);
    way(&resolver, &dial).srv(name, deadline).await
}

/// The ECH list of `name`'s HTTPS record, from the resolvers in turn through
/// `proxy` (T-642): pod-dns's reader of ECH lists for `pod-tls`.
pub async fn doh_https(
    name: &str,
    proxy: &ProxyChoice,
    deadline: Instant,
) -> Result<Option<pod_tls::ech::Published>, String> {
    let resolver = resolver();
    let dial = crate::dial::dialer(proxy, false);
    pod_tls::ech::Records::ech_list(&way(&resolver, &dial), name, deadline).await
}

/// The way to the resolvers of `resolver` through `dial`, with the TLS of the
/// process.
fn way<'a>(resolver: &'a pod_dns::Resolver, dial: &'a pod_proxy::Dialer) -> Way<'a> {
    Way { settings: resolver.settings(), context: crate::tls::context(), dial }
}
