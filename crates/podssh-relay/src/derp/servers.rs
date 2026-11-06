//! The DERP servers that a node may call home: Tailscale's fleet for
//! tailcat, which needs no account (https://tailcat.dev/derpmap.json, read
//! on 2026-10-31: four regions, one server each), then Tailscale's main
//! fleet, which serves Tailscale's own clients and let podssh in when it
//! was tried (the operator's ruling Q74, T-534) unless [`MAIN_ENV`] says
//! no; or those of [`ENV`], a derper of the user's own. The home is the first of the list
//! whose probe answers through the proxy, as the iroh road picks its home
//! relay; a client tries the server of the ticket first, then the others
//! of the fleet, as a node whose home went away calls the next one home.

use std::fmt;
use std::time::Duration;

use podssh_ws::{Cut, ProxyChoice, Trust};
use tokio::time::Instant;

/// tailcat's DERP: the service `tailcat-derp` of `pod-services`.
fn tailcat_derp() -> &'static pod_services::Service {
    pod_services::get("tailcat-derp").expect("pod-services holds the service tailcat-derp")
}

/// The servers of tailcat's map, in the order of its regions: New York,
/// San Francisco, Frankfurt and Tokyo (the endpoints of the role `region`).
pub fn tailcat() -> Vec<&'static str> {
    tailcat_derp().endpoints_of("region").map(|e| e.host()).collect()
}
/// The variable that names the servers in place of the fleet:
/// `HOST[:PORT][,...]`.
pub const ENV: &str = "PODSSH_DERP_SERVER";
/// The variable that keeps tailcat's four alone: `no`.
pub const MAIN_ENV: &str = "PODSSH_DERP_MAIN";

/// Tailscale's main fleet: the service `tailscale-derp` of `pod-services`.
fn main_derp() -> &'static pod_services::Service {
    pod_services::get("tailscale-derp").expect("pod-services holds the service tailscale-derp")
}

/// The servers of Tailscale's main fleet: the first of each region in the
/// order of the regions' ids, then the others in the same order, so that a
/// node in a cage probes one server of a region before the next region.
pub fn main_fleet() -> Vec<Server> {
    let all = main_derp().endpoints();
    let first = |e: &&pod_services::Endpoint| e.name().ends_with("-1");
    let ordered = all.iter().filter(first).chain(all.iter().filter(|e| !first(e)));
    ordered.map(|e| Server { host: e.host().to_ascii_lowercase(), port: e.port() }).collect()
}

/// Whether the main fleet follows tailcat's, by the value of [`MAIN_ENV`]:
/// unset, empty or yes, it does; no keeps tailcat's four alone.
pub fn main_wanted(value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else { return Ok(true) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Ok(true),
        "no" | "off" | "false" | "0" => Ok(false),
        _ => Err(format!("{MAIN_ENV}={value}: yes or no")),
    }
}
/// derper's probe of latency (tailscale/tailscale:cmd/derper/derper.go): an
/// empty answer to a GET; the fact `probe-path`.
pub fn probe_path() -> &'static str {
    tailcat_derp().text("probe-path").expect("tailcat-derp of pod-services holds the fact probe-path")
}
/// The bound of each probe, its connection included.
pub const PROBE_LIMIT: Duration = Duration::from_secs(5);
/// The port of a server that names none.
pub const PORT: u16 = 443;

/// A DERP server: the name that its certificate holds, and its HTTPS port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

impl Server {
    pub fn new(host: &str, port: u16) -> Result<Server, String> {
        podssh_ws::names::check_host(host)?;
        if port == 0 {
            return Err("port 0 is not a port".into());
        }
        Ok(Server { host: host.to_ascii_lowercase(), port })
    }

    /// `HOST` or `HOST:PORT`, also after `https://` and with a `/` after.
    pub fn parse(text: &str) -> Result<Server, String> {
        let word = text.trim();
        let word = word.strip_prefix("https://").unwrap_or(word);
        let word = word.strip_suffix('/').unwrap_or(word);
        let (host, port) = match word.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) => (host, port),
                Err(_) => return Err(format!("{text:?}: {port:?} is not a port")),
            },
            None => (word, PORT),
        };
        Server::new(host, port).map_err(|why| format!("{text:?}: {why}"))
    }

    /// `HOST:PORT`, as a `Host` header names it.
    pub fn authority(&self) -> String {
        podssh_ws::dial::authority(&self.host, self.port)
    }

    /// Whether this is a server of tailcat's fleet.
    pub fn in_fleet(&self) -> bool {
        self.port == PORT && tailcat().contains(&self.host.as_str())
    }

    /// The fleet that this server is of, in a line's words; `None` for a
    /// server of the user's own.
    pub fn fleet_name(&self) -> Option<&'static str> {
        if self.in_fleet() {
            Some(TAILCAT_FLEET)
        } else if main_fleet().contains(self) {
            Some(MAIN_FLEET)
        } else {
            None
        }
    }

    /// The words after this server in a line: its fleet, and for the main
    /// fleet what it is and how to keep to tailcat's.
    pub fn fleet_note(&self) -> String {
        match self.fleet_name() {
            Some(MAIN_FLEET) => format!(
                ", of {MAIN_FLEET}, which serves Tailscale's own clients and which podssh tries after tailcat's four \
                 ({MAIN_ENV}=no keeps to those)"
            ),
            Some(fleet) => format!(", of {fleet}"),
            None => String::new(),
        }
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            PORT => f.write_str(&self.host),
            port => write!(f, "{}:{port}", self.host),
        }
    }
}

/// The words of tailcat's fleet in a line.
pub const TAILCAT_FLEET: &str = "Tailscale's tailcat fleet";
/// The words of the main fleet in a line.
pub const MAIN_FLEET: &str = "Tailscale's main fleet";

/// Tailscale's servers for tailcat.
pub fn tailcat_fleet() -> Vec<Server> {
    tailcat().into_iter().map(|host| Server { host: host.to_string(), port: PORT }).collect()
}

/// The fleet of the road: tailcat's four, then the main fleet when `main`.
pub fn fleet_with(main: bool) -> Vec<Server> {
    let mut servers = tailcat_fleet();
    if main {
        servers.extend(main_fleet());
    }
    servers
}

/// The fleet of the road, by [`MAIN_ENV`]; a value that is neither yes nor
/// no keeps the main fleet, as [`from_environment`] refuses it before.
pub fn fleet() -> Vec<Server> {
    fleet_with(main_wanted(std::env::var(MAIN_ENV).ok().as_deref()).unwrap_or(true))
}

/// The servers of `flag`, else of [`ENV`], else the fleet; and whether the
/// user named them. A value of [`MAIN_ENV`] that is neither yes nor no is
/// refused.
pub fn from_environment(flag: Option<&str>) -> Result<(Vec<Server>, bool), String> {
    let named = flag.map(str::to_string).or_else(|| std::env::var(ENV).ok().filter(|v| !v.trim().is_empty()));
    let Some(list) = named else {
        let main = main_wanted(std::env::var(MAIN_ENV).ok().as_deref())?;
        return Ok((fleet_with(main), false));
    };
    let servers = list.split(',').map(Server::parse).collect::<Result<Vec<_>, _>>()?;
    Ok((servers, true))
}

/// The servers that a client tries for a node whose home is `home`: it
/// first, then the rest of the fleet when it is of the fleet, as the node
/// calls the next one home when its own goes away.
pub fn for_client(home: &Server) -> Vec<Server> {
    for_client_in(home, &fleet())
}

/// [`for_client`] with the client's own list in place of the fleet (T-379):
/// `home` first, then the rest of `list` when `home` is of it, in the
/// list's order, which is the order in which a node of that list moves.
pub fn for_client_in(home: &Server, list: &[Server]) -> Vec<Server> {
    let mut servers = vec![home.clone()];
    if list.contains(home) {
        servers.extend(list.iter().filter(|server| *server != home).cloned());
    }
    servers
}

/// Why a probe got no answer: the words, and how the connection ended
/// where an error of I/O or the bound ended it, which `podssh doctor` reads
/// (T-487); an answer of another status has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub why: String,
    pub cut: Option<Cut>,
}

/// derper's probe at `server`, through `proxy`: how long its answer took, or
/// why none came.
pub async fn probe(server: &Server, trust: &Trust, proxy: &ProxyChoice) -> Result<Duration, String> {
    probe_kept(server, trust, proxy).await.map_err(|missed| missed.why)
}

/// [`probe`], with the cut of a failure beside its words.
pub async fn probe_kept(server: &Server, trust: &Trust, proxy: &ProxyChoice) -> Result<Duration, Missed> {
    let started = Instant::now();
    let get = podssh_ws::client::https_get(&server.host, server.port, probe_path(), 1024, trust, proxy, PROBE_LIMIT);
    let missed = |why: String, cut: Option<Cut>| Err(Missed { why, cut });
    match tokio::time::timeout(PROBE_LIMIT, get).await {
        Err(_) => missed(
            format!("{server} did not answer {} within {} s", probe_path(), PROBE_LIMIT.as_secs()),
            Some(Cut::TimedOut),
        ),
        Ok(Ok(answer)) if (200..300).contains(&answer.status) => Ok(started.elapsed()),
        Ok(Ok(answer)) => missed(format!("{server} answered {} with HTTP {}", probe_path(), answer.status), None),
        Ok(Err(e)) => missed(format!("{server}: {e}"), e.cut()),
    }
}

/// [`probe`] of owned values, for a search that probes one server after
/// another (`far::home`): whether it answered.
pub async fn answers(server: Server, trust: Trust, proxy: ProxyChoice) -> Result<(), String> {
    probe(&server, &trust, &proxy).await.map(|_| ())
}

/// The first of `servers` whose probe answers, in their order; and why each
/// one before it did not.
pub async fn home(servers: &[Server], trust: &Trust, proxy: &ProxyChoice) -> (Option<Server>, Vec<String>) {
    let mut missed = Vec::new();
    for server in servers {
        match probe(server, trust, proxy).await {
            Ok(_) => return (Some(server.clone()), missed),
            Err(why) => missed.push(why),
        }
    }
    (None, missed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_is_read_with_or_without_its_port_and_scheme() {
        assert_eq!(Server::parse("tc301a.ipn.dev"), Ok(Server { host: "tc301a.ipn.dev".into(), port: 443 }));
        assert_eq!(Server::parse("https://DERP.example.org:8443/").unwrap().to_string(), "derp.example.org:8443");
        assert_eq!(Server::parse("127.0.0.1:3340").unwrap().authority(), "127.0.0.1:3340");
        assert!(Server::parse("derp.example.org:x").is_err());
        assert!(Server::parse("derp.example.org:0").is_err());
        assert!(Server::parse("bad host").is_err());
        assert!(Server::parse("").is_err());
    }

    #[test]
    fn the_fleet_is_tailcat_s_four_and_a_client_tries_its_ticket_s_server_first() {
        let fleet = tailcat_fleet();
        assert_eq!(fleet.len(), 4);
        assert!(fleet.iter().all(Server::in_fleet));
        assert_eq!(fleet_with(false), fleet, "{MAIN_ENV}=no keeps tailcat's four alone");
        let tokyo = Server::parse("tc304a.ipn.dev").unwrap();
        let order = for_client_in(&tokyo, &fleet);
        assert_eq!(order[0], tokyo);
        assert_eq!(order.len(), 4);
        let own = Server::parse("derp.example.org").unwrap();
        assert_eq!(for_client(&own), vec![own]);
    }

    #[test]
    fn the_main_fleet_follows_tailcat_s_one_server_of_each_region_first() {
        let main = main_fleet();
        let all = fleet_with(true);
        assert_eq!(all[..4], tailcat_fleet()[..], "tailcat's four first (Q74)");
        assert_eq!(all[4..], main[..]);
        assert!(main.len() > 28 && main.iter().all(|s| s.port == PORT && !s.in_fleet()));
        // The first of each region, in the order of the regions, then the rest.
        let regions = main_derp().endpoints().iter().filter(|e| e.name().ends_with("-1")).count();
        assert!(regions >= 20, "{regions} regions");
        let firsts: Vec<&str> = main[..regions].iter().map(|s| s.host.as_str()).collect();
        assert_eq!(firsts[0], main_derp().endpoint("nyc-1").unwrap().host(), "New York's first, region 1");
        let named = |name: &str| main_derp().endpoint(name).map(|e| e.host().to_string());
        assert_eq!(Some(main[regions].host.clone()), named("nyc-2"), "then the second of region 1");
        assert_eq!(main[1].fleet_name(), Some(MAIN_FLEET));
        assert_eq!(all[0].fleet_name(), Some(TAILCAT_FLEET));
        assert_eq!(Server::parse("derp.example.org").unwrap().fleet_name(), None);
        // A client of a home of the main fleet: it, then the rest in order.
        let order = for_client_in(&main[3], &all);
        assert_eq!((order[0].clone(), order[1].clone(), order.len()), (main[3].clone(), all[0].clone(), all.len()));
    }

    #[test]
    fn podssh_derp_main_is_yes_or_no() {
        for on in [None, Some(""), Some("yes"), Some("ON"), Some("1")] {
            assert_eq!(main_wanted(on), Ok(true), "{on:?}");
        }
        for off in ["no", "Off", "false", "0"] {
            assert_eq!(main_wanted(Some(off)), Ok(false), "{off}");
        }
        assert!(main_wanted(Some("maybe")).unwrap_err().starts_with("PODSSH_DERP_MAIN=maybe"));
    }

    #[test]
    fn a_client_s_own_list_follows_the_ticket_s_server_when_it_holds_that_server() {
        let list: Vec<Server> = ["a.example.org", "b.example.org:8443", "c.example.org"]
            .iter()
            .map(|s| Server::parse(s).unwrap())
            .collect();
        let shown = |servers: Vec<Server>| servers.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(shown(for_client_in(&list[1], &list)), ["b.example.org:8443", "a.example.org", "c.example.org"]);
        let other = Server::parse("d.example.org").unwrap();
        assert_eq!(for_client_in(&other, &list), vec![other], "a home of no list is tried alone");
    }

    #[test]
    fn the_flag_names_the_servers_in_place_of_the_fleet() {
        let (servers, named) = from_environment(Some("a.example.org,b.example.org:8443")).unwrap();
        assert!(named);
        let shown: Vec<String> = servers.iter().map(ToString::to_string).collect();
        assert_eq!(shown, ["a.example.org", "b.example.org:8443"]);
        assert!(from_environment(Some("a.example.org,,")).is_err());
    }
}
