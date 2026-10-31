//! The DERP servers that a node may call home: Tailscale's fleet for
//! tailcat, which needs no account (https://tailcat.dev/derpmap.json, read
//! on 2026-10-31: four regions, one server each), or those of
//! [`ENV`], a derper of the user's own. The home is the first of the list
//! whose probe answers through the proxy, as the iroh road picks its home
//! relay; a client tries the server of the ticket first, then the others
//! of the fleet, as a node whose home went away calls the next one home.

use std::fmt;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use tokio::time::Instant;

/// The servers of tailcat's map, in the order of its regions: New York,
/// San Francisco, Frankfurt and Tokyo.
pub const TAILCAT: &[&str] = &["tc301a.ipn.dev", "tc302a.ipn.dev", "tc303a.ipn.dev", "tc304a.ipn.dev"];
/// The variable that names the servers in place of the fleet:
/// `HOST[:PORT][,...]`.
pub const ENV: &str = "PODSSH_DERP_SERVER";
/// derper's probe of latency (tailscale/tailscale:cmd/derper/derper.go at
/// v1.104.4): an empty answer to a GET.
pub const PROBE_PATH: &str = "/derp/probe";
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
        self.port == PORT && TAILCAT.contains(&self.host.as_str())
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

/// Tailscale's servers for tailcat.
pub fn fleet() -> Vec<Server> {
    TAILCAT.iter().map(|host| Server { host: (*host).to_string(), port: PORT }).collect()
}

/// The servers of `flag`, else of [`ENV`], else the fleet; and whether the
/// user named them.
pub fn from_environment(flag: Option<&str>) -> Result<(Vec<Server>, bool), String> {
    let named = flag.map(str::to_string).or_else(|| std::env::var(ENV).ok().filter(|v| !v.trim().is_empty()));
    let Some(list) = named else { return Ok((fleet(), false)) };
    let servers = list.split(',').map(Server::parse).collect::<Result<Vec<_>, _>>()?;
    Ok((servers, true))
}

/// The servers that a client tries for a node whose home is `home`: it
/// first, then the rest of the fleet when it is of the fleet, as the node
/// calls the next one home when its own goes away.
pub fn for_client(home: &Server) -> Vec<Server> {
    let mut servers = vec![home.clone()];
    if home.in_fleet() {
        servers.extend(fleet().into_iter().filter(|server| server != home));
    }
    servers
}

/// derper's probe at `server`, through `proxy`: how long its answer took, or
/// why none came.
pub async fn probe(server: &Server, trust: &Trust, proxy: &ProxyChoice) -> Result<Duration, String> {
    let started = Instant::now();
    let get = podssh_ws::client::https_get(&server.host, server.port, PROBE_PATH, 1024, trust, proxy, PROBE_LIMIT);
    match tokio::time::timeout(PROBE_LIMIT, get).await {
        Err(_) => Err(format!("{server} did not answer {PROBE_PATH} within {} s", PROBE_LIMIT.as_secs())),
        Ok(Ok(answer)) if (200..300).contains(&answer.status) => Ok(started.elapsed()),
        Ok(Ok(answer)) => Err(format!("{server} answered {PROBE_PATH} with HTTP {}", answer.status)),
        Ok(Err(e)) => Err(format!("{server}: {e}")),
    }
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
        let fleet = fleet();
        assert_eq!(fleet.len(), 4);
        assert!(fleet.iter().all(Server::in_fleet));
        let tokyo = Server::parse("tc304a.ipn.dev").unwrap();
        let order = for_client(&tokyo);
        assert_eq!(order[0], tokyo);
        assert_eq!(order.len(), 4);
        let own = Server::parse("derp.example.org").unwrap();
        assert_eq!(for_client(&own), vec![own]);
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
