//! Bridges (T-385): relays that the directory does not list, which a user
//! names by bridge lines, as Tor gives them out. A line is a plain bridge
//! (`ADDRESS:PORT FINGERPRINT`), or one of the two transports that podssh
//! speaks itself, meek_lite and WebTunnel (`NAME ADDRESS FINGERPRINT
//! k=v...`); a leading `Bridge`, as in a torrc, is dropped. Arti asks each
//! line for the bridge's RSA fingerprint, so a line with none is refused
//! here, as is a transport that would be another program (obfs4,
//! snowflake): podssh starts none.
//!
//! In Arti's configuration ([`apply`]): the bridges in use, each of
//! podssh's transports as one that Arti does not manage, at its sentinel
//! ([`crate::transport`]), and the first hops on any address, as a bridge
//! of a transport has a dummy one that a rule of ports would drop. A
//! network's own file may name no transport ([`refuse_transports`]): one
//! with a `path` would be a program that Arti starts.

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, PtTransportName, TorClientConfigBuilder};
use tor_netdoc::types::policy::AddrPortPattern;

use crate::transport::Kind;

/// A bridge line that podssh can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    line: String,
    transport: Option<Kind>,
}

impl Bridge {
    /// A line of a bridge, or why podssh cannot use it. podssh's words
    /// repeat no part of the line but a transport's name: a bridge that is
    /// not public is a secret of sorts.
    pub fn parse(text: &str) -> Result<Bridge, String> {
        let mut words: Vec<&str> = text.split_ascii_whitespace().collect();
        if words.first().is_some_and(|w| w.eq_ignore_ascii_case("bridge")) {
            words.remove(0);
        }
        let Some(first) = words.first() else { return Err("an empty bridge line".into()) };
        let (transport, rest) = if first.contains(':') {
            (None, &words[1..])
        } else {
            let kind = Kind::by_name(first).ok_or_else(|| {
                let name = if first.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { *first } else { "?" };
                format!(
                    "the transport {name} is another program, which podssh does not start; podssh speaks meek_lite \
                     and webtunnel itself, and takes a plain bridge's ADDRESS:PORT FINGERPRINT"
                )
            })?;
            (Some(kind), words.get(2..).unwrap_or_default())
        };
        let fingerprint = rest.first().map(|w| w.trim_start_matches('$')).unwrap_or_default();
        if fingerprint.len() != 40 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("a bridge line needs the bridge's fingerprint, 40 hex digits after its address: Arti \
                        refuses a line without one"
                .into());
        }
        let line = words.join(" ");
        line.parse::<BridgeConfigBuilder>().map_err(|e| format!("Arti does not read the line: {e}"))?;
        let settings: Vec<(String, String)> =
            rest.iter().filter_map(|w| w.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        // The transport's arguments are read now, so that a bad one is said
        // before anything connects.
        match transport {
            Some(Kind::Meek) => {
                podssh_ws::meek::Args::parse(&settings)?;
            }
            Some(Kind::WebTunnel) => {
                podssh_ws::webtunnel::Args::parse(&settings)?;
            }
            None => {}
        }
        Ok(Bridge { line, transport })
    }

    /// The transport, or none for a plain bridge.
    pub fn transport(&self) -> Option<Kind> {
        self.transport
    }

    /// The line, with no leading `Bridge`.
    pub fn line(&self) -> &str {
        &self.line
    }
}

/// `1 bridge over meek_lite`, `2 bridges over meek_lite and webtunnel`:
/// for a line of podssh's, with no word of a bridge line.
pub fn summary(bridges: &[Bridge]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for bridge in bridges {
        let name = bridge.transport.map_or("plain TCP", Kind::name);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let over = match names.split_last() {
        Some((last, [])) => last.to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => "nothing".to_string(),
    };
    let plural = if bridges.len() == 1 { "" } else { "s" };
    format!("{} bridge{plural} over {over}", bridges.len())
}

/// Refuse a network's configuration that names a pluggable transport.
pub fn refuse_transports(network: &str) -> Result<(), String> {
    let table: toml::Table =
        toml::from_str(network).map_err(|e| format!("the network's configuration does not read: {e}"))?;
    let named = table.get("bridges").and_then(toml::Value::as_table).is_some_and(|b| b.contains_key("transports"));
    match named {
        true => Err("the network's configuration names a pluggable transport (bridges.transports), which Arti \
                     would run as another program; podssh starts none, and gives its own transports"
            .into()),
        false => Ok(()),
    }
}

/// Put `bridges` in `builder`: in use, with podssh's transports at their
/// sentinels, and the first hops on any address.
pub fn apply(builder: &mut TorClientConfigBuilder, bridges: &[Bridge]) -> Result<(), String> {
    let section = builder.bridges();
    section.enabled(BoolOrAuto::Explicit(true));
    let list = section.bridges();
    list.clear();
    for bridge in bridges {
        list.push(bridge.line.parse::<BridgeConfigBuilder>().map_err(|e| format!("a bridge line: {e}"))?);
    }
    let transports = section.transports();
    transports.clear();
    for kind in Kind::ALL {
        let name: PtTransportName = kind.name().parse().map_err(|e| format!("{}: {e}", kind.name()))?;
        let mut transport = TransportConfigBuilder::default();
        transport.protocols(vec![name]).proxy_addr(kind.at());
        transports.push(transport);
    }
    // A bridge of a transport has a dummy address, which a rule of ports
    // drops (tor-guardmgr filters bridges by `reachable_addrs`).
    let reachable = builder.path_rules().reachable_addrs();
    reachable.clear();
    reachable.push(AddrPortPattern::new_all());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0BAC39417268B96B9F514EF763FA6FBA1A788956";

    #[test]
    fn a_line_of_each_kind_is_read_with_or_without_bridge() {
        let meek = Bridge::parse(&format!("Bridge meek_lite 192.0.2.20:80 {FP} url=https://cdn.test/ front=www.test"))
            .unwrap();
        assert_eq!(meek.transport(), Some(Kind::Meek));
        assert!(meek.line().starts_with("meek_lite 192.0.2.20:80 "), "{}", meek.line());
        let tunnel = format!("webtunnel [2001:db8::1]:443 {FP} url=https://b.test/s ver=0.0.7");
        let tunnel = Bridge::parse(&tunnel).unwrap();
        assert_eq!(tunnel.transport(), Some(Kind::WebTunnel));
        let plain = Bridge::parse(&format!("bridge 192.0.2.83:443 ${FP}")).unwrap();
        assert_eq!(plain.transport(), None);
        assert_eq!(summary(std::slice::from_ref(&meek)), "1 bridge over meek_lite");
        assert_eq!(summary(&[meek, tunnel, plain]), "3 bridges over meek_lite, webtunnel and plain TCP");
    }

    #[test]
    fn a_line_with_no_fingerprint_another_program_or_a_bad_argument_is_refused() {
        // Tor Browser's meek line has no fingerprint.
        let shipped = "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net";
        assert!(Bridge::parse(shipped).unwrap_err().contains("fingerprint"));
        let obfs4 = Bridge::parse(&format!("obfs4 192.0.2.55:38114 {FP} cert=abc iat-mode=0")).unwrap_err();
        assert!(obfs4.contains("obfs4 is another program"), "{obfs4}");
        assert!(Bridge::parse(&format!("meek_lite 192.0.2.20:80 {FP} front=www.test")).is_err());
        assert!(Bridge::parse(&format!("webtunnel [2001:db8::1]:443 {FP} url=ftp://b.test/")).is_err());
        assert!(Bridge::parse("  ").is_err());
    }

    #[test]
    fn a_network_that_names_a_transport_is_refused() {
        let managed = "[bridges]\nbridges = []\n[[bridges.transports]]\nprotocols = [\"obfs4\"]\npath = \"/bin/sh\"\n";
        assert!(refuse_transports(managed).unwrap_err().contains("bridges.transports"));
        let inline = "[bridges]\ntransports = [{ protocols = [\"x\"], proxy_addr = \"127.0.0.1:9\" }]\n";
        assert!(refuse_transports(inline).is_err());
        assert_eq!(refuse_transports("[bridges]\nbridges = []\n[path_rules]\n"), Ok(()));
    }

    #[test]
    fn the_bridges_go_in_with_podssh_s_transports_and_any_first_hop() {
        let mut builder = TorClientConfigBuilder::default();
        builder.path_rules().reachable_addrs().push("*:443".parse().unwrap());
        let line = format!("meek_lite 192.0.2.20:80 {FP} url=https://cdn.test/ front=www.test");
        apply(&mut builder, &[Bridge::parse(&line).unwrap()]).unwrap();
        assert_eq!(builder.bridges().bridges().len(), 1);
        assert_eq!(builder.bridges().transports().len(), 2);
        assert_eq!(builder.path_rules().reachable_addrs().as_slice(), [AddrPortPattern::new_all()]);
        builder.build().expect("Arti takes the configuration");
    }
}
