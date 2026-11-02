//! `--vless FILE` (T-440, the operator's ruling Q66): VLESS servers that the
//! user runs (Xray-core, shoes, sing-box), in place of the relay, so that a
//! server of the user's own is a road with no relay. FILE is private, as a
//! pair file is (`podssh_relay::cache::read_private`): each line is a share
//! link, `vless://ID@HOST:PORT?type=ws|xhttp&security=tls&...`, whose ID never
//! goes to argv, a log or a message; `#` starts a comment. The servers are
//! tried in the order of the file, as the relay hosts are (T-220). The stream
//! goes over a WebSocket, or over XHTTP's plain requests on HTTP/2, which pass
//! where a proxy or a front end refuses the upgrade (`podssh_ws::vless`). The
//! host key of SSH protects the session, as on each road: the server sees the
//! target's name and SSH's encrypted bytes.

pub mod pipe;
pub mod reach;

use std::path::Path;

use podssh_ws::vless::Server;
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Resolved, Transport};

/// The servers of a run, in the order of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub servers: Vec<Server>,
}

/// The file of `--vless`: refused (78) when it is not this user's private
/// file, or when a line cannot go.
pub fn read(path: &str) -> Result<Servers, Refusal> {
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("--vless: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, path).map_err(Refusal::config)
}

/// The lines of the file named `file`. A refusal names the file and the
/// line's number, never the line: it holds an ID.
pub fn parse(text: &str, file: &str) -> Result<Servers, String> {
    let mut servers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        servers.push(Server::parse(line).map_err(|why| format!("--vless {file}:{}: {why}", i + 1))?);
    }
    if servers.is_empty() {
        return Err(format!("--vless {file}: it has no vless:// line"));
    }
    Ok(Servers { servers })
}

/// The flag of another road beside `--vless`, if one is given.
fn other_road(args: &SshArgs) -> Option<&'static str> {
    let flags = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The road of a run that resolved to the relay: the servers of the file
/// when `--vless` names one, with the relay's trust for their TLS; else the
/// road as it was. `-4` and `-6` choose the family that the relay dials,
/// and a server dials as it chooses.
pub fn or_relay(args: &SshArgs, transport: Transport) -> Result<Transport, Refusal> {
    let Some(path) = args.vless.as_deref() else { return Ok(transport) };
    let (trust, family) = match transport {
        Transport::Relay { trust, family, .. } => (trust, family),
        // A road of its own: `check` names it.
        other => return Ok(other),
    };
    if let Some(flag) = other_road(args) {
        return Err(Refusal::usage(format!("--vless and {flag} name two roads; a run has one")));
    }
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a VLESS server dials as it chooses",
        ));
    }
    Ok(Transport::Vless { servers: read(path)?, trust })
}

/// `--vless` beside a road of its own, which [`or_relay`] never took: a
/// usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.vless.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Vless { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Via { .. } => "--via",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
    };
    Err(Refusal::usage(format!("--vless cannot go with {other}, which is a road of its own; a run has one road")))
}

/// The servers that `podssh doctor --vless FILE` checks.
pub fn for_doctor(path: Option<&str>) -> Result<Option<Servers>, Refusal> {
    path.map(read).transpose()
}

/// The trust of the servers' TLS: `--ca-file`, else `SSL_CERT_FILE` or
/// `CaFile`, else podssh's default stores, as the relay's.
pub fn trust(ca_file: Option<&str>) -> Trust {
    crate::settings::ca_file(ca_file).map_or(Trust::Default, |file| Trust::File(file.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from its parts: a scanner of secrets takes a whole link with an
    // ID for a credential.
    fn line(rest: &str) -> String {
        ["vless://550e8400-e29b-41d4", "-a716-446655440000@", rest, "\n"].concat()
    }

    #[test]
    fn a_file_holds_links_and_comments_and_a_refusal_names_the_line_never_its_id() {
        let (first, second) = (line("a.example:443?type=ws&security=tls"), line("b.example:443?type=xhttp"));
        let text = format!("# mine\n\n{first}{second}");
        let servers = parse(&text, "v.list").unwrap();
        assert_eq!(servers.servers.len(), 2);
        assert_eq!(servers.servers[1].shown(), "vless://b.example:443/");
        assert!(!format!("{servers:?}").contains("550e8400"));
        let bad = parse(&format!("\n{}", line("a.example:443?type=ws&flow=xtls-rprx-vision")), "f").unwrap_err();
        assert!(bad.starts_with("--vless f:2: flow=") && !bad.contains("550e8400"), "{bad}");
        let other = parse("vmess://secret\n", "f").unwrap_err();
        assert!(other.starts_with("--vless f:1: a line is vless://") && !other.contains("secret"), "{other}");
        assert!(parse("# only\n", "f").unwrap_err().contains("no vless:// line"));
    }
}
