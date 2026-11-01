//! `--shadowsocks FILE` (T-373, GitHub #62): a road through Shadowsocks
//! servers that the user names, in place of the relay. FILE is private, as a
//! pair file is (`podssh_relay::cache::read_private`): its `ss://` lines hold
//! passwords, which never go to argv, a log or a message. Each line is an
//! `ss://` URI, or `subscription URL`, a list that a provider serves over
//! TLS ([`subscription`]); `#` starts a comment. The servers are tried in
//! the order of the file, as the relay hosts are (T-220), and a
//! subscription's list in its own order ([`order`]). The host key of SSH
//! protects the session, as on each road: the server sees the target's
//! name and the encrypted bytes of SSH.

pub mod order;
pub mod pipe;
pub mod reach;
pub mod subscription;

use std::path::Path;

use podssh_ws::shadowsocks::Node;
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Resolved, Transport};
pub use subscription::Subscription;

/// One line of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Node(Node),
    Subscription(Subscription),
}

/// The servers of a run, in the order of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub entries: Vec<Entry>,
}

/// The file of `--shadowsocks`: refused (78) when it is not this user's
/// private file, or when a line cannot go.
pub fn read(path: &str) -> Result<Servers, Refusal> {
    let text = podssh_relay::cache::read_private(Path::new(path))
        .map_err(|why| Refusal::config(format!("--shadowsocks: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, path).map_err(Refusal::config)
}

/// The lines of the file named `file`. A refusal names the file and the
/// line's number, never the line: it may hold a password.
pub fn parse(text: &str, file: &str) -> Result<Servers, String> {
    let mut entries = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let at = format!("--shadowsocks {file}:{}", i + 1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.get(..5).is_some_and(|scheme| scheme.eq_ignore_ascii_case("ss://")) {
            entries.push(Entry::Node(Node::parse(line).map_err(|why| format!("{at}: {why}"))?));
            continue;
        }
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some(word), Some(url), None) if word.eq_ignore_ascii_case("subscription") => {
                let list = Subscription::parse(url).map_err(|why| format!("{at}: {why}"))?;
                entries.push(Entry::Subscription(list));
            }
            _ => return Err(format!("{at}: a line is ss://..., subscription https://..., or a # comment")),
        }
    }
    if entries.is_empty() {
        return Err(format!("--shadowsocks {file}: it has no ss:// line and no subscription"));
    }
    Ok(Servers { entries })
}

/// The relay's flag on the command line, if one is given beside the flag.
fn relay_flag(args: &SshArgs) -> Option<&'static str> {
    let flags = [("--relay-host", args.relay_host.is_some()), ("--relay-failover", args.relay_failover.is_some())];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The road of a run that resolved to the relay: the servers of the file
/// when `--shadowsocks` names one, with the relay's trust for a
/// subscription's TLS; else the road as it was. `-4` and `-6` choose the
/// family that the relay dials, and a server dials as it chooses.
pub fn or_relay(args: &SshArgs, transport: Transport) -> Result<Transport, Refusal> {
    let Some(path) = args.shadowsocks.as_deref() else { return Ok(transport) };
    let (trust, family) = match transport {
        Transport::Relay { trust, family, .. } => (trust, family),
        // A road of its own, or the forwarders: `check` names it.
        other => return Ok(other),
    };
    if let Some(flag) = relay_flag(args) {
        return Err(Refusal::usage(format!("--shadowsocks and {flag} name two roads; a run has one")));
    }
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a Shadowsocks server dials as it chooses",
        ));
    }
    Ok(Transport::Shadowsocks { servers: read(path)?, trust })
}

/// `--shadowsocks` beside a road of its own, which [`or_relay`] never
/// took: a usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.shadowsocks.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Shadowsocks { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
    };
    Err(Refusal::usage(format!("--shadowsocks cannot go with {other}, which is a road of its own; a run has one road")))
}

/// The servers that `podssh doctor --shadowsocks FILE` checks, with the
/// trust of its TLS.
pub fn for_doctor(path: Option<&str>) -> Result<Option<Servers>, Refusal> {
    path.map(read).transpose()
}

/// The trust of a subscription's TLS: `--ca-file`, else `SSL_CERT_FILE` or
/// `CaFile`, else podssh's default stores, as the relay's.
pub fn trust(ca_file: Option<&str>) -> Trust {
    crate::settings::ca_file(ca_file).map_or(Trust::Default, |file| Trust::File(file.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_holds_ss_lines_subscriptions_and_comments_and_a_refusal_hides_the_line() {
        let text = "# mine\n\nss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#one\n\
                    Subscription https://sub.example/list?token=SECRET\n";
        let servers = parse(text, "ss.list").unwrap();
        assert_eq!(servers.entries.len(), 2);
        let Entry::Subscription(list) = &servers.entries[1] else { panic!("{servers:?}") };
        assert_eq!(list.shown(), "https://sub.example/...");
        assert!(!format!("{servers:?}").contains("SECRET") && !format!("{servers:?}").contains("test"));
        // Built from its parts: a secret scanner takes a URI with a user and
        // a password, written whole in a source, for a credential.
        let bad = parse(&["ss://aes-256-gcm", ":hunter2", "@h.example\n"].concat(), "f").unwrap_err();
        assert!(bad.starts_with("--shadowsocks f:1: ") && !bad.contains("hunter2"), "{bad}");
        let other = parse("\n\nvmess://hunter2\n", "f").unwrap_err();
        assert!(other.starts_with("--shadowsocks f:3: a line is") && !other.contains("hunter2"), "{other}");
        assert!(parse("# only\n", "f").unwrap_err().contains("no ss:// line"));
        let plain = parse("subscription http://sub.example/list\n", "f").unwrap_err();
        assert!(plain.contains("over TLS"), "{plain}");
    }
}
