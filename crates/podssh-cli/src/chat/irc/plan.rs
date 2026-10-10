//! The checks of `podssh chat --irc SERVER[:PORT] CHANNEL` that need no
//! network (T-252): the server and its port, the channel, the nick by the
//! grammar of IRC, and the flags of the roads, which do not go with it.

use crate::chat::args::ChatArgs;
use crate::relay_settings::Refusal;

/// The port of IRC over TLS.
pub const TLS_PORT: u16 = 6697;
/// The port of IRC in plain text.
pub const PLAIN_PORT: u16 = 6667;
/// The length of a nick that each server takes (RFC 2812); a nick of the
/// user's own may be longer, as most servers allow.
const SHORT_NICK: usize = 9;
const MAX_NICK: usize = 30;

/// Where the chat goes over IRC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcPlan {
    pub server: String,
    pub port: u16,
    /// TLS inside the relay stream; plain text only with `--irc-plaintext`.
    pub tls: bool,
    pub channel: String,
    /// TCP to the server, through `HTTPS_PROXY` when it is set, not the
    /// relay (`--direct`).
    pub direct: bool,
}

/// The checks of `--irc`, in order: the flags that do not go with it, the
/// server, then the channel that PEER names.
pub fn plan(args: &ChatArgs, server: &str, channel: &str) -> Result<IrcPlan, Refusal> {
    let roads = [
        ("--listen", args.listen),
        ("--iroh", args.iroh),
        ("--key", args.key.is_some()),
        ("--ephemeral-key", args.ephemeral_key),
        ("--allow", args.allow.is_some()),
        ("--client-key", args.client_key.is_some()),
        ("--node-key", args.node_key.is_some()),
        ("--pair-file", args.pair_file.is_some()),
        ("--iroh-relay", args.iroh_relay.is_some()),
    ];
    if let Some((flag, _)) = roads.iter().find(|(_, given)| *given) {
        return Err(Refusal::usage(format!(
            "{flag} is for the roads between two podssh ends; --irc talks in a channel of an IRC network"
        )));
    }
    if args.irc_plaintext && args.irc_ca_file.is_some() {
        return Err(Refusal::usage("--irc-ca-file is for the server's TLS, which --irc-plaintext turns off"));
    }
    let tls = !args.irc_plaintext;
    let (host, port) = server_and_port(server, if tls { TLS_PORT } else { PLAIN_PORT })?;
    check_channel(channel)?;
    Ok(IrcPlan { server: host, port, tls, channel: channel.to_string(), direct: args.direct })
}

/// `SERVER` or `SERVER:PORT` (`[IPV6]:PORT`), the port by default.
fn server_and_port(text: &str, default: u16) -> Result<(String, u16), Refusal> {
    let has_port = if text.starts_with('[') { text.contains("]:") } else { text.matches(':').count() == 1 };
    let (host, port) = if has_port {
        crate::proxy::parse_target(Some(text), None).map_err(|why| Refusal::usage(format!("--irc {text:?}: {why}")))?
    } else {
        let host = text.trim_start_matches('[').trim_end_matches(']');
        (host.to_string(), default)
    };
    podssh_relay::relay::check_target(&host).map_err(|why| Refusal::usage(format!("--irc {text:?}: {why}")))?;
    Ok((host, port))
}

/// A channel's name: `#` or `&` first, and none of the characters that end
/// it or list another.
fn check_channel(channel: &str) -> Result<(), Refusal> {
    let bad = |c: char| c.is_whitespace() || c.is_control() || matches!(c, ',' | '\u{7}');
    if !(channel.starts_with('#') || channel.starts_with('&')) || channel.len() < 2 || channel.chars().any(bad) {
        return Err(Refusal::usage(format!(
            "{channel:?} is not a channel: with --irc, PEER is a channel, as #name (quote it for the shell)"
        )));
    }
    Ok(())
}

/// The nick on IRC: `--nick`, else `PODSSH_NICK`, by the grammar of IRC;
/// else the user's account, made one, of 9 characters at most; else
/// `podssh`.
pub fn nick(given: Option<&str>) -> Result<String, Refusal> {
    if let Some(nick) = given {
        return valid(nick).then(|| nick.to_string()).ok_or_else(|| {
            Refusal::usage(format!("--nick {nick:?}: an IRC nick is a letter or one of []\\`_^{{|}} first, then those, digits and -, {MAX_NICK} at most"))
        });
    }
    if let Some(nick) = std::env::var("PODSSH_NICK").ok().filter(|n| !n.trim().is_empty()) {
        return valid(&nick).then(|| nick.clone()).ok_or_else(|| {
            Refusal::config(format!("PODSSH_NICK={nick:?}: not an IRC nick; --nick NICK gives another"))
        });
    }
    let account = ["USER", "LOGNAME", "USERNAME"].iter().find_map(|name| std::env::var(name).ok());
    Ok(account.map(|a| made_valid(&a)).filter(|n| valid(n)).unwrap_or_else(|| "podssh".to_string()))
}

fn special(c: char) -> bool {
    matches!(c, '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}')
}

/// The grammar of a nick (RFC 2812), with the length that servers allow
/// today.
pub fn valid(nick: &str) -> bool {
    let mut chars = nick.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || special(c));
    first_ok && nick.len() <= MAX_NICK && chars.all(|c| c.is_ascii_alphanumeric() || special(c) || c == '-')
}

/// An account name as a nick: each other character a `_`, a letter first,
/// and 9 characters at most.
fn made_valid(account: &str) -> String {
    let mut nick: String =
        account.chars().map(|c| if c.is_ascii_alphanumeric() || special(c) || c == '-' { c } else { '_' }).collect();
    if !nick.starts_with(|c: char| c.is_ascii_alphabetic() || special(c)) {
        nick.insert(0, 'p');
    }
    nick.chars().take(SHORT_NICK).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nick_follows_the_grammar_of_irc() {
        for good in ["ana", "bo_2", "[x]", "a-b", "Zed`"] {
            assert!(valid(good), "{good}");
        }
        for bad in ["", "2ana", "-x", "a b", "a.b", "é", &"n".repeat(31)] {
            assert!(!valid(bad), "{bad}");
        }
        assert_eq!(made_valid("John Doe"), "John_Doe");
        assert_eq!(made_valid("1user.name"), "p1user_na");
        assert!(valid(&made_valid("ünï")));
    }

    #[test]
    fn a_server_has_the_port_of_its_mode_unless_it_names_one() {
        assert_eq!(server_and_port("irc.example.org", 6697).unwrap(), ("irc.example.org".into(), 6697));
        assert_eq!(server_and_port("irc.example.org:7000", 6697).unwrap(), ("irc.example.org".into(), 7000));
        assert_eq!(server_and_port("[2001:db8::1]:6697", 6667).unwrap(), ("2001:db8::1".into(), 6697));
        assert!(server_and_port("irc.example.org:x", 6697).is_err());
    }

    #[test]
    fn a_channel_starts_with_its_sign_and_holds_no_separator() {
        assert!(check_channel("#podssh").is_ok() && check_channel("&local").is_ok());
        for bad in ["podssh", "#", "#a b", "#a,b"] {
            assert!(check_channel(bad).is_err(), "{bad}");
        }
    }
}
