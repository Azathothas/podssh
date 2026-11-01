//! `--forwarder TEMPLATES` (T-369): a road through WebSocket forwarders of
//! other products, which take the target from the client, in place of the
//! relay. The user names each one, as a proxy in `ALL_PROXY`: a template of
//! `podssh_ws::forwarder`, or a list of them, tried in order, as the relay
//! hosts are. They come from `--forwarder`, else `PODSSH_FORWARDER`, else
//! `Forwarder` of the settings file (T-048), each only where nothing at its
//! level or above names another road: a run has one road. No token goes on
//! this road, and no `/v1/mint`, `/relays.json` or pool is asked. A word
//! names a forwarder that the binary carries (`mudlet`, T-370), and those
//! are the fallback when each relay host failed ([`fallback`]).

pub mod fallback;
pub mod pipe;
pub mod reach;

use podssh_ws::forwarder::builtin::{self, Builtin};
use podssh_ws::forwarder::Template;

use crate::relay_settings::Refusal;
use crate::settings::Defaults;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Env, Resolved, Transport};

/// The variable of the forwarders.
pub const FORWARDER_ENV: &str = "PODSSH_FORWARDER";

/// A forwarder of a run: its template, and its name in each line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarder {
    pub template: Template,
    pub name: String,
}

impl Forwarder {
    fn of(template: Template) -> Forwarder {
        let name = template.shown().to_string();
        Forwarder { template, name }
    }

    /// A forwarder that the binary names, by its word and its URL.
    fn named(b: &Builtin) -> Result<Forwarder, String> {
        let template = Template::parse(b.template)?;
        let name = format!("{} ({})", b.word, template.shown());
        Ok(Forwarder { template, name })
    }

    /// A template, or the word of a forwarder that the binary names. A
    /// word that is none is not shown: it may be a mistyped URL whose query
    /// holds a secret.
    fn parse(item: &str) -> Result<Forwarder, String> {
        if item.contains("://") {
            return Template::parse(item).map(Forwarder::of);
        }
        let words = builtin::words();
        let b = builtin::lookup(item)
            .ok_or_else(|| format!("a forwarder is a ws:// or wss:// template, or one of the words {words}"))?;
        Forwarder::named(b)
    }
}

/// The forwarders that the binary names, in the order of the fallback.
pub fn builtins() -> Vec<Forwarder> {
    builtin::BUILTIN.iter().filter_map(|b| Forwarder::named(b).ok()).collect()
}

/// A list of forwarders: templates and words separated by commas, in
/// order, each once; a comma inside a template is written %2C. An empty
/// list is refused.
pub fn parse_list(text: &str) -> Result<Vec<Forwarder>, String> {
    let mut out: Vec<Forwarder> = Vec::new();
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let forwarder = Forwarder::parse(item)?;
        if !out.contains(&forwarder) {
            out.push(forwarder);
        }
    }
    if out.is_empty() {
        return Err("no forwarder in the list".into());
    }
    Ok(out)
}

/// The forwarders of a run: `flag` (64 when it is bad, or when `named`, a
/// flag of another road, is given too); else, with no such flag, the
/// variable (78), refused beside `PODSSH_RELAY` (`relay_env`); else the
/// settings file's `Forwarder` (78), when `PODSSH_RELAY` is not set either.
pub fn choose(
    flag: Option<&str>,
    named: Option<&str>,
    env: Option<String>,
    relay_env: bool,
    file: &Defaults,
) -> Result<Option<Vec<Forwarder>>, Refusal> {
    match (flag, named) {
        (Some(_), Some(other)) => Err(Refusal::usage(format!("--forwarder and {other} name two roads; a run has one"))),
        (Some(text), None) => parse_list(text).map(Some).map_err(|why| Refusal::usage(format!("--forwarder: {why}"))),
        (None, Some(_)) => Ok(None),
        (None, None) => from_environment(env, relay_env, file),
    }
}

/// `PODSSH_FORWARDER`, else `Forwarder` of the settings file; none when
/// the relay's variable names the road.
fn from_environment(env: Option<String>, relay_env: bool, file: &Defaults) -> Result<Option<Vec<Forwarder>>, Refusal> {
    let relay = podssh_relay::relay::RELAY_ENV;
    if let Some(value) = env.filter(|v| !v.trim().is_empty()) {
        if relay_env {
            return Err(Refusal::config(format!("{FORWARDER_ENV} and {relay} name two roads; a run has one")));
        }
        return parse_list(&value).map(Some).map_err(|why| Refusal::config(format!("{FORWARDER_ENV}: {why}")));
    }
    match (&file.forwarder, relay_env) {
        (Some(value), false) => {
            file.check()?;
            parse_list(&value.text).map(Some).map_err(|why| Refusal::config(format!("{}: Forwarder {why}", value.at)))
        }
        _ => Ok(None),
    }
}

/// The variable of the process, read as each road reads its own.
fn env_value() -> Option<String> {
    std::env::var(FORWARDER_ENV).ok()
}

/// The flag of another road on the command line, if one is given:
/// `--shadowsocks` too (T-373), whose servers take the relay's place.
fn other_road(relay_host: bool, relay_failover: bool, shadowsocks: bool) -> Option<&'static str> {
    let flags = [("--relay-host", relay_host), ("--relay-failover", relay_failover), ("--shadowsocks", shadowsocks)];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The road of a run that resolved to the relay: the forwarders when the
/// command line, the environment or the settings file names them, with
/// the relay's trust; else the relay as it was. `-4` and `-6` choose the
/// family that the relay dials, and a forwarder dials as it chooses.
pub fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let (relays, trust, family, failover, then_direct) = match relay {
        Transport::Relay { relays, trust, family, failover, then_direct } => {
            (relays, trust, family, failover, then_direct)
        }
        other => return Ok(other),
    };
    let named = other_road(args.relay_host.is_some(), args.relay_failover.is_some(), args.shadowsocks.is_some());
    let chosen = choose(args.forwarder.as_deref(), named, env_value(), env.relay.is_some(), &env.settings)?;
    let Some(forwarders) = chosen else {
        // The relay's road: a bad word of its fallback is refused now, before
        // anything connects (T-370).
        fallback::on_from(fallback::env_value(), &env.settings)?;
        return Ok(Transport::Relay { relays, trust, family, failover, then_direct });
    };
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a forwarder dials as it chooses",
        ));
    }
    Ok(Transport::Forwarder { forwarders, trust })
}

/// `--forwarder` beside a road of its own, which [`or_relay`] never saw: a
/// usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.forwarder.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Forwarder { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice:// or warp:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
        Transport::Shadowsocks { .. } => "--shadowsocks",
    };
    Err(Refusal::usage(format!("--forwarder cannot go with {other}, which is a road of its own; a run has one road")))
}

/// The forwarders that `podssh doctor` checks: the flag (64), else the
/// variable or the settings file (78); none when none names them. The
/// doctor checks the relay too, so no other road is refused beside them.
pub fn for_doctor(flag: Option<&str>) -> Result<Vec<Forwarder>, Refusal> {
    Ok(choose(flag, None, env_value(), false, crate::settings::here())?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit_codes::EXIT_USAGE;
    use crate::exitmap::sysexits::EX_CONFIG;
    use crate::settings::Value;

    const QUERY: &str = "wss://web-proxy.mudlet.org/?host={host}&port={port}";

    fn file(forwarder: Option<&str>) -> Defaults {
        let value = forwarder.map(|text| Value { text: text.into(), at: "settings:3".into() });
        Defaults { forwarder: value, ..Defaults::default() }
    }

    #[test]
    fn a_list_is_tried_in_order_each_once() {
        let list = parse_list(&format!("{QUERY}, wss://ssheasy.com/p ,{QUERY}")).unwrap();
        let names: Vec<&str> = list.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["wss://web-proxy.mudlet.org/", "wss://ssheasy.com/p"]);
        assert!(parse_list(" , ").is_err());
        assert!(parse_list("wss://f.example/?host={host}").is_err());
    }

    #[test]
    fn a_word_names_a_forwarder_of_the_binary_and_another_is_refused_unshown() {
        let list = parse_list("mudlet, SSHEASY,mudix,mudlet").unwrap();
        let names: Vec<&str> = list.iter().map(|f| f.name.as_str()).collect();
        let want = [
            "mudlet (wss://web-proxy.mudlet.org/)",
            "ssheasy (wss://ssheasy.com/p)",
            "mudix (wss://mudix.delwing.workers.dev/)",
        ];
        assert_eq!(names, want);
        assert_eq!(builtins(), list, "the fallback's order");
        let refused = parse_list("f.example/?key=SECRET").unwrap_err();
        assert!(refused.contains("mudlet, ssheasy, mudix") && !refused.contains("SECRET"), "{refused}");
        // The help names each word that the binary takes.
        let row = crate::flags::SSH_FLAGS.iter().find(|r| r.long == "forwarder").expect("the row");
        for b in builtin::BUILTIN {
            assert!(row.help.contains(b.word), "{}: {}", b.word, row.help);
        }
    }

    #[test]
    fn the_flag_wins_and_two_roads_at_one_level_are_refused() {
        let none = Defaults::default();
        let flag = choose(Some(QUERY), None, Some("wss://ssheasy.com/p".into()), true, &none).unwrap().unwrap();
        assert_eq!(flag[0].name, "wss://web-proxy.mudlet.org/");
        let both = choose(Some(QUERY), Some("--relay-host"), None, false, &none).unwrap_err();
        assert_eq!(both.code, EXIT_USAGE);
        assert!(both.message.contains("--forwarder and --relay-host name two roads"), "{both}");
        let bad = choose(Some("https://x.example/"), None, None, false, &none).unwrap_err();
        assert!(bad.code == EXIT_USAGE && bad.message.starts_with("--forwarder: "), "{bad}");
        // A relay flag on the command line beats the variable and the file.
        assert_eq!(choose(None, Some("--relay-host"), Some(QUERY.into()), false, &file(Some(QUERY))).unwrap(), None);
    }

    #[test]
    fn the_variable_beats_the_file_and_neither_goes_beside_the_relay_s_variable() {
        let from_env = choose(None, None, Some(QUERY.into()), false, &file(Some("wss://ssheasy.com/p"))).unwrap();
        assert_eq!(from_env.unwrap()[0].name, "wss://web-proxy.mudlet.org/");
        let both = choose(None, None, Some(QUERY.into()), true, &Defaults::default()).unwrap_err();
        assert!(both.code == EX_CONFIG && both.message.contains("PODSSH_FORWARDER and PODSSH_RELAY"), "{both}");
        let frame = choose(None, None, Some("ws://x".into()), false, &Defaults::default());
        assert!(frame.is_ok(), "a template with neither placeholder is the frame form");
        let bad = choose(None, None, Some("nope".into()), false, &Defaults::default()).unwrap_err();
        assert!(bad.code == EX_CONFIG && bad.message.starts_with("PODSSH_FORWARDER: "), "{bad}");
        let from_file = choose(None, None, Some("  ".into()), false, &file(Some(QUERY))).unwrap();
        assert_eq!(from_file.unwrap().len(), 1, "an empty variable is no variable");
        assert_eq!(choose(None, None, None, true, &file(Some(QUERY))).unwrap(), None, "PODSSH_RELAY names the road");
        let bad = choose(None, None, None, false, &file(Some("nope"))).unwrap_err();
        assert!(bad.code == EX_CONFIG && bad.message.starts_with("settings:3: Forwarder "), "{bad}");
    }
}
