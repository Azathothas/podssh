//! The section `carriers` (T-435): the public carriers of the operator's
//! ruling Q65 that this host reaches, which the roads try unasked: the
//! magic-wormhole transit relay (a pair's transit road, T-436), the
//! mailboxes of the pairing by a short code (T-086, T-616) and the Piping
//! Server (T-437). Each is one connection through the proxy, one after
//! another, and carries nothing of the user's: the transit relay's
//! WebSocket is opened and closed with no line said, so it pairs nothing; a
//! mailbox says its welcome and is bound to podssh's application, with no
//! nameplate claimed; the Piping Server is asked its `/version`. A carrier
//! that its variable turns off is not asked. The Wisp demo server of Q65 is
//! a forwarder: the line `fallback` says how `--forwarder wisp` asks it.

use std::time::Duration;

use podssh_relay::code::mailbox::Mailbox;
use podssh_relay::piping::Server;
use podssh_relay::session::{Entropy, OsEntropy};
use podssh_relay::transit::{self, Setting};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use tokio::time::Instant;

use super::Report;
use crate::piping_road::Want;

/// The bound of each carrier's probe, whatever its steps' own: the section's
/// four probes, one after another, end within 40 s.
const WAIT: Duration = Duration::from_secs(10);
/// The most bytes of a Piping Server's `/version` that are read.
const VERSION_MOST: usize = 256;

/// What the section asks, read from the variables of the roads: each
/// carrier, `None` when its variable turns it off, or the fault of its
/// variable.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Plan {
    transit: Result<Option<WsUrl>, String>,
    mailboxes: Result<Option<Vec<WsUrl>>, String>,
    piping: Result<Option<Vec<Server>>, String>,
}

/// The words of a variable that turn a carrier off.
fn off(value: Option<&str>) -> bool {
    matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("no" | "off" | "false" | "0"))
}

/// The plan of the variables' values: `PODSSH_TRANSIT`, `PODSSH_PAIR_MAILBOX`
/// and `PODSSH_PIPING`, read as their roads read them.
pub(super) fn plan(transit_value: Option<&str>, mailbox_value: Option<&str>, piping_value: Option<&str>) -> Plan {
    let transit = transit::setting(transit_value).map(|setting| match setting {
        Setting::On(url) => Some(url),
        Setting::Off => None,
    });
    let mailboxes = match off(mailbox_value) {
        true => Ok(None),
        false => podssh_relay::code::mailboxes(None, mailbox_value).map(Some),
    };
    let piping = match crate::piping_road::want_from(piping_value) {
        Ok(Want::Off) => Ok(None),
        Ok(Want::Unasked(servers) | Want::Asked(servers)) => Ok(Some(servers)),
        Err(refusal) => Err(refusal.message),
    };
    Plan { transit, mailboxes, piping }
}

/// The plan of this process's variables.
fn plan_here() -> Plan {
    let var = |name: &str| std::env::var(name).ok();
    let (transit, mailbox) = (var(transit::ENV), var(podssh_relay::code::ENV));
    plan(transit.as_deref(), mailbox.as_deref(), var(crate::piping_road::ENV).as_deref())
}

/// The lines of the carriers that `plan` does not ask, with no connection:
/// each one turned off, ????; each variable that cannot be used, FAIL.
fn unasked_lines(report: &mut Report<'_>, plan: &Plan) {
    let lines = [
        ("transit relay", plan.transit.as_ref().map(Option::is_none), transit::ENV),
        ("mailbox", plan.mailboxes.as_ref().map(Option::is_none), podssh_relay::code::ENV),
        ("Piping Server", plan.piping.as_ref().map(Option::is_none), crate::piping_road::ENV),
    ];
    for (label, turned_off, variable) in lines {
        match turned_off {
            Ok(true) => report.unknown(label, format!("{variable}=no turns it off, so it was not asked")),
            Ok(false) => {}
            Err(why) => report.fail(label, why.clone()),
        }
    }
}

/// The section's lines.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let plan = plan_here();
    unasked_lines(report, &plan);
    if let Ok(Some(url)) = &plan.transit {
        transit_line(report, url, trust).await;
    }
    if let Ok(Some(urls)) = &plan.mailboxes {
        for url in urls {
            mailbox_line(report, url, trust).await;
        }
    }
    // Each server of the road, as a node may wait at any (T-497).
    if let Ok(Some(servers)) = &plan.piping {
        for server in servers {
            piping_line(report, server, trust).await;
        }
    }
}

/// The transit relay's WebSocket, opened and closed with no line: Least
/// Authority's takes the host's trust, as the road takes it, and another
/// one doctor's.
async fn transit_line(report: &mut Report<'_>, url: &WsUrl, trust: &Trust) {
    let label = format!("transit relay {}", url.shown());
    let least = WsUrl::parse(&transit::default_url()).is_ok_and(|least| least == *url);
    let trust = if least { crate::pairs::trust(None) } else { trust.clone() };
    let started = Instant::now();
    let dialed = tokio::time::timeout(WAIT, transit::far::dial(url, &trust, &ProxyChoice::FromEnvironment)).await;
    match dialed {
        Ok(Ok(session)) => {
            let ms = started.elapsed().as_millis();
            let _ = tokio::time::timeout(Duration::from_secs(2), session.send_close(1000, "")).await;
            let line = format!("the WebSocket opened in {ms} ms, certificate verified; no line said, nothing paired");
            report.ok(&label, line);
        }
        Ok(Err(why)) => report.fail(&label, why),
        Err(_) => report.fail(&label, format!("no WebSocket within {} s", WAIT.as_secs())),
    }
}

/// A mailbox's welcome, bound to podssh's application, then left at once.
async fn mailbox_line(report: &mut Report<'_>, url: &WsUrl, trust: &Trust) {
    let label = format!("mailbox {}", url.shown());
    let mut bytes = [0u8; 5];
    if OsEntropy.fill(&mut bytes).is_err() {
        return report.unknown(&label, "not asked: this host gave no random side");
    }
    let side: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let started = Instant::now();
    match tokio::time::timeout(WAIT, Mailbox::connect(url, trust, &ProxyChoice::FromEnvironment, &side)).await {
        Ok(Ok(mailbox)) => {
            let ms = started.elapsed().as_millis();
            let motd = mailbox.motd.as_ref().map(|motd| format!("; it says: {motd}")).unwrap_or_default();
            let _ = tokio::time::timeout(Duration::from_secs(2), mailbox.end()).await;
            report.ok(&label, format!("welcomed in {ms} ms, certificate verified; no nameplate claimed{motd}"));
        }
        Ok(Err(failed)) => report.fail(&label, failed.to_string()),
        Err(_) => report.fail(&label, format!("no welcome within {} s", WAIT.as_secs())),
    }
}

/// The Piping Server's `/version`, which waits for no sender.
async fn piping_line(report: &mut Report<'_>, server: &Server, trust: &Trust) {
    let label = format!("Piping Server {server}");
    let http = crate::piping_road::http(server, trust);
    let started = Instant::now();
    // The dial has its own bound for TCP and for TLS: the whole probe, this one.
    let asked = tokio::time::timeout(WAIT, http.get_all(&server.path("version"), Some(WAIT), VERSION_MOST)).await;
    match asked {
        Ok(Ok(body)) => {
            let ms = started.elapsed().as_millis();
            let version = podssh_ws::text::one_line(&String::from_utf8_lossy(&body));
            let proto = http.proto().map(|proto| format!(" over {proto}")).unwrap_or_default();
            report.ok(&label, format!("/version answered {version:?}{proto} in {ms} ms, certificate verified"));
        }
        Ok(Err(failed)) => report.fail(&label, failed.to_string()),
        Err(_) => report.fail(&label, format!("no answer within {} s", WAIT.as_secs())),
    }
    http.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no variable each carrier of Q65 is asked: Least Authority's
    /// transit relay, the two public mailboxes in order, and ppng.io. A
    /// variable's no asks none of its carrier, and says so with no
    /// connection; a word that its road refuses fails.
    #[test]
    fn each_carrier_is_asked_unless_its_variable_turns_it_off() {
        let all = plan(None, None, None);
        assert_eq!(all.transit, Ok(Some(WsUrl::parse(&transit::default_url()).unwrap())));
        let shown: Vec<String> = all.mailboxes.clone().unwrap().unwrap().iter().map(WsUrl::shown).collect();
        let public = podssh_relay::code::public_mailboxes().into_iter().map(|url| WsUrl::parse(&url).unwrap().shown());
        let public: Vec<String> = public.collect();
        assert_eq!(shown, public);
        assert_eq!(all.piping, Ok(Some(podssh_relay::piping::server::public())));
        let none = plan(Some("no"), Some("No"), Some("off"));
        assert_eq!(none.transit, Ok(None), "{none:?}");
        assert_eq!(none.mailboxes, Ok(None), "{none:?}");
        assert_eq!(none.piping, Ok(None), "{none:?}");
        let mut out = Vec::new();
        let mut report = Report::new(&mut out);
        unasked_lines(&mut report, &none);
        unasked_lines(&mut report, &plan(Some("maybe"), None, None));
        let _ = report.finish();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("PODSSH_TRANSIT=no turns it off, so it was not asked"), "{text}");
        assert!(text.contains("PODSSH_PAIR_MAILBOX=no turns it off") && text.contains("PODSSH_PIPING=no"), "{text}");
        assert!(text.contains("0 ok, 1 FAIL, 3 ????"), "{text}");
    }
}
