//! The sections of `doctor` that connect, each a part of the report that
//! runs on its own (T-511): which of them run, in the order of the report,
//! and how many start together. `--quick` keeps this host, the egress and
//! the relay, what each run of `ssh` and `proxy` needs, with the roads that
//! the run names (`--forwarder`, `--shadowsocks`, `--via`, `--vless`), and
//! a line names the sections that it left out.

use podssh_relay::failover::Mode;
use podssh_relay::relay::RelayList;
use podssh_ws::Trust;

use super::parts::{self, Ended, Seat};
use super::Report;
use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// The most sections that `--jobs` and `DoctorJobs` name; a number above
/// the sections of a run starts each of them.
pub const MOST_JOBS: usize = 64;

/// What the checks of the network take.
pub(super) struct Checks<'a> {
    pub(super) relays: &'a RelayList,
    pub(super) trust: &'a Trust,
    pub(super) failover: Mode,
    pub(super) full: bool,
    pub(super) forwarders: &'a [crate::forwarder::Forwarder],
    /// The servers of `--shadowsocks`, when it names a file.
    pub(super) servers: Option<&'a crate::shadowsocks::Servers>,
    /// The second proxy of `--via` or `PODSSH_VIA`.
    pub(super) road: Option<&'a crate::via::Road>,
    /// The servers of `--vless`, when it names a file.
    pub(super) links: Option<&'a crate::vless::Servers>,
    /// `--quick`: the roads that the run did not ask for are left out.
    pub(super) quick: bool,
    /// How many sections start together.
    pub(super) jobs: usize,
}

/// A section that connects, or a part of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// What the proxy lets through, or port 22 straight out, and names.
    Network,
    /// The quick tunnel's UDP and its road over TCP.
    QuickTunnel,
    Relay,
    Forwarders,
    Shadowsocks,
    Via,
    Vless,
    #[cfg(feature = "iroh")]
    Iroh,
    #[cfg(feature = "tor")]
    Tor,
    /// The API's host of OpenTunnel (T-531).
    OpenTunnel,
    Derp,
    Pairs,
}

impl Kind {
    /// The section of the report that its lines are in.
    fn section(self) -> &'static str {
        match self {
            Kind::Network | Kind::QuickTunnel => "egress",
            Kind::Relay => "relay",
            Kind::Forwarders => "forwarders",
            Kind::Shadowsocks => "shadowsocks",
            Kind::Via => "via",
            Kind::Vless => "vless",
            #[cfg(feature = "iroh")]
            Kind::Iroh => "iroh",
            #[cfg(feature = "tor")]
            Kind::Tor => "tor",
            Kind::OpenTunnel => "opentunnel",
            Kind::Derp => "derp",
            Kind::Pairs => "pairs",
        }
    }

    /// Whether it begins its section: the egress's parts go on after its
    /// lines that open nothing, which come first.
    fn opens(self) -> bool {
        !matches!(self, Kind::Network | Kind::QuickTunnel)
    }
}

/// The parts of a run, in the order of the report: the roads that the run
/// names, when it names them; with `quick`, none of the roads that it did
/// not ask for.
pub(super) fn kinds(quick: bool, servers: bool, road: bool, links: bool) -> Vec<Kind> {
    let mut kinds = vec![Kind::Network];
    if !quick {
        kinds.push(Kind::QuickTunnel);
    }
    kinds.extend([Kind::Relay, Kind::Forwarders]);
    let named = [(servers, Kind::Shadowsocks), (road, Kind::Via), (links, Kind::Vless)];
    kinds.extend(named.into_iter().filter(|(on, _)| *on).map(|(_, kind)| kind));
    if !quick {
        #[cfg(feature = "iroh")]
        kinds.push(Kind::Iroh);
        #[cfg(feature = "tor")]
        kinds.push(Kind::Tor);
        kinds.extend([Kind::OpenTunnel, Kind::Derp, Kind::Pairs]);
    }
    kinds
}

/// Each section that connects, at most `jobs` at once, into the report in
/// its order; the lines of each section go out as `parts` lets them.
pub(super) async fn network(report: &mut Report<'_>, checks: &Checks<'_>) {
    let kinds = kinds(checks.quick, checks.servers.is_some(), checks.road.is_some(), checks.links.is_some());
    let json = report.json;
    let start = |i: usize, seat: Seat| part(kinds[i], seat, json, checks);
    let ended = parts::run(&mut *report.out, kinds.len(), checks.jobs, start).await;
    for one in ended {
        report.absorb(one);
    }
}

/// One part: its section opened, or the egress's gone on with, then its
/// checks.
async fn part(kind: Kind, mut seat: Seat, json: bool, checks: &Checks<'_>) -> Ended {
    let mut report = Report::new(&mut seat);
    report.json = json;
    match kind.opens() {
        true => report.section(kind.section()),
        false => report.section = kind.section().to_string(),
    }
    checks_of(kind, &mut report, checks).await;
    report.ended()
}

/// The checks of one part, as they ran one section after another.
async fn checks_of(kind: Kind, report: &mut Report<'_>, checks: &Checks<'_>) {
    let Checks { relays, trust, failover, full, forwarders, servers, road, links, .. } = *checks;
    match kind {
        Kind::Network => super::net::check_network(report, relays, trust).await,
        Kind::QuickTunnel => {
            // Whether UDP reaches the quick tunnel's edge, Cloudflare's,
            // with --full alone (T-359).
            super::quick::udp_out(report, full).await;
            // And which road over TCP reaches it, inside WARP's tunnel too (T-374).
            super::quick::edge_road(report, full).await;
        }
        Kind::Relay => super::relay_checks::check(report, relays, trust, failover, full).await,
        Kind::Forwarders => match forwarders.is_empty() {
            true => super::forwarder::fallback_line(report, relays),
            false => super::forwarder::check(report, forwarders, trust).await,
        },
        Kind::Shadowsocks => {
            if let Some(servers) = servers {
                super::shadowsocks::check(report, servers, trust).await;
            }
        }
        Kind::Via => {
            if let Some(road) = road {
                super::via::check(report, road).await;
            }
        }
        Kind::Vless => {
            if let Some(servers) = links {
                super::vless::check(report, servers, trust).await;
            }
        }
        #[cfg(feature = "iroh")]
        Kind::Iroh => super::iroh::relay(report, trust).await,
        #[cfg(feature = "tor")]
        Kind::Tor => super::tor::check(report, trust, full).await,
        Kind::OpenTunnel => super::opentunnel::check(report, trust).await,
        Kind::Derp => super::derp::check(report, trust).await,
        Kind::Pairs => {
            let stored = super::pairs::stored(report);
            super::pairs::presence(report, &stored, trust).await;
        }
    }
}

/// How many sections start together: `--jobs N`, else `DoctorJobs` of the
/// settings file, else each of them (Q73).
pub(super) fn jobs(flag: Option<&str>, file: &Defaults) -> Result<usize, Refusal> {
    let words = format!("a number of sections from 1 to {MOST_JOBS}");
    if let Some(text) = flag {
        return count(text).ok_or_else(|| Refusal::usage(format!("--jobs {text}: give {words}")));
    }
    match &file.doctor_jobs {
        // The file's value was checked as the file was read; one that a test
        // puts in by hand is refused here, as 78.
        Some(value) => count(&value.text)
            .ok_or_else(|| Refusal::config(format!("{}: DoctorJobs {:?}: {words}", value.at, value.text))),
        None => Ok(usize::MAX),
    }
}

/// A number of sections: 1 to [`MOST_JOBS`].
pub(crate) fn count(text: &str) -> Option<usize> {
    text.trim().parse::<usize>().ok().filter(|n| (1..=MOST_JOBS).contains(n))
}

/// What `--quick` leaves out, in the order of the report.
fn left_out() -> Vec<&'static str> {
    let mut names = vec!["the quick tunnel's edge (its roots, UDP out, edge road)"];
    #[cfg(feature = "iroh")]
    names.push("iroh (bind UDP and its relays)");
    #[cfg(feature = "tor")]
    names.push("tor");
    names.extend(["OpenTunnel", "DERP", "the pairs"]);
    names
}

/// The line of `--quick`: the sections that it left out, ????, as checks
/// that did not run, in a section of its own at the end.
pub(super) fn left_out_line(report: &mut Report<'_>) {
    let names = left_out();
    let list = match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.join(""),
    };
    report.section("left out");
    report.unknown("sections", format!("not checked with --quick: {list}; a run without --quick checks them"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Value;

    /// The order of the report, and `--quick`'s parts: the egress, the
    /// relay, the forwarders and each road that the run names.
    #[test]
    fn the_parts_are_in_the_order_of_the_report_and_quick_keeps_the_roads_named() {
        let whole = kinds(false, false, false, false);
        assert_eq!(whole[..4], [Kind::Network, Kind::QuickTunnel, Kind::Relay, Kind::Forwarders]);
        assert_eq!(whole[whole.len() - 2..], [Kind::Derp, Kind::Pairs]);
        assert_eq!(kinds(true, false, false, false), [Kind::Network, Kind::Relay, Kind::Forwarders]);
        let named = kinds(true, true, true, true);
        assert_eq!(named[3..], [Kind::Shadowsocks, Kind::Via, Kind::Vless]);
        assert!(!named.contains(&Kind::Derp) && !named.contains(&Kind::QuickTunnel), "{named:?}");
        assert!(!named.contains(&Kind::OpenTunnel) && whole.contains(&Kind::OpenTunnel), "{whole:?}");
        let sections: Vec<&str> = kinds(false, true, false, false).iter().map(|k| k.section()).collect();
        assert_eq!(sections[..5], ["egress", "egress", "relay", "forwarders", "shadowsocks"]);
        assert!(!Kind::Network.opens() && !Kind::QuickTunnel.opens() && Kind::Relay.opens());
    }

    /// `--jobs` before `DoctorJobs`, each at once with neither; a bad
    /// flag is 64, a bad value of the file 78, with its line.
    #[test]
    fn jobs_come_from_the_flag_the_file_or_each_at_once() {
        let none = Defaults::default();
        assert_eq!(jobs(None, &none).unwrap(), usize::MAX);
        assert_eq!(jobs(Some("1"), &none).unwrap(), 1);
        let file = Defaults { doctor_jobs: Some(Value { text: "2".into(), at: "f:3".into() }), ..Defaults::default() };
        assert_eq!(jobs(None, &file).unwrap(), 2);
        assert_eq!(jobs(Some("5"), &file).unwrap(), 5, "the flag wins");
        for bad in ["0", "65", "-1", "two", ""] {
            let refusal = jobs(Some(bad), &none).unwrap_err();
            assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{bad:?}");
            assert_eq!(refusal.message, format!("--jobs {bad}: give a number of sections from 1 to 64"));
        }
        let many = Value { text: "many".into(), at: "f:3".into() };
        let bad = Defaults { doctor_jobs: Some(many), ..Defaults::default() };
        let refusal = jobs(None, &bad).unwrap_err();
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG);
        assert!(refusal.message.starts_with("f:3: DoctorJobs \"many\": a number of sections"), "{}", refusal.message);
    }

    /// The line names each section that `--quick` left out, and is ????.
    #[test]
    fn the_line_of_quick_names_what_it_left_out() {
        let mut out = Vec::new();
        let mut report = Report::new(&mut out);
        left_out_line(&mut report);
        let _ = report.finish();
        let text = String::from_utf8(out).unwrap();
        let line = "\nleft out\n  ????  sections       not checked with --quick: the quick tunnel's edge";
        assert!(text.contains(line), "{text}");
        assert!(text.contains(", DERP and the pairs; a run without --quick checks them"), "{text}");
        assert!(text.contains("0 ok, 0 FAIL, 1 ????"), "{text}");
    }
}
