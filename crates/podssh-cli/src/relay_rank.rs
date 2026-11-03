//! `podssh relay rank` (T-606): each relay host measured on demand from this
//! host, one at a time, and the rank kept in the cache beside the record of
//! failures. The relay's own order (`relay info`) is the edge's estimate and
//! changes from call to call (GitHub #125); this one is measured here. Each
//! probe is a session of `ping`'s relay leg to GitHub's SSH port, never a
//! session's destination (`ping`'s rule), timed from the dial to the
//! upgrade, the token's time left out. Rounds in a new random order each, so
//! that a cold start or the proxy's state falls on no one host each time.

use std::io::Write;
use std::time::{Duration, Instant};

use podssh_relay::rank::{self, Figures, Probe, Rank};
use podssh_relay::relay::Relay;
use serde_json::json;

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_cmd::RelayArgs;
use crate::relay_settings::Refusal;

/// The default and the largest `--rounds`.
const ROUNDS: u32 = 3;
const MAX_ROUNDS: u32 = 20;
/// The default and the largest `--count`, the pings of each probe.
const COUNT: u32 = 5;
const MAX_COUNT: u32 = 20;
/// Between two probes: one connection at a time, and no burst.
const PAUSE: Duration = Duration::from_millis(250);
/// The whole run; a host not probed by then is named.
const RUN_LIMIT: Duration = Duration::from_secs(600);
/// The read of `/relays.json` when no pool is cached.
const POOL_STEP: Duration = Duration::from_secs(20);

/// Run `relay rank`; the exit code.
pub fn run(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.forget && args.cached {
        return Refusal::usage("rank: --cached reads the rank kept and --forget removes it; give one")
            .report("relay", err);
    }
    if args.forget {
        rank::forget();
        let _ = writeln!(err, "podssh relay rank: the rank kept is forgotten");
        return 0;
    }
    if args.cached {
        return cached(args.json, out, err);
    }
    match plan(args, err) {
        Ok(plan) => measure(&plan, args.json, out, err),
        Err(refusal) => refusal.report("relay", err),
    }
}

/// What a run of `rank` measures, with what.
struct Plan {
    hosts: Vec<Relay>,
    named: bool,
    trust: podssh_ws::Trust,
    target: (String, u16),
    rounds: u32,
    count: u32,
}

/// `--NAME N`, from 1 to `max`, else `default`.
fn number(value: Option<&str>, name: &str, default: u32, max: u32) -> Result<u32, Refusal> {
    let Some(value) = value else { return Ok(default) };
    match value.trim().parse::<u32>() {
        Ok(n) if (1..=max).contains(&n) => Ok(n),
        _ => Err(Refusal::usage(format!("rank: {name} {value:?}: a number from 1 to {max}"))),
    }
}

/// The flags read and checked, before anything connects; the hosts: those
/// named, else the default host and each host of its pool, the pool read
/// once first when none is cached.
fn plan(args: &RelayArgs, err: &mut dyn Write) -> Result<Plan, Refusal> {
    let rounds = number(args.rounds.as_deref(), "--rounds", ROUNDS, MAX_ROUNDS)?;
    let count = number(args.count.as_deref(), "--count", COUNT, MAX_COUNT)?;
    let target = match &args.target {
        Some(t) => crate::proxy::parse_target(Some(t), None)
            .map_err(|why| Refusal::usage(format!("rank: --target {t}: {why}")))?,
        None => (crate::ping::relay::REFERENCE.0.to_string(), crate::ping::relay::REFERENCE.1),
    };
    let (relays, trust) = crate::relay_diag::settings(args)?;
    if relays.explicit {
        return Ok(Plan { hosts: relays.hosts, named: true, trust, target, rounds, count });
    }
    let primary = relays.primary().clone();
    if podssh_relay::pool::cached(&primary.host).is_none() {
        let refreshed = crate::relay_cmd::block_on(podssh_relay::pool::refresh(
            &primary,
            &primary.host,
            &trust,
            &podssh_ws::ProxyChoice::FromEnvironment,
            POOL_STEP,
        ))?;
        if let Err(why) = refreshed {
            // The hosts of the default list still rank: the seed's.
            let _ = writeln!(
                err,
                "podssh relay rank: the pool of {} was not read ({why}); its known hosts rank",
                primary.host
            );
        }
    }
    let mut hosts = vec![primary.clone()];
    for host in podssh_relay::pool::alternates(&primary.host) {
        if let Ok(relay) = podssh_relay::relay::parse_relay(&host) {
            if !hosts.contains(&relay) {
                hosts.push(relay);
            }
        }
    }
    Ok(Plan { hosts, named: false, trust, target, rounds, count })
}

/// The indexes `0..n` in a random order (Fisher and Yates).
fn shuffled(n: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rand::random::<u64>() % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    order
}

/// The probe of one leg of `ping`: opened once the relay answered the
/// upgrade, which it does once it reached the target, as a session's race
/// decides; a ping that failed after it leaves the ping's figure out, not
/// the open. A background probe (T-608) is one too.
pub(crate) fn probe_of(leg: &crate::ping::relay::Leg) -> Probe {
    let ms = |d: &Duration| d.as_secs_f64() * 1000.0;
    let open = match (&leg.connect, &leg.tls, &leg.upgrade) {
        (Some((_, c)), Some(t), Some(u)) => Some(ms(c) + ms(t) + ms(u)),
        _ => None,
    };
    let ping = crate::ping::stats::Summary::of(&leg.pings).map(|s| s.p50);
    match open {
        Some(open) => Probe { open_ms: Some(open), ping_ms: ping, why: None },
        None => {
            Probe { open_ms: None, ping_ms: None, why: Some(leg.failed.clone().unwrap_or_else(|| "no session".into())) }
        }
    }
}

/// The egress of this run, as the rank keeps it: the proxy that the first
/// host goes through, by its digest, or direct.
fn egress_of(host: &Relay) -> String {
    match podssh_ws::dial::proxy_from_env(&host.host) {
        Ok(Some(proxy)) => rank::egress(Some((&proxy.host, proxy.port))),
        _ => rank::egress(None),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// The rounds of probes, the rank, its file and its lines.
fn measure(plan: &Plan, json: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let target = (plan.target.0.as_str(), plan.target.1);
    let shown_target = podssh_ws::dial::authority(target.0, target.1);
    let mut probes: Vec<Vec<Probe>> = vec![Vec::new(); plan.hosts.len()];
    let mut not_probed = 0usize;
    let work = async {
        let deadline = Instant::now() + RUN_LIMIT;
        for round in 1..=plan.rounds {
            for i in shuffled(plan.hosts.len()) {
                let host = &plan.hosts[i];
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    not_probed += 1;
                    continue;
                }
                let leg = crate::ping::relay::leg(host, &plan.trust, target, None, plan.count as usize);
                let probe = match tokio::time::timeout(left, leg).await {
                    Ok(leg) => probe_of(&leg),
                    Err(_) => Probe { why: Some("the run's 10 minutes passed".into()), ..Probe::default() },
                };
                let _ = writeln!(err, "{}", probe_line(round, plan.rounds, host, &probe));
                probes[i].push(probe);
                tokio::time::sleep(PAUSE).await;
            }
        }
    };
    if let Err(refusal) = crate::relay_cmd::block_on(work) {
        return refusal.report("relay", err);
    }
    let figures: Vec<Figures> = plan
        .hosts
        .iter()
        .zip(&probes)
        .map(|(host, p)| rank::figures(&podssh_ws::dial::authority(&host.host, host.port), p))
        .collect();
    let old = rank::load();
    let made = Rank {
        schema: rank::SCHEMA,
        made_ms: now_ms(),
        egress: egress_of(&plan.hosts[0]),
        target: shown_target,
        rounds: plan.rounds,
        named: plan.named,
        hosts: rank::order(figures),
        // The samples of the races are kept across ranks (T-607), and when
        // the last background rank was made (T-608).
        background_ms: old.as_ref().map_or(0, |o| o.background_ms),
        samples: old.map(|o| o.samples).unwrap_or_default(),
        source: rank::ON_DEMAND.to_string(),
        partial: false,
    };
    let kept = rank::save(&made);
    let opened = made.first().is_some();
    if json {
        let mut doc = rank_json(&made, now_ms());
        doc["not_probed"] = json!(not_probed);
        doc["kept"] = json!(kept.is_ok());
        let _ = writeln!(out, "{doc}");
    } else {
        for line in rank_lines(&made) {
            let _ = writeln!(out, "{line}");
        }
    }
    if not_probed > 0 {
        let _ = writeln!(err, "podssh relay rank: {not_probed} probes not made: the run's 10 minutes passed");
    }
    match &kept {
        Ok(_) => {
            let _ = writeln!(err, "podssh relay rank: kept in the cache; it holds 24 h for this egress");
        }
        Err(why) => {
            let _ = writeln!(err, "podssh relay rank: not kept: {why}");
        }
    }
    if opened {
        0
    } else {
        let _ = writeln!(err, "podssh relay rank: no relay host opened a session");
        EX_UNAVAILABLE
    }
}

/// `rank 2/3 HOST: open 312 ms, ping p50 41 ms`, or why it failed.
fn probe_line(round: u32, rounds: u32, host: &Relay, probe: &Probe) -> String {
    let name = podssh_ws::dial::authority(&host.host, host.port);
    match (probe.open_ms, &probe.why) {
        (Some(open), None) => {
            let ping = probe.ping_ms.map(|p| format!(", ping p50 {p:.0} ms")).unwrap_or_default();
            format!("rank {round}/{rounds} {name}: open {open:.0} ms{ping}")
        }
        (_, why) => format!("rank {round}/{rounds} {name}: {}", why.as_deref().unwrap_or("no session")),
    }
}

fn ms(value: Option<f64>) -> String {
    value.map_or_else(|| "-".into(), |v| format!("{v:.0}"))
}

/// The lines of a rank, best first.
pub(crate) fn rank_lines(made: &Rank) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, h) in made.hosts.iter().enumerate() {
        let why = h.why.as_deref().map(|w| format!("; {w}")).unwrap_or_default();
        lines.push(format!(
            "{:>2} {}: opened {} of {}, open p50 {} ms, p95 {} ms, ping p50 {} ms{why}",
            i + 1,
            h.host,
            h.opened,
            h.tries,
            ms(h.open_p50_ms),
            ms(h.open_p95_ms),
            ms(h.ping_p50_ms)
        ));
    }
    lines
}

/// A rank as one JSON object.
pub(crate) fn rank_json(made: &Rank, now: i64) -> serde_json::Value {
    json!({
        "schema": 1,
        "podssh": crate::help::version(),
        "made_ms": made.made_ms,
        "age_s": made.age(now).map(|a| a.as_secs()),
        "egress": made.egress,
        "target": made.target,
        "rounds": made.rounds,
        "named": made.named,
        "source": source(made),
        "partial": made.partial,
        "hosts": made.hosts,
    })
}

/// Who made a rank: `relay rank`, or `background` (T-608).
fn source(made: &Rank) -> &'static str {
    if made.background() {
        rank::BACKGROUND
    } else {
        rank::ON_DEMAND
    }
}

/// `--cached`: the rank kept, its age and whether it holds for this egress,
/// with no connection.
fn cached(json: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(kept) = rank::load() else {
        let _ = writeln!(err, "podssh relay rank: no rank is kept; `podssh relay rank` measures and keeps one");
        return EX_UNAVAILABLE;
    };
    let now = now_ms();
    let here = egress_of(&Relay { host: podssh_relay::relay::DEFAULT_RELAY_HOST.to_string(), port: 443 });
    let holds = kept.holds(now, &here);
    if json {
        let mut doc = rank_json(&kept, now);
        doc["this_egress"] = json!(kept.egress == here);
        doc["holds"] = json!(holds);
        let _ = writeln!(out, "{doc}");
        return 0;
    }
    let age = kept.age(now).map_or_else(|| "at a time that this clock has not reached".into(), ago);
    let whose = if kept.egress == here { "this egress" } else { "another egress" };
    let state = if holds { "it holds" } else { "it no longer holds; `podssh relay rank` measures again" };
    let by = match (kept.background(), kept.partial) {
        (true, true) => " in a session's background, of part of its hosts so far",
        (true, false) => " in a session's background",
        _ => "",
    };
    let _ =
        writeln!(out, "rank of {} hosts to {}, made {age}{by}, for {whose}: {state}", kept.hosts.len(), kept.target);
    for line in rank_lines(&kept) {
        let _ = writeln!(out, "{line}");
    }
    0
}

/// The rank kept, for `podssh status` (T-606), with no connection: its age,
/// whether it is of this egress and still holds, its first host that
/// opened and how many it ranks; null with none.
pub(crate) fn status_value() -> serde_json::Value {
    let Some(kept) = rank::load() else { return serde_json::Value::Null };
    let now = now_ms();
    let here = egress_of(&Relay { host: podssh_relay::relay::DEFAULT_RELAY_HOST.to_string(), port: 443 });
    json!({
        "age_s": kept.age(now).map(|a| a.as_secs()),
        "this_egress": kept.egress == here,
        "holds": kept.holds(now, &here),
        "named": kept.named,
        "source": source(&kept),
        "partial": kept.partial,
        "first": kept.first().map(|h| h.host.clone()),
        "hosts": kept.hosts.len(),
    })
}

/// `12 min ago`, `3 h ago`.
pub(crate) fn ago(age: Duration) -> String {
    let s = age.as_secs();
    match s {
        0..=119 => format!("{s} s ago"),
        120..=7199 => format!("{} min ago", s / 60),
        _ => format!("{} h ago", s / 3600),
    }
}

#[cfg(test)]
#[path = "relay_rank_tests.rs"]
mod tests;
