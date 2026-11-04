//! `podssh ping node://NAME`, and `podssh ping NAME` of a member of the net
//! (T-435), as `tailscale ping` names the path that answered: the roads that
//! `podssh ssh` races to the node, each with its time to the far end's first
//! bytes or why it failed, and the one that answered first. Each road that
//! starts opens its one connection, as a race of `ssh` opens it; no session
//! goes above the roads, so the node dials nothing at its TARGET, and nothing
//! logs in (`crate::ssh::roads::probe`). Any other run is `super::run`'s.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::Log;
use serde_json::{json, Value};

use super::PingArgs;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;
use crate::ssh::resolve::{self, Env};
use crate::ssh::roads::probe::{Measured, Measures};

/// `podssh ping`: the roads of a node; else the relay legs, and a host's
/// measures (`super::run`). 0 when a road answered; 69 when none did, or
/// with `PODSSH_OFFLINE`; 64 for a flag of a host's measures, before
/// anything connects; else the refusal of the node's resolution.
pub fn run(args: &PingArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(text) = args.ssh.destination.as_deref() else { return super::run(args, out, err) };
    let env = Env::from_process();
    if !is_node(text, &env) {
        return super::run(args, out, err);
    }
    // A node's roads race once, and the measures of a host are no road's.
    for (given, flag) in [(&args.size, "--size"), (&args.count, "--count"), (&args.target, "--target")] {
        if given.is_some() {
            let why = format!("{flag} is for the relay leg and a host's measures; the roads of {text} race once");
            return Refusal::usage(why).report("ping", err);
        }
    }
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("ping", err);
    }
    let resolved = match resolve::resolve_or_refuse(&args.ssh, &env) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("ping", err),
    };
    if podssh_relay::open::offline() {
        let variable = podssh_relay::open::OFFLINE_ENV;
        let _ = writeln!(err, "podssh ping: {variable} is set, so podssh does not connect anywhere");
        return EX_UNAVAILABLE;
    }
    let log = Arc::new(Log::new(resolved.options.log_level));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh ping: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    let measuring = crate::ssh::node_roads::measure(&resolved.transport, &log);
    let measured = runtime.block_on(async { tokio::time::timeout(super::RUN_LIMIT, measuring).await });
    // A road's dialer may have left a task behind; the measure is done.
    runtime.shutdown_background();
    let measures = match measured {
        Ok(Ok(measures)) => measures,
        Ok(Err(not)) => {
            for line in &not.lines {
                let _ = writeln!(err, "podssh ping: {line}");
            }
            return not.code;
        }
        Err(_) => {
            let _ = writeln!(err, "podssh ping: the run passed its limit of {} s", super::RUN_LIMIT.as_secs());
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    let code = if measures.won.is_some() { 0 } else { EX_UNAVAILABLE };
    if args.json {
        let _ = writeln!(out, "{}", json_of(&measures, code));
    } else {
        for line in lines(&measures) {
            let _ = writeln!(out, "{line}");
        }
    }
    let _ = out.flush();
    code
}

/// Whether `text` names a node as `podssh ssh` reads it: `node://NAME`, or
/// the name alone of a member with the role node; a group of one host is
/// that host.
fn is_node(text: &str, env: &Env) -> bool {
    let Ok(one) = crate::hosts::one(text, &env.settings.groups) else { return false };
    matches!(crate::ssh::node::destination(&one), Ok(Some(_)))
}

/// A time in milliseconds, to a tenth.
fn shown_ms(time: Duration) -> String {
    format!("{:.1} ms", time.as_secs_f64() * 1000.0)
}

/// The road that answered first, and its time from the start of the race.
fn winner(measures: &Measures) -> Option<(&'static str, Duration)> {
    let at = measures.won?;
    let measured = measures.roads.get(at)?;
    Some((measured.road, measured.timed.as_ref()?.ended()))
}

/// The line of one road.
fn road_line(shown: &str, measured: &Measured) -> String {
    let road = measured.road;
    let Some(timed) = &measured.timed else {
        return format!("{shown}: {road}: not started: a fallback, which starts only when each road before it failed");
    };
    // A road started with the race is some microseconds in, which would
    // read as "started 0.0 ms": only a road that waited says when.
    let into = match timed.started < std::time::Duration::from_millis(1) {
        true => String::new(),
        false => format!(", started {} into the race", shown_ms(timed.started)),
    };
    match &timed.answered {
        Ok(()) => format!("{shown}: {road}: answered in {}{into}", shown_ms(timed.took)),
        Err(why) => format!("{shown}: {road}: failed after {}{into}: {why}", shown_ms(timed.took)),
    }
}

/// The lines of the measure: one for each road, in the order of the race,
/// then the road that answered first, or that none did.
fn lines(measures: &Measures) -> Vec<String> {
    let shown = &measures.shown;
    let mut lines: Vec<String> = measures.roads.iter().map(|measured| road_line(shown, measured)).collect();
    lines.push(match winner(measures) {
        Some((road, took)) => format!("{shown}: {road} answered first, in {}", shown_ms(took)),
        None => format!("{shown}: not reached: no road answered"),
    });
    lines
}

/// One JSON object, in the shape of the other runs of `ping --json`, with
/// `node` in place of the relay legs and the destination's measures.
fn json_of(measures: &Measures, code: i32) -> Value {
    let ms = |time: Duration| (time.as_secs_f64() * 1_000_000.0).round() / 1000.0;
    let road = |measured: &Measured| match &measured.timed {
        None => json!({
            "road": measured.road,
            "started": false,
            "started_ms": null,
            "ms": null,
            "answered": false,
            "error": null,
        }),
        Some(timed) => json!({
            "road": measured.road,
            "started": true,
            "started_ms": ms(timed.started),
            "ms": ms(timed.took),
            "answered": timed.answered.is_ok(),
            "error": timed.answered.as_ref().err(),
        }),
    };
    let won = winner(measures);
    json!({
        "schema": 1,
        "podssh": crate::help::version(),
        "relays": [],
        "destination": null,
        "node": {
            "name": measures.shown,
            "roads": measures.roads.iter().map(road).collect::<Vec<_>>(),
            "won": won.map(|(road, _)| road),
            "won_ms": won.map(|(_, took)| ms(took)),
        },
        "exit": code,
    })
}

#[cfg(test)]
mod tests {
    use podssh_relay::session::race::Timed;

    use super::*;

    fn timed(started_ms: u64, took_us: u64, answered: Result<(), String>) -> Option<Timed> {
        Some(Timed { started: Duration::from_millis(started_ms), took: Duration::from_micros(took_us), answered })
    }

    fn three() -> Measures {
        let roads = vec![
            Measured { road: "the iroh road", timed: timed(0, 412_000, Ok(())) },
            Measured { road: "the pair's road", timed: timed(250, 12_340, Ok(())) },
            Measured { road: "the transit road", timed: None },
        ];
        Measures { shown: "node://lab".into(), roads, won: Some(1) }
    }

    /// Each road has its line with its time, and when it started into the
    /// race; a fallback that did not start says so; the last line names the
    /// road that answered first, with its time from the start of the race.
    #[test]
    fn each_road_has_its_time_and_the_last_line_names_the_first_that_answered() {
        let lines = lines(&three());
        assert_eq!(lines[0], "node://lab: the iroh road: answered in 412.0 ms");
        assert_eq!(lines[1], "node://lab: the pair's road: answered in 12.3 ms, started 250.0 ms into the race");
        assert!(lines[2].starts_with("node://lab: the transit road: not started"), "{lines:#?}");
        assert_eq!(lines[3], "node://lab: the pair's road answered first, in 262.3 ms");
        let failed = Measured { road: "the pair's road", timed: timed(0, 30_000, Err("the node is offline".into())) };
        let none = Measures { shown: "node://gone".into(), roads: vec![failed], won: None };
        let lines = super::lines(&none);
        let failed = "node://gone: the pair's road: failed after 30.0 ms: the node is offline";
        assert_eq!(lines, [failed, "node://gone: not reached: no road answered"]);
    }

    /// The JSON has each road with its times in milliseconds, the road that
    /// won and its time, and the exit, beside the fields of a host's run.
    #[test]
    fn the_json_has_each_road_s_times_and_the_winner() {
        let value = json_of(&three(), 0);
        assert_eq!(value["schema"], 1);
        assert_eq!((&value["relays"], &value["destination"]), (&json!([]), &Value::Null));
        let roads = &value["node"]["roads"];
        assert_eq!(roads[0]["ms"], 412.0);
        assert_eq!((&roads[1]["started_ms"], &roads[1]["ms"]), (&json!(250.0), &json!(12.34)));
        assert_eq!((&roads[2]["started"], &roads[2]["ms"]), (&json!(false), &Value::Null));
        assert_eq!((&value["node"]["won"], &value["node"]["won_ms"]), (&json!("the pair's road"), &json!(262.34)));
        assert_eq!(value["exit"], 0);
    }
}
