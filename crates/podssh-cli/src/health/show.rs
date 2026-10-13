//! The facts of `podssh health` (T-189) for a person, one line for each,
//! and for a program, one JSON object in the form of `doctor --json`
//! (T-049): `schema`, `podssh`, the facts, `error` and `exit`.

use serde_json::{json, Value};

use super::parse::Facts;

/// The number of the JSON object's form.
pub const SCHEMA: u32 = 1;

/// One line for each fact of the host `destination`.
pub fn lines(destination: &str, facts: &Facts) -> Vec<String> {
    let mut out = vec![format!("host {destination}")];
    if let Some(system) = &facts.system {
        out.push(format!("system {system}: no facts for this system"));
        return out;
    }
    if let Some([one, five, fifteen]) = facts.load {
        let cpus = facts.cpus.map(|n| format!(", {n} CPUs")).unwrap_or_default();
        out.push(format!("load {one:.2} {five:.2} {fifteen:.2} (1, 5 and 15 min){cpus}"));
    }
    if let (Some(busy), Some(secs)) = (facts.cpu_busy, facts.interval) {
        out.push(format!("cpu {busy:.1} % busy over {secs:.1} s"));
    }
    if let Some(m) = &facts.memory {
        let estimated = if m.estimated { " (an estimate: the kernel has no MemAvailable)" } else { "" };
        let swap_used = m.swap_total_kib.saturating_sub(m.swap_free_kib);
        out.push(format!(
            "memory {} available of {} ({}){estimated}; swap {} used of {}",
            kib(m.available_kib),
            kib(m.total_kib),
            percent(m.available_kib, m.total_kib),
            kib(swap_used),
            kib(m.swap_total_kib)
        ));
    }
    if let Some(secs) = facts.uptime {
        out.push(format!("uptime {}", duration(secs)));
    }
    for i in &facts.network {
        let now = i.per_second.map(|(rx, tx)| format!("; now {}/s in, {}/s out", size(rx), size(tx)));
        let (rx, tx) = (size(i.rx_bytes as f64), size(i.tx_bytes as f64));
        out.push(format!("network {}: {rx} in, {tx} out since the start{}", i.name, now.unwrap_or_default()));
    }
    for d in &facts.disks {
        out.push(format!(
            "disk {}: {} used of {} ({}), {} available",
            d.mount,
            kib(d.used_kib),
            kib(d.size_kib),
            percent(d.used_kib, d.size_kib),
            kib(d.available_kib)
        ));
    }
    if let Some(n) = facts.processes {
        out.push(format!("processes {n}"));
    }
    out
}

/// The JSON object of a run: the facts, or the error, and the exit code.
pub fn json(destination: &str, answer: Result<&Facts, &str>, exit: i32) -> Value {
    let facts = answer.ok();
    let memory = facts.and_then(|f| f.memory).map(|m| {
        json!({
            "total_kib": m.total_kib,
            "available_kib": m.available_kib,
            "available_estimated": m.estimated,
            "swap_total_kib": m.swap_total_kib,
            "swap_free_kib": m.swap_free_kib,
        })
    });
    let network: Vec<Value> = facts
        .map_or(&[][..], |f| &f.network[..])
        .iter()
        .map(|i| {
            json!({
                "interface": i.name,
                "rx_bytes": i.rx_bytes,
                "tx_bytes": i.tx_bytes,
                "rx_per_s": i.per_second.map(|(rx, _)| rx),
                "tx_per_s": i.per_second.map(|(_, tx)| tx),
            })
        })
        .collect();
    let disks: Vec<Value> = facts
        .map_or(&[][..], |f| &f.disks[..])
        .iter()
        .map(|d| {
            json!({
                "mount": d.mount,
                "filesystem": d.filesystem,
                "size_kib": d.size_kib,
                "used_kib": d.used_kib,
                "available_kib": d.available_kib,
            })
        })
        .collect();
    json!({
        "schema": SCHEMA,
        "podssh": crate::help::version(),
        "destination": destination,
        "system": facts.and_then(|f| f.system.clone()),
        "load": facts.and_then(|f| f.load),
        "cpus": facts.and_then(|f| f.cpus),
        "cpu_busy_percent": facts.and_then(|f| f.cpu_busy),
        "interval_s": facts.and_then(|f| f.interval),
        "memory": memory,
        "uptime_s": facts.and_then(|f| f.uptime),
        "network": network,
        "disks": disks,
        "processes": facts.and_then(|f| f.processes),
        "error": answer.err(),
        "exit": exit,
    })
}

/// KiB as a size.
fn kib(n: u64) -> String {
    size(n as f64 * 1024.0)
}

/// `bytes` in the largest binary unit that keeps it at 1 or more.
pub fn size(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024.0 {
        return format!("{bytes:.0} B");
    }
    let (mut value, mut unit) = (bytes / 1024.0, 0);
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// `part` of `whole`, in whole percent.
fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0 %".to_string();
    }
    format!("{:.0} %", part as f64 * 100.0 / whole as f64)
}

/// Seconds as days, hours and minutes.
fn duration(secs: f64) -> String {
    let s = secs as u64;
    let (days, hours, minutes) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60);
    let day = if days == 1 { "day" } else { "days" };
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{s} s"),
        (0, 0, _) => format!("{minutes} min"),
        (0, _, _) => format!("{hours} h {minutes} min"),
        _ => format!("{days} {day} {hours} h {minutes} min"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::parse::{Disk, Interface, Memory};

    fn host() -> Facts {
        Facts {
            load: Some([0.15, 0.21, 0.18]),
            cpus: Some(2),
            cpu_busy: Some(7.77),
            interval: Some(1.01),
            memory: Some(Memory {
                total_kib: 4 * 1024 * 1024,
                available_kib: 1024 * 1024,
                estimated: false,
                swap_total_kib: 1024 * 1024,
                swap_free_kib: 1024 * 1024,
            }),
            uptime: Some(1_093_624.53),
            network: vec![Interface {
                name: "eth0".into(),
                rx_bytes: 5 * 1024 * 1024 * 1024,
                tx_bytes: 300,
                per_second: Some((100_000.0, 512.0)),
            }],
            disks: vec![Disk {
                mount: "/".into(),
                filesystem: "/dev/sda1".into(),
                size_kib: 40 * 1024 * 1024,
                used_kib: 10 * 1024 * 1024,
                available_kib: 30 * 1024 * 1024,
            }],
            processes: Some(146),
            system: None,
        }
    }

    /// One line for each fact, in a person's units.
    #[test]
    fn each_fact_is_one_line() {
        assert_eq!(
            lines("u@h", &host()),
            [
                "host u@h",
                "load 0.15 0.21 0.18 (1, 5 and 15 min), 2 CPUs",
                "cpu 7.8 % busy over 1.0 s",
                "memory 1.0 GiB available of 4.0 GiB (25 %); swap 0 B used of 1.0 GiB",
                "uptime 12 days 15 h 47 min",
                "network eth0: 5.0 GiB in, 300 B out since the start; now 97.7 KiB/s in, 512 B/s out",
                "disk /: 10.0 GiB used of 40.0 GiB (25 %), 30.0 GiB available",
                "processes 146",
            ]
        );
        let bsd = Facts { system: Some("FreeBSD".into()), ..Facts::default() };
        assert_eq!(lines("u@h", &bsd), ["host u@h", "system FreeBSD: no facts for this system"]);
    }

    /// The JSON holds the numbers as they came, and the error of a run
    /// that has none.
    #[test]
    fn the_json_holds_the_numbers_or_the_error() {
        let facts = host();
        let doc = json("u@h", Ok(&facts), 0);
        assert_eq!((doc["schema"].as_u64(), doc["exit"].as_i64()), (Some(1), Some(0)));
        assert_eq!(doc["memory"]["available_kib"], 1024 * 1024);
        assert_eq!(doc["network"][0]["rx_per_s"], 100_000.0);
        assert_eq!(doc["disks"][0]["mount"], "/");
        assert_eq!(doc["error"], Value::Null);
        let doc = json("u@h", Err("the server has no sh"), 255);
        assert_eq!((doc["error"].as_str(), doc["exit"].as_i64()), (Some("the server has no sh"), Some(255)));
        assert_eq!((doc["memory"].clone(), doc["network"].clone()), (Value::Null, json!([])));
    }

    #[test]
    fn sizes_and_durations_read_well() {
        assert_eq!(size(0.0), "0 B");
        assert_eq!(size(1536.0), "1.5 KiB");
        assert_eq!(size(3.0 * 1024.0 * 1024.0 * 1024.0), "3.0 GiB");
        assert_eq!(duration(42.9), "42 s");
        assert_eq!(duration(3600.0 + 120.0), "1 h 2 min");
        assert_eq!(duration(86_400.0 + 60.0), "1 day 0 h 1 min");
    }
}
