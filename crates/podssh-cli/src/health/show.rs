//! The facts of `podssh health` (T-189) for a person, one line for each,
//! and for a program, one JSON object in the form of `doctor --json`
//! (T-049): `schema`, `podssh`, the facts, `error` and `exit`. Where a
//! cgroup limits the CPUs or the memory (T-480), its own facts come beside
//! the host's, which keep their lines and their keys.

use serde_json::{json, Value};

use super::cgroup::{self, Cgroup, Effective};
use super::parse::Facts;

/// The number of the JSON object's form: the keys of T-480 are new keys,
/// and each key of before keeps its meaning.
pub const SCHEMA: u32 = 1;

/// One line for each fact of the host `destination`.
pub fn lines(destination: &str, facts: &Facts) -> Vec<String> {
    let mut out = vec![format!("host {destination}")];
    if let Some(system) = &facts.system {
        out.push(format!("system {system}: no facts for this system"));
        return out;
    }
    let effective = cgroup::effective(facts);
    let limited = effective.as_ref().filter(|e| e.cpus_limited() || e.memory_limited());
    if let Some([one, five, fifteen]) = facts.load {
        let cpus = facts.cpus.map(|n| format!(", {n} CPUs")).unwrap_or_default();
        // The kernel keeps one load for the whole host, a container's too.
        let whose = if limited.is_some() { ": the whole host's" } else { "" };
        out.push(format!("load {one:.2} {five:.2} {fifteen:.2} (1, 5 and 15 min){cpus}{whose}"));
    }
    let cg = facts.cgroup.as_ref();
    out.extend(cg.and_then(pressure));
    if let Some(e) = effective.as_ref().filter(|e| e.cpus_limited()) {
        let host = facts.cpus.map(|n| format!(", {n} on the host")).unwrap_or_default();
        out.extend(e.cpus.map(|n| format!("cpus {} ({}){host}", count(n), e.cpus_from)));
    }
    if let (Some(busy), Some(secs)) = (facts.cpu_busy, facts.interval) {
        out.push(match effective.as_ref().and_then(own_cpu) {
            Some(own) => format!("cpu {busy:.1} % busy over {secs:.1} s, the host's; {own}"),
            None => format!("cpu {busy:.1} % busy over {secs:.1} s"),
        });
    }
    if let Some(m) = &facts.memory {
        let estimated = if m.estimated { " (an estimate: the kernel has no MemAvailable)" } else { "" };
        let swap_used = m.swap_total_kib.saturating_sub(m.swap_free_kib);
        let swap = format!("swap {} used of {}", kib(swap_used), kib(m.swap_total_kib));
        let (available, total) = (m.available_kib, m.total_kib);
        let host = format!("{} available of {} ({}){estimated}", kib(available), kib(total), percent(available, total));
        out.push(match effective.as_ref().filter(|e| e.memory_limited()) {
            Some(e) => format!("memory {}; the host: {host}; {swap}", own_memory(e)),
            None => format!("memory {host}; {swap}"),
        });
    }
    if let Some(cg) = cg {
        out.extend(other_limits(cg));
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
        "effective": facts.and_then(cgroup::effective).map(|e| effective_json(&e)),
        "cgroup": facts.and_then(|f| f.cgroup.as_ref()).map(cgroup_json),
        "error": answer.err(),
        "exit": exit,
    })
}

/// The facts to plan from, on any host: a cgroup's where it limits, else
/// the host's, each with its source.
fn effective_json(e: &Effective) -> Value {
    json!({
        "cpus": e.cpus,
        "cpus_from": e.cpus_from,
        "memory_total_kib": e.memory_total_kib,
        "memory_available_kib": e.memory_available_kib,
        "memory_from": e.memory_from,
        "cpu_used": e.cpu_used,
        "cpu_busy_percent": e.cpu_busy,
        "throttled_periods": e.throttled.map(|(throttled, _)| throttled),
        "periods": e.throttled.map(|(_, periods)| periods),
    })
}

/// The cgroup as the script read it: its version, its directory, and each
/// value as it came, by its key.
fn cgroup_json(cg: &Cgroup) -> Value {
    let mut values = serde_json::Map::new();
    for (key, rest) in &cg.values {
        if let Value::Array(list) = values.entry(key.clone()).or_insert_with(|| Value::Array(Vec::new())) {
            list.push(Value::String(rest.clone()));
        }
    }
    json!({
        "version": cg.version,
        "path": cg.path,
        "values": values,
        "cpu_usage_usec": [cg.usage.0, cg.usage.1],
        "pids_current": cg.pids_current,
        "pids_max": cg.pids_max,
        "io_max": cg.io_max,
        "cpu_pressure_avg10": cg.cpu_pressure,
        "memory_pressure_avg10": cg.memory_pressure,
    })
}

/// The cgroup's share of the last 10 s spent waiting, where PSI gives it.
fn pressure(cg: &Cgroup) -> Option<String> {
    let part = |name: &str, avg: Option<f64>| avg.map(|avg| format!("{name} {avg:.2} %"));
    let parts: Vec<String> =
        [part("cpu", cg.cpu_pressure), part("memory", cg.memory_pressure)].into_iter().flatten().collect();
    (!parts.is_empty()).then(|| format!("pressure {} of the last 10 s waiting (the cgroup's)", parts.join(", ")))
}

/// The cgroup's use of its CPUs between the samples, and its throttling.
fn own_cpu(e: &Effective) -> Option<String> {
    let (busy, cpus) = (e.cpu_busy?, e.cpus?);
    let throttled = match e.throttled {
        Some((throttled, periods)) if throttled > 0 => format!(", throttled in {throttled} of {periods} periods"),
        _ => String::new(),
    };
    Some(format!("the cgroup's {busy:.1} % of {} CPUs{throttled}", count(cpus)))
}

/// The memory that the cgroup leaves, and its source.
fn own_memory(e: &Effective) -> String {
    let total = e.memory_total_kib.unwrap_or(0);
    match e.memory_available_kib {
        Some(room) => {
            format!("{} available of {} ({}, {})", kib(room), kib(total), percent(room, total), e.memory_from)
        }
        None => format!("{} at most ({}), its use not read", kib(total), e.memory_from),
    }
}

/// The limits of the disks' bytes and of the processes, where the cgroup
/// has them. A device's line is the far host's, made safe for a terminal.
fn other_limits(cg: &Cgroup) -> Vec<String> {
    let v = cg.version;
    let mut out: Vec<String> =
        cg.io_max.iter().map(|d| format!("io {} (cgroup v{v} io.max)", podssh_ws::text::one_line(d))).collect();
    if let Some(max) = cg.pids_max {
        let now = cg.pids_current.map(|n| format!("{n} of ")).unwrap_or_default();
        out.push(format!("pids {now}{max} (cgroup v{v} pids.max)"));
    }
    out
}

/// A count of CPUs: 4, or 1.5 for a quota of a CPU and a half.
pub(super) fn count(n: f64) -> String {
    if (n - n.round()).abs() < 0.005 {
        format!("{n:.0}")
    } else {
        format!("{n:.2}").trim_end_matches('0').to_string()
    }
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
            cgroup: None,
        }
    }

    fn container(text: &str) -> Facts {
        crate::health::parse::facts(&crate::health::parse::sections(text).expect("the mark"))
    }

    /// A container of 4 CPUs and 4 GiB on a host of 16 (T-480): its own
    /// CPUs, memory, use and pressure, and the host's beside them, whose
    /// load is said to be the whole host's.
    #[test]
    fn a_container_s_limits_come_beside_the_host_s_facts() {
        let got = lines("u@h", &container(include_str!("../../tests/fixtures/health/container-v2.txt")));
        for want in [
            "load 2.10 1.80 1.50 (1, 5 and 15 min), 16 CPUs: the whole host's",
            "pressure cpu 1.20 %, memory 0.00 % of the last 10 s waiting (the cgroup's)",
            "cpus 4 (cgroup v2 cpu.max), 16 on the host",
            "cpu 25.0 % busy over 1.0 s, the host's; the cgroup's 62.5 % of 4 CPUs, throttled in 4 of 10 periods",
            "memory 3.3 GiB available of 4.0 GiB (82 %, cgroup v2 memory.max); the host: 39.3 GiB available of \
             62.8 GiB (63 %); swap 0 B used of 0 B",
            "processes 9",
        ] {
            assert!(got.iter().any(|l| l == want), "{want}: {got:#?}");
        }
        assert!(!got.iter().any(|l| l.starts_with("pids ")), "pids.max is max: {got:#?}");
        let v1 = lines("u@h", &container(include_str!("../../tests/fixtures/health/container-v1.txt")));
        assert!(v1.iter().any(|l| l == "cpus 4 (cgroup v1 cfs_quota_us), 16 on the host"), "{v1:#?}");
        assert!(v1.iter().any(|l| l.starts_with("memory 3.0 GiB available of 4.0 GiB (75 %, cgroup v1 ")), "{v1:#?}");
        // No limit: the lines of before, and the cgroup's share of the CPUs.
        let free = lines("u@h", &container(include_str!("../../tests/fixtures/health/container-free.txt")));
        assert!(free.iter().any(|l| l == "load 0.40 0.30 0.20 (1, 5 and 15 min), 16 CPUs"), "{free:#?}");
        assert!(!free.iter().any(|l| l.starts_with("cpus ") || l.starts_with("pressure ")), "{free:#?}");
        assert!(free.iter().any(|l| l.ends_with("the host's; the cgroup's 1.0 % of 16 CPUs")), "{free:#?}");
        let host_memory = "memory 39.3 GiB available of 62.8 GiB (63 %); swap 0 B used of 0 B";
        assert!(free.iter().any(|l| l == host_memory), "{free:#?}");
    }

    /// The limits of the disks and of the processes, a line each; a count
    /// of CPUs that is not whole.
    #[test]
    fn the_other_limits_are_a_line_each() {
        let cg = Cgroup {
            version: 2,
            io_max: vec!["8:0 rbps=1048576 wbps=max riops=max wiops=max".into()],
            pids_current: Some(12),
            pids_max: Some(4096),
            ..Cgroup::default()
        };
        assert_eq!(
            other_limits(&cg),
            [
                "io 8:0 rbps=1048576 wbps=max riops=max wiops=max (cgroup v2 io.max)",
                "pids 12 of 4096 (cgroup v2 pids.max)"
            ]
        );
        assert_eq!((count(4.0), count(1.5), count(0.25)), ("4".to_string(), "1.5".to_string(), "0.25".to_string()));
    }

    /// The JSON keeps each key of before, the host's, and adds `effective`,
    /// on any host, and `cgroup` where one was read.
    #[test]
    fn the_json_adds_the_effective_facts_and_the_cgroup() {
        let facts = container(include_str!("../../tests/fixtures/health/container-v2.txt"));
        let doc = json("u@h", Ok(&facts), 0);
        assert_eq!((doc["cpus"].as_u64(), doc["memory"]["total_kib"].as_u64()), (Some(16), Some(65842388)));
        let e = &doc["effective"];
        assert_eq!((e["cpus"].as_f64(), e["cpus_from"].as_str()), (Some(4.0), Some("cgroup v2 cpu.max")));
        assert_eq!(e["memory_total_kib"], 4 * 1024 * 1024);
        assert_eq!(e["memory_from"], "cgroup v2 memory.max");
        assert_eq!(e["memory_available_kib"], 3452928);
        assert_eq!((e["throttled_periods"].as_u64(), e["periods"].as_u64()), (Some(4), Some(10)));
        let cg = &doc["cgroup"];
        assert_eq!((cg["version"].as_u64(), cg["path"].as_str()), (Some(2), Some("/sys/fs/cgroup/")));
        assert_eq!(cg["values"]["cpu.max"], json!(["400000 100000"]));
        assert_eq!(cg["values"]["memory.stat"], json!(["inactive_file 314572800"]));
        let doc = json("u@h", Ok(&host()), 0);
        let e = &doc["effective"];
        assert_eq!((e["cpus"].as_f64(), e["cpus_from"].as_str()), (Some(2.0), Some("host")));
        assert_eq!(doc["cgroup"], Value::Null);
        let doc = json("u@h", Err("the server has no sh"), 255);
        assert_eq!((doc["effective"].clone(), doc["cgroup"].clone()), (Value::Null, Value::Null));
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
