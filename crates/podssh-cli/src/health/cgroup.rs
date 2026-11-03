//! The cgroup of the far shell (T-480), read from the sections `cgroup` and
//! `cgroup 2` of the answer of `podssh health`, and the facts that a program
//! plans its work from: the CPUs and the memory that the cgroup leaves it.
//! `/proc/stat` and `/proc/meminfo` give the whole host's (proc(5)), so a
//! container of 4 CPUs on a host of 48 read 48 there.
//!
//! The files and their forms are the kernel's: `cpu.max`, `cpu.stat`,
//! `cpuset.cpus.effective`, `memory.max`, `memory.current`, `memory.stat`,
//! `io.max`, `pids.max` and the pressure files of cgroup v2
//! (`Documentation/admin-guide/cgroup-v2.rst`, "Controllers"; the root
//! cgroup has none of them); `memory.limit_in_bytes`, `memory.usage_in_bytes`
//! and `hierarchical_memory_limit` of v1 (`cgroup-v1/memory.rst`, 3 and
//! 5.2); `cpu.cfs_quota_us`, -1 for no limit, and `cpu.cfs_period_us`
//! (`scheduler/sched-bwc.rst`, "Management"); `cpuset.effective_cpus`
//! (`cgroup-v1/cpusets.rst`, 1.3); `some avg10=...` (`accounting/psi.rst`).
//! A value that is missing or does not parse is absent, never a guess.

use super::parse::{Facts, Memory};

/// The source of a fact that no cgroup limits.
pub const HOST: &str = "host";

/// One level of the cgroup's path: its own first, then each parent's up to
/// the root of the mount (v2), as a parent's limit binds its children too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Level {
    /// The limit of memory, in bytes: `memory.max` (v2), or the least of
    /// `memory.limit_in_bytes` and `hierarchical_memory_limit` (v1); `None`
    /// for `max`.
    pub memory_max: Option<u64>,
    /// Whether that limit is v1's `hierarchical_memory_limit`.
    pub hierarchical: bool,
    /// `memory.current` (v2), `memory.usage_in_bytes` (v1), in bytes.
    pub memory_current: Option<u64>,
    /// The cache that the kernel takes back before its killer runs: the
    /// `inactive_file` of `memory.stat` (v1: `total_inactive_file`, of the
    /// hierarchy), which `docker stats` takes out of the use too.
    pub inactive_file: Option<u64>,
    /// The quota and the period, in µs: `cpu.max` (v2), `cpu.cfs_quota_us`
    /// and `cpu.cfs_period_us` (v1); `None` for `max` and for -1.
    pub cpu_quota: Option<(u64, u64)>,
}

/// `nr_periods` and `nr_throttled` of one sample of `cpu.stat`.
pub type Periods = (u64, u64);

/// What the script read of the cgroup.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cgroup {
    /// 2 or 1.
    pub version: u8,
    /// The directory read: v2's, or v1's of `memory` (else of the first
    /// controller), as the far host named it.
    pub path: String,
    /// Each line of the section as it came: its key and the rest.
    pub values: Vec<(String, String)>,
    pub levels: Vec<Level>,
    /// The CPUs of the effective cpuset.
    pub cpuset: Option<usize>,
    /// The CPU time that the cgroup used, in µs, before and after the sleep.
    pub usage: (Option<u64>, Option<u64>),
    /// `nr_periods` and `nr_throttled` of `cpu.stat`, before and after (v2).
    pub periods: (Option<Periods>, Option<Periods>),
    pub pids_current: Option<u64>,
    /// `pids.max`; `None` for `max`.
    pub pids_max: Option<u64>,
    /// Each line of `io.max`, a device and its limits.
    pub io_max: Vec<String>,
    /// The `avg10` of the line `some` of `cpu.pressure` and of
    /// `memory.pressure`: the share of the last 10 s that a task waited.
    pub cpu_pressure: Option<f64>,
    pub memory_pressure: Option<f64>,
}

/// The lines of a section, each its key and the rest.
type Pairs = Vec<(String, String)>;

fn split(line: &str) -> (String, String) {
    match line.split_once(' ') {
        Some((key, rest)) => (key.to_string(), rest.to_string()),
        None => (line.to_string(), String::new()),
    }
}

fn one<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim())
}

/// The number after `field` in the lines of `key`: `cpu.stat usage_usec 5`.
fn field(pairs: &[(String, String)], key: &str, name: &str) -> Option<u64> {
    pairs.iter().filter(|(k, _)| k == key).find_map(|(_, v)| {
        let (n, value) = v.split_once(' ')?;
        (n == name).then(|| value.trim().parse().ok()).flatten()
    })
}

fn number(text: Option<&str>) -> Option<u64> {
    text?.parse().ok()
}

/// `cpu.max`: `QUOTA PERIOD`, or `max PERIOD` for no limit.
fn quota_v2(text: Option<&str>) -> Option<(u64, u64)> {
    let mut words = text?.split_whitespace();
    let (quota, period) = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
    (period > 0).then_some((quota, period))
}

/// `cpu.cfs_quota_us` and `cpu.cfs_period_us`: -1 is no limit.
fn quota_v1(quota: Option<&str>, period: Option<&str>) -> Option<(u64, u64)> {
    let quota: i64 = quota?.parse().ok()?;
    let period: u64 = period?.parse().ok()?;
    (quota > 0 && period > 0).then_some((quota as u64, period))
}

/// The CPUs of a list such as `0-4,6,8-10`.
pub fn cpu_count(list: &str) -> Option<usize> {
    let list = list.trim();
    if list.is_empty() {
        return None;
    }
    let mut count = 0usize;
    for part in list.split(',') {
        match part.split_once('-') {
            Some((first, last)) => {
                let (first, last): (usize, usize) = (first.trim().parse().ok()?, last.trim().parse().ok()?);
                if last < first {
                    return None;
                }
                count += last - first + 1;
            }
            None => {
                part.trim().parse::<usize>().ok()?;
                count += 1;
            }
        }
    }
    Some(count)
}

/// The `avg10` of the line `some` of a pressure file.
fn avg10(pairs: &[(String, String)], key: &str) -> Option<f64> {
    pairs.iter().filter(|(k, _)| k == key).find_map(|(_, v)| {
        let rest = v.strip_prefix("some ")?;
        rest.split_whitespace().find_map(|w| w.strip_prefix("avg10=")).and_then(|n| n.parse().ok())
    })
}

/// The level of v2 that `pairs` give, the leaf's or a parent's.
fn level_v2(pairs: &[(String, String)]) -> Level {
    Level {
        memory_max: number(one(pairs, "memory.max")),
        hierarchical: false,
        memory_current: number(one(pairs, "memory.current")),
        inactive_file: field(pairs, "memory.stat", "inactive_file"),
        cpu_quota: quota_v2(one(pairs, "cpu.max")),
    }
}

/// The cgroup of the sections `cgroup` and `cgroup 2`; `None` when the
/// script found neither version, as where `/sys/fs/cgroup` is hidden.
pub fn read(first: &[String], second: Option<&[String]>) -> Option<Cgroup> {
    let pairs: Pairs = first.iter().map(|l| split(l)).collect();
    let later: Pairs = second.unwrap_or_default().iter().map(|l| split(l)).collect();
    let mut cg = Cgroup { values: pairs.clone(), ..Cgroup::default() };
    if let Some(path) = one(&pairs, "v2") {
        cg.version = 2;
        cg.path = path.to_string();
        cg.levels.push(level_v2(&pairs));
        // The parents, `up1` nearest, each line `upN FILE VALUE`.
        let mut parents: Vec<(&str, Pairs)> = Vec::new();
        for (key, rest) in &pairs {
            if !key.strip_prefix("up").is_some_and(|n| n.parse::<u32>().is_ok()) {
                continue;
            }
            match parents.iter_mut().find(|(k, _)| *k == key.as_str()) {
                Some((_, lines)) => lines.push(split(rest)),
                None => parents.push((key.as_str(), vec![split(rest)])),
            }
        }
        cg.levels.extend(parents.iter().map(|(_, lines)| level_v2(lines)));
        cg.cpuset = one(&pairs, "cpuset.cpus.effective").and_then(cpu_count);
        cg.usage = (field(&pairs, "cpu.stat", "usage_usec"), field(&later, "cpu.stat", "usage_usec"));
        let periods =
            |p: &[(String, String)]| Some((field(p, "cpu.stat", "nr_periods")?, field(p, "cpu.stat", "nr_throttled")?));
        cg.periods = (periods(&pairs), periods(&later));
        let devices = pairs.iter().filter(|(k, v)| k == "io.max" && !v.trim().is_empty());
        cg.io_max = devices.map(|(_, v)| v.clone()).collect();
        cg.cpu_pressure = avg10(&pairs, "cpu.pressure");
        cg.memory_pressure = avg10(&pairs, "memory.pressure");
    } else if pairs.iter().any(|(k, _)| k == "v1") {
        cg.version = 1;
        let dirs: Vec<&str> = pairs.iter().filter(|(k, _)| k == "v1").map(|(_, v)| v.as_str()).collect();
        let memory = dirs.iter().find_map(|d| d.strip_prefix("memory "));
        let any = dirs.first().and_then(|d| d.split_once(' ')).map(|(_, dir)| dir);
        cg.path = memory.or(any).unwrap_or_default().to_string();
        let limit = number(one(&pairs, "memory.limit_in_bytes"));
        let whole = field(&pairs, "memory.stat", "hierarchical_memory_limit");
        let (memory_max, hierarchical) = match (limit, whole) {
            (Some(own), Some(whole)) if whole < own => (Some(whole), true),
            (Some(own), _) => (Some(own), false),
            (None, whole) => (whole, whole.is_some()),
        };
        let inactive = field(&pairs, "memory.stat", "total_inactive_file");
        cg.levels.push(Level {
            memory_max,
            hierarchical,
            memory_current: number(one(&pairs, "memory.usage_in_bytes")),
            inactive_file: inactive.or_else(|| field(&pairs, "memory.stat", "inactive_file")),
            cpu_quota: quota_v1(one(&pairs, "cpu.cfs_quota_us"), one(&pairs, "cpu.cfs_period_us")),
        });
        let cpus = one(&pairs, "cpuset.effective_cpus").filter(|l| !l.is_empty()).or(one(&pairs, "cpuset.cpus"));
        cg.cpuset = cpus.and_then(cpu_count);
        // cpuacct.usage is in ns.
        let usage = |p: &[(String, String)]| number(one(p, "cpuacct.usage")).map(|ns| ns / 1000);
        cg.usage = (usage(&pairs), usage(&later));
    } else {
        return None;
    }
    cg.pids_current = number(one(&pairs, "pids.current"));
    cg.pids_max = number(one(&pairs, "pids.max"));
    Some(cg)
}

/// The CPUs and the memory to plan from, and the cgroup's use of its CPUs.
#[derive(Debug, Clone, PartialEq)]
pub struct Effective {
    /// A number such as 4.0 or 1.5: the least of the quota over its
    /// period, the effective cpuset, and the host's CPUs.
    pub cpus: Option<f64>,
    /// `cgroup v2 cpu.max`, `cgroup v2 cpu.max of a parent`, `cgroup v2
    /// cpuset`, `cgroup v1 cfs_quota_us`, `cgroup v1 cpuset` or [`HOST`].
    pub cpus_from: &'static str,
    pub memory_total_kib: Option<u64>,
    /// The limit less the working set (the use less the cache that the
    /// kernel takes back first), at each level that limits, and never more
    /// than the host's `MemAvailable`.
    pub memory_available_kib: Option<u64>,
    pub memory_from: &'static str,
    /// The CPUs that the cgroup used between the two samples, and that as a
    /// share of `cpus`, in percent.
    pub cpu_used: Option<f64>,
    pub cpu_busy: Option<f64>,
    /// The periods in which the cgroup was throttled, of those that passed
    /// between the two samples (v2).
    pub throttled: Option<(u64, u64)>,
}

impl Effective {
    pub fn cpus_limited(&self) -> bool {
        self.cpus_from != HOST
    }

    pub fn memory_limited(&self) -> bool {
        self.memory_from != HOST
    }
}

/// The effective facts of a host's answer; `None` for a host with no
/// `/proc`, which gives no facts. A cgroup with no limit, or none read,
/// gives the host's, with the source [`HOST`].
pub fn effective(facts: &Facts) -> Option<Effective> {
    if facts.system.is_some() {
        return None;
    }
    let cg = facts.cgroup.as_ref();
    let (cpus, cpus_from) = cpus_of(cg, facts.cpus.map(|n| n as f64));
    let (memory_total_kib, memory_available_kib, memory_from) = memory_of(cg, facts.memory.as_ref());
    let cpu_used = cg.and_then(|c| match (c.usage, facts.interval) {
        ((Some(before), Some(after)), Some(secs)) if after >= before && secs > 0.0 => {
            Some((after - before) as f64 / 1e6 / secs)
        }
        _ => None,
    });
    let cpu_busy = match (cpu_used, cpus) {
        (Some(used), Some(n)) if n > 0.0 => Some(used * 100.0 / n),
        _ => None,
    };
    let throttled = cg.and_then(|c| match c.periods {
        (Some((p1, t1)), Some((p2, t2))) if p2 >= p1 && t2 >= t1 => Some((t2 - t1, p2 - p1)),
        _ => None,
    });
    Some(Effective {
        cpus,
        cpus_from,
        memory_total_kib,
        memory_available_kib,
        memory_from,
        cpu_used,
        cpu_busy,
        throttled,
    })
}

/// The least of the host's CPUs and each limit below it; a limit equal to
/// an earlier one keeps the earlier's name.
fn cpus_of(cg: Option<&Cgroup>, host: Option<f64>) -> (Option<f64>, &'static str) {
    let mut best = (host, HOST);
    let Some(cg) = cg else { return best };
    let v2 = cg.version == 2;
    let mut candidates: Vec<(f64, &'static str)> = Vec::new();
    for (i, level) in cg.levels.iter().enumerate() {
        if let Some((quota, period)) = level.cpu_quota {
            let from = match (v2, i) {
                (true, 0) => "cgroup v2 cpu.max",
                (true, _) => "cgroup v2 cpu.max of a parent",
                (false, _) => "cgroup v1 cfs_quota_us",
            };
            candidates.push((quota as f64 / period as f64, from));
        }
    }
    if let Some(n) = cg.cpuset {
        candidates.push((n as f64, if v2 { "cgroup v2 cpuset" } else { "cgroup v1 cpuset" }));
    }
    for (n, from) in candidates {
        if best.0.is_none_or(|b| n < b) {
            best = (Some(n), from);
        }
    }
    best
}

/// The least limit of memory below the host's, and the least room that the
/// levels that limit leave; the host's where none limits. A limit at or
/// above the host's memory limits nothing: v1 writes its "none" as a huge
/// number, and LXCFS gives a container its own `/proc/meminfo` already.
fn memory_of(cg: Option<&Cgroup>, host: Option<&Memory>) -> (Option<u64>, Option<u64>, &'static str) {
    let (mut total, mut available) = (host.map(|m| m.total_kib), host.map(|m| m.available_kib));
    let mut from = HOST;
    let Some(cg) = cg else { return (total, available, from) };
    let mut room_known = true;
    for (i, level) in cg.levels.iter().enumerate() {
        let Some(max) = level.memory_max.map(|bytes| bytes / 1024) else { continue };
        if host.is_some_and(|m| max >= m.total_kib) {
            continue;
        }
        if from == HOST || total.is_none_or(|t| max < t) {
            total = Some(max);
            from = match (cg.version, i, level.hierarchical) {
                (2, 0, _) => "cgroup v2 memory.max",
                (2, _, _) => "cgroup v2 memory.max of a parent",
                (_, _, true) => "cgroup v1 hierarchical_memory_limit",
                _ => "cgroup v1 memory.limit_in_bytes",
            };
        }
        match level.memory_current {
            Some(current) => {
                let working = current.saturating_sub(level.inactive_file.unwrap_or(0)) / 1024;
                let room = max.saturating_sub(working);
                available = Some(available.map_or(room, |a| a.min(room)));
            }
            None => room_known = false,
        }
    }
    if from != HOST && !room_known {
        available = None;
    }
    (total, available, from)
}

#[cfg(test)]
#[path = "cgroup_tests.rs"]
mod tests;
