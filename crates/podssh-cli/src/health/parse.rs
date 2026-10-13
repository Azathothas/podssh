//! The answer of the script of `podssh health` (T-189), read: its sections
//! after [`MARK`], and the facts in them, each as the kernel writes it in
//! `/proc` (proc(5)) and as `df -P` prints it. A fact that the answer lacks,
//! or that does not parse, is absent, never a guess. A name that the far
//! host gives (an interface, a mount, a file system, the system) is made
//! safe for a terminal first.

use podssh_ssh::exec::Captured;

use super::script::MARK;

/// The sections of an answer, each with its lines, in order.
pub type Sections = Vec<(String, Vec<String>)>;

/// The memory of the host, in KiB, as `/proc/meminfo` gives it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    pub total_kib: u64,
    /// `MemAvailable`; on a kernel before 3.14, which has none, `MemFree`,
    /// `Buffers` and `Cached` together, and `estimated` says so.
    pub available_kib: u64,
    pub estimated: bool,
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
}

/// One network interface: the bytes since the host started, and each way's
/// bytes in a second between the two samples.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Interface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub per_second: Option<(f64, f64)>,
}

/// One file system of `df -P -k`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Disk {
    pub mount: String,
    pub filesystem: String,
    pub size_kib: u64,
    pub used_kib: u64,
    pub available_kib: u64,
}

/// What the far host told.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    /// What `uname -s` printed on a host with no `/proc`, which gives no
    /// other fact.
    pub system: Option<String>,
    /// The load averages of 1, 5 and 15 minutes.
    pub load: Option<[f64; 3]>,
    pub cpus: Option<usize>,
    /// The share of the time that the CPUs were busy between the two
    /// samples, in percent.
    pub cpu_busy: Option<f64>,
    /// The seconds between the two samples, by the host's own clock.
    pub interval: Option<f64>,
    pub memory: Option<Memory>,
    /// The seconds since the host started.
    pub uptime: Option<f64>,
    /// Each interface but the loopback.
    pub network: Vec<Interface>,
    pub disks: Vec<Disk>,
    pub processes: Option<u64>,
}

/// The facts of a run of the script, or why it gave none: no `sh` (the
/// status 127), or no line of the script.
pub fn answer(got: &Captured) -> Result<Facts, String> {
    let stdout = String::from_utf8_lossy(&got.stdout);
    if let Some(sections) = sections(&stdout) {
        return Ok(facts(&sections));
    }
    let said = podssh_ws::text::one_line(&String::from_utf8_lossy(&got.stderr));
    let said = if said.is_empty() { String::new() } else { format!(": {said}") };
    Err(match got.status {
        Some(127) => format!("the server has no sh{said}"),
        Some(status) => format!("the server gave no facts, and the status {status}{said}"),
        None => format!("the server gave no facts, and no status{said}"),
    })
}

/// The sections after the line [`MARK`], up to `@ end`; `None` when that
/// line never came, as no POSIX `sh` ran the script. What a login printed
/// before it is not read.
pub fn sections(text: &str) -> Option<Sections> {
    let mut lines = text.lines();
    lines.by_ref().find(|line| *line == MARK)?;
    let mut out: Sections = Vec::new();
    for line in lines {
        match line.strip_prefix("@ ") {
            Some("end") => break,
            Some(name) => out.push((name.to_string(), Vec::new())),
            None => {
                if let Some((_, body)) = out.last_mut() {
                    body.push(line.to_string());
                }
            }
        }
    }
    Some(out)
}

fn section<'a>(sections: &'a [(String, Vec<String>)], name: &str) -> Option<&'a [String]> {
    sections.iter().find(|(n, _)| n == name).map(|(_, lines)| lines.as_slice())
}

fn first_line<'a>(sections: &'a [(String, Vec<String>)], name: &str) -> Option<&'a str> {
    section(sections, name)?.first().map(String::as_str)
}

/// The facts of the sections of an answer.
pub fn facts(sections: &[(String, Vec<String>)]) -> Facts {
    if let Some(lines) = section(sections, "system") {
        let system = lines.iter().map(|l| podssh_ws::text::one_line(l.as_str())).find(|l| !l.is_empty());
        return Facts { system: Some(system.unwrap_or_else(|| "an unknown system".to_string())), ..Facts::default() };
    }
    let uptime = first_line(sections, "uptime").and_then(seconds);
    let interval = match (uptime, first_line(sections, "uptime 2").and_then(seconds)) {
        (Some(before), Some(after)) if after > before => Some(after - before),
        _ => None,
    };
    let (cpus, before) = section(sections, "stat").map(cpu).unwrap_or_default();
    let (_, after) = section(sections, "stat 2").map(cpu).unwrap_or_default();
    let cpu_busy = match (before, after, interval) {
        (Some((busy, total)), Some((busy2, total2)), Some(_)) if total2 > total && busy2 >= busy => {
            Some((busy2 - busy) as f64 * 100.0 / (total2 - total) as f64)
        }
        _ => None,
    };
    let later = section(sections, "net/dev 2").map(interfaces).unwrap_or_default();
    let network = section(sections, "net/dev")
        .map(interfaces)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, rx_bytes, tx_bytes)| {
            let per_second = interval.and_then(|secs| {
                let (_, rx, tx) = later.iter().find(|(n, ..)| *n == name)?;
                Some((rx.saturating_sub(rx_bytes) as f64 / secs, tx.saturating_sub(tx_bytes) as f64 / secs))
            });
            Interface { name, rx_bytes, tx_bytes, per_second }
        })
        .collect();
    Facts {
        system: None,
        load: first_line(sections, "loadavg").and_then(load),
        cpus,
        cpu_busy,
        interval,
        memory: section(sections, "meminfo").and_then(memory),
        uptime,
        network,
        disks: section(sections, "df").map(disks).unwrap_or_default(),
        processes: first_line(sections, "processes").and_then(|l| l.trim().parse().ok()),
    }
}

/// The first number of a line of `/proc/uptime`.
fn seconds(line: &str) -> Option<f64> {
    line.split_whitespace().next()?.parse().ok()
}

/// The three averages of `/proc/loadavg`: `0.15 0.20 0.18 1/213 4567`.
fn load(line: &str) -> Option<[f64; 3]> {
    let mut words = line.split_whitespace().map(|w| w.parse::<f64>().ok());
    Some([words.next()??, words.next()??, words.next()??])
}

/// The CPUs of `/proc/stat` (its `cpuN` lines), and the busy and the whole
/// time of its `cpu` line: user, nice, system, idle, iowait, irq, softirq
/// and steal, where idle and iowait are not busy; guest is in user already.
fn cpu(lines: &[String]) -> (Option<usize>, Option<(u64, u64)>) {
    let numbered = |line: &&String| line.strip_prefix("cpu").is_some_and(|n| n.starts_with(char::is_numeric));
    let cpus = lines.iter().filter(numbered).count();
    let times = lines.iter().find_map(|line| line.strip_prefix("cpu ")).and_then(|rest| {
        let counts: Vec<u64> = rest.split_whitespace().take(8).map(str::parse).collect::<Result<_, _>>().ok()?;
        let idle = counts.get(3)? + counts.get(4).copied().unwrap_or(0);
        let total: u64 = counts.iter().sum();
        Some((total - idle, total))
    });
    ((cpus > 0).then_some(cpus), times)
}

/// `/proc/meminfo`: lines `Name:   N kB`.
fn memory(lines: &[String]) -> Option<Memory> {
    let kib = |key: &str| -> Option<u64> {
        lines.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim() != key {
                return None;
            }
            value.split_whitespace().next()?.parse().ok()
        })
    };
    let total_kib = kib("MemTotal")?;
    let (available_kib, estimated) = match kib("MemAvailable") {
        Some(available) => (available, false),
        None => (kib("MemFree")? + kib("Buffers").unwrap_or(0) + kib("Cached").unwrap_or(0), true),
    };
    Some(Memory {
        total_kib,
        available_kib,
        estimated,
        swap_total_kib: kib("SwapTotal").unwrap_or(0),
        swap_free_kib: kib("SwapFree").unwrap_or(0),
    })
}

/// The interfaces of `/proc/net/dev` but the loopback: each line is the
/// name, a colon and sixteen counts, the bytes received first and the bytes
/// sent ninth. The two lines of the heading have no colon.
fn interfaces(lines: &[String]) -> Vec<(String, u64, u64)> {
    lines
        .iter()
        .filter_map(|line| {
            let (name, counts) = line.split_once(':')?;
            let name = podssh_ws::text::one_line(name);
            if name.is_empty() || name == "lo" {
                return None;
            }
            let counts: Vec<&str> = counts.split_whitespace().collect();
            Some((name, counts.first()?.parse::<u64>().ok()?, counts.get(8)?.parse::<u64>().ok()?))
        })
        .collect()
}

/// The lines of `df -P -k`: the file system, its size, used and available
/// KiB, the capacity, and the mount point, which may hold blanks. The
/// heading has no numbers; a mount that came twice (the home on `/`) is
/// kept once.
fn disks(lines: &[String]) -> Vec<Disk> {
    let mut out: Vec<Disk> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() < 6 {
            continue;
        }
        let number = |i: usize| words[i].parse::<u64>().ok();
        let (Some(size_kib), Some(used_kib), Some(available_kib)) = (number(1), number(2), number(3)) else {
            continue;
        };
        let mount = podssh_ws::text::one_line(&words[5..].join(" "));
        if out.iter().any(|disk| disk.mount == mount) {
            continue;
        }
        let filesystem = podssh_ws::text::one_line(words[0]);
        out.push(Disk { mount, filesystem, size_kib, used_kib, available_kib });
    }
    out
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
