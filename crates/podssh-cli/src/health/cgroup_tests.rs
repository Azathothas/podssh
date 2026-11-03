//! The reader of the cgroup of `podssh health` (T-480), on the answers of a
//! container of 4 CPUs and 4 GiB under cgroup v2 and under v1, of one with no
//! limit (`tests/fixtures/health/`), and on the cases that a host may give:
//! a parent's limit, a cpuset alone, LXCFS, a limit above the host's, a
//! hidden `/sys/fs/cgroup`, and a use that was not read.

use super::*;
use crate::health::parse::{facts, sections};

const V2: &str = include_str!("../../tests/fixtures/health/container-v2.txt");
const V1: &str = include_str!("../../tests/fixtures/health/container-v1.txt");
const FREE: &str = include_str!("../../tests/fixtures/health/container-free.txt");
const DEBIAN: &str = include_str!("../../tests/fixtures/health/debian.txt");

fn of(text: &str) -> Facts {
    facts(&sections(text).expect("the mark"))
}

fn near(a: Option<f64>, b: f64) -> bool {
    a.is_some_and(|a| (a - b).abs() < 0.01)
}

/// The host's facts of the answers of a container, which `/proc` gives for
/// the whole host, and its own beside them.
const HOST_KIB: u64 = 65842388;
const GIB4_KIB: u64 = 4 * 1024 * 1024;

/// cgroup v2: 4 CPUs of `cpu.max` (its cpuset is each of the host's 16),
/// 4 GiB of `memory.max`, and the room that the working set leaves.
#[test]
fn a_container_on_cgroup_v2_gives_its_own_cpus_and_memory() {
    let f = of(V2);
    assert_eq!(f.cpus, Some(16), "the host's CPUs stay the host's");
    assert_eq!(f.memory.map(|m| m.total_kib), Some(HOST_KIB));
    let cg = f.cgroup.as_ref().expect("the cgroup");
    assert_eq!((cg.version, cg.path.as_str()), (2, "/sys/fs/cgroup/"));
    assert_eq!(cg.levels.len(), 1, "a namespace shows no parent: {:?}", cg.levels);
    assert_eq!(cg.levels[0].cpu_quota, Some((400000, 100000)));
    assert_eq!(cg.cpuset, Some(16));
    assert_eq!((cg.pids_current, cg.pids_max), (Some(23), None));
    assert!(near(cg.cpu_pressure, 1.2) && near(cg.memory_pressure, 0.0), "{cg:?}");
    let e = effective(&f).expect("the effective facts");
    assert!(near(e.cpus, 4.0), "{e:?}");
    assert_eq!(e.cpus_from, "cgroup v2 cpu.max");
    assert_eq!((e.memory_total_kib, e.memory_from), (Some(GIB4_KIB), "cgroup v2 memory.max"));
    // 4 GiB less (1 GiB in use less 300 MiB of inactive cache).
    assert_eq!(e.memory_available_kib, Some(GIB4_KIB - (1024 - 300) * 1024));
    assert!(near(e.cpu_used, 2.5) && near(e.cpu_busy, 62.5), "{e:?}");
    assert_eq!(e.throttled, Some((4, 10)));
}

/// cgroup v1: the quota of `cpu.cfs_quota_us`, the limit of
/// `memory.limit_in_bytes`, the hierarchy's inactive cache, and the use of
/// `cpuacct.usage` in ns.
#[test]
fn a_container_on_cgroup_v1_gives_its_own_cpus_and_memory() {
    let f = of(V1);
    let cg = f.cgroup.as_ref().expect("the cgroup");
    assert_eq!((cg.version, cg.path.as_str()), (1, "/sys/fs/cgroup/memory"));
    let e = effective(&f).expect("the effective facts");
    assert!(near(e.cpus, 4.0), "{e:?}");
    assert_eq!(e.cpus_from, "cgroup v1 cfs_quota_us");
    assert_eq!((e.memory_total_kib, e.memory_from), (Some(GIB4_KIB), "cgroup v1 memory.limit_in_bytes"));
    assert_eq!(e.memory_available_kib, Some(3 * 1024 * 1024));
    assert!(near(e.cpu_used, 1.5) && near(e.cpu_busy, 37.5), "{e:?}");
    assert_eq!(e.throttled, None, "v1 gives no second cpu.stat");
}

/// A container with no limit, and a host whose cgroup was not read, give
/// the host's facts, with the source `host`.
#[test]
fn no_limit_and_no_cgroup_give_the_host_s_facts() {
    let f = of(FREE);
    let e = effective(&f).expect("the effective facts");
    assert!(near(e.cpus, 16.0) && e.cpus_from == HOST, "{e:?}");
    assert_eq!((e.memory_total_kib, e.memory_available_kib, e.memory_from), (Some(HOST_KIB), Some(41234560), HOST));
    assert!(!e.cpus_limited() && !e.memory_limited());
    assert!(near(e.cpu_busy, 1.0), "the cgroup's use of the host's CPUs: {e:?}");
    let f = of(DEBIAN);
    assert_eq!(f.cgroup, None);
    let e = effective(&f).expect("the effective facts");
    assert!(near(e.cpus, 2.0) && e.cpus_from == HOST, "{e:?}");
    assert_eq!((e.memory_total_kib, e.memory_from, e.cpu_busy), (Some(4022708), HOST, None));
    let bsd = Facts { system: Some("FreeBSD".into()), ..Facts::default() };
    assert_eq!(effective(&bsd), None);
}

/// The answer of a host of `cpus` CPUs and 8 GiB with these lines of the
/// section `cgroup`.
fn host_with(cpus: usize, cgroup: &[&str]) -> Facts {
    let mut text = String::from("podssh-health 1\n@ meminfo\nMemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n@ stat\n");
    text.push_str("cpu  1 0 1 1 0 0 0 0\n");
    for n in 0..cpus {
        text.push_str(&format!("cpu{n} 1 0 1 1 0 0 0 0\n"));
    }
    text.push_str("@ cgroup\n");
    for line in cgroup {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("@ end\n");
    of(&text)
}

/// A parent's limit binds as the cgroup's own does: the least of each
/// level's, with the room that each leaves.
#[test]
fn a_parent_s_limit_binds_too() {
    let f = host_with(
        8,
        &[
            "self 0::/user.slice/user-1000.slice/session-3.scope",
            "v2 /sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope",
            "memory.max max",
            "memory.current 104857600",
            "cpu.max max 100000",
            "up1 memory.max 2147483648",
            "up1 memory.current 1073741824",
            "up1 memory.stat inactive_file 0",
            "up1 cpu.max 150000 100000",
            "up2 memory.max max",
            "up2 cpu.max max 100000",
        ],
    );
    let cg = f.cgroup.as_ref().unwrap();
    assert_eq!(cg.levels.len(), 3, "{:?}", cg.levels);
    let e = effective(&f).unwrap();
    assert!(near(e.cpus, 1.5) && e.cpus_from == "cgroup v2 cpu.max of a parent", "{e:?}");
    assert_eq!((e.memory_total_kib, e.memory_from), (Some(2 * 1024 * 1024), "cgroup v2 memory.max of a parent"));
    assert_eq!(e.memory_available_kib, Some(1024 * 1024), "the parent's room: 2 GiB less its 1 GiB");
}

/// A cpuset alone limits the CPUs; a cpuset of each CPU, a limit at or above
/// the host's memory (LXCFS, or v1's huge "none"), and `max` limit nothing.
#[test]
fn a_cpuset_limits_and_a_limit_above_the_host_does_not() {
    let f = host_with(8, &["v2 /sys/fs/cgroup/", "cpu.max max 100000", "cpuset.cpus.effective 2-3", "memory.max max"]);
    let e = effective(&f).unwrap();
    assert!(near(e.cpus, 2.0) && e.cpus_from == "cgroup v2 cpuset", "{e:?}");
    assert_eq!(e.memory_from, HOST);
    // A quota and a cpuset of the same count: the quota names it.
    let f = host_with(8, &["v2 /sys/fs/cgroup/", "cpu.max 200000 100000", "cpuset.cpus.effective 0,1"]);
    assert_eq!(effective(&f).unwrap().cpus_from, "cgroup v2 cpu.max");
    let lxcfs = host_with(8, &["v2 /sys/fs/cgroup/", "cpuset.cpus.effective 0-7", "memory.max 8589934592"]);
    let e = effective(&lxcfs).unwrap();
    assert_eq!((e.cpus_from, e.memory_from, e.memory_total_kib), (HOST, HOST, Some(8388608)));
    let none = ["v1 memory /sys/fs/cgroup/memory", "memory.limit_in_bytes 9223372036854771712", "cpu.cfs_quota_us -1"];
    let e = effective(&host_with(8, &none)).unwrap();
    assert_eq!((e.cpus_from, e.memory_from), (HOST, HOST));
}

/// The room is never more than the host's `MemAvailable`, and a limit whose
/// use was not read gives no room, never a guess.
#[test]
fn the_room_is_bounded_and_never_guessed() {
    let f = host_with(4, &["v2 /sys/fs/cgroup/", "memory.max 7516192768", "memory.current 0"]);
    assert_eq!(effective(&f).unwrap().memory_available_kib, Some(6291456), "the host's MemAvailable");
    let f = host_with(4, &["v2 /sys/fs/cgroup/", "memory.max 1073741824"]);
    let e = effective(&f).unwrap();
    assert_eq!((e.memory_total_kib, e.memory_available_kib), (Some(1024 * 1024), None));
}

/// A section with neither version, as where `/sys/fs/cgroup` is hidden, is
/// no cgroup; the lines of `io.max` and `pids.max` are kept.
#[test]
fn a_hidden_cgroup_is_none_and_the_other_limits_are_kept() {
    assert_eq!(read(&["self 0::/".to_string()], None), None);
    let lines: Vec<String> = ["v2 /sys/fs/cgroup/", "io.max 8:0 rbps=1048576 wbps=max riops=max wiops=max", "io.max "]
        .iter()
        .chain(&["pids.max 4096", "pids.current 12"])
        .map(|l| l.to_string())
        .collect();
    let cg = read(&lines, None).unwrap();
    assert_eq!(cg.io_max, ["8:0 rbps=1048576 wbps=max riops=max wiops=max"]);
    assert_eq!((cg.pids_current, cg.pids_max), (Some(12), Some(4096)));
}

#[test]
fn a_list_of_cpus_is_counted() {
    assert_eq!(cpu_count("0-4,6,8-10"), Some(9));
    assert_eq!(cpu_count("7"), Some(1));
    assert_eq!(cpu_count(" 0-47\n"), Some(48));
    for bad in ["", "3-1", "a", "0-", "1,,2"] {
        assert_eq!(cpu_count(bad), None, "{bad:?}");
    }
}
