//! The reader of the answer of `podssh health` (T-189), on answers in the
//! form of Debian and of Alpine in a container
//! (`tests/fixtures/health/`), and on the cases that a host may give: no
//! `/proc`, no `sleep`, no `MemAvailable`, no `sh`, and hostile names.

use super::*;

const DEBIAN: &str = include_str!("../../tests/fixtures/health/debian.txt");
const ALPINE: &str = include_str!("../../tests/fixtures/health/alpine.txt");

fn read(text: &str) -> Facts {
    facts(&sections(text).expect("the mark"))
}

fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < 0.01
}

/// Debian: each fact, the available memory from `MemAvailable` (never
/// `MemFree`), the loopback left out, and the root named once although
/// `df` gave it for `/` and for the home.
#[test]
fn a_debian_answer_gives_each_fact() {
    let f = read(DEBIAN);
    assert_eq!(f.system, None);
    assert_eq!(f.load, Some([0.15, 0.21, 0.18]));
    assert_eq!(f.cpus, Some(2));
    assert!(f.interval.is_some_and(|s| near(s, 1.01)), "{:?}", f.interval);
    assert!(f.cpu_busy.is_some_and(|b| near(b, 7.767)), "{:?}", f.cpu_busy);
    let memory = Memory {
        total_kib: 4022708,
        available_kib: 2561432,
        estimated: false,
        swap_total_kib: 1048572,
        swap_free_kib: 1046268,
    };
    assert_eq!(f.memory, Some(memory));
    assert_eq!(f.uptime, Some(1093624.53));
    assert_eq!(f.network.len(), 1, "{:?}", f.network);
    let eth0 = &f.network[0];
    assert_eq!((eth0.name.as_str(), eth0.rx_bytes, eth0.tx_bytes), ("eth0", 9873315276, 1325104577));
    let (rx, tx) = eth0.per_second.expect("a rate");
    assert!(near(rx / 1000.0, 100.0) && near(tx / 1000.0, 19.802), "{rx} {tx}");
    let root = Disk {
        mount: "/".into(),
        filesystem: "/dev/sda1".into(),
        size_kib: 40970400,
        used_kib: 12583124,
        available_kib: 26276552,
    };
    assert_eq!(f.disks, [root]);
    assert_eq!(f.processes, Some(146));
}

/// Alpine in a container: four CPUs, no swap, an overlay, and BusyBox's
/// `df`.
#[test]
fn an_alpine_answer_gives_each_fact() {
    let f = read(ALPINE);
    assert_eq!(f.load, Some([1.42, 0.97, 0.66]));
    assert_eq!(f.cpus, Some(4));
    assert!(f.cpu_busy.is_some_and(|b| near(b, 57.143)), "{:?}", f.cpu_busy);
    let memory = f.memory.expect("the memory");
    assert_eq!((memory.available_kib, memory.estimated), (5986712, false));
    assert_eq!((memory.swap_total_kib, memory.swap_free_kib), (0, 0));
    assert_eq!(f.network.len(), 1);
    let (rx, tx) = f.network[0].per_second.expect("a rate");
    assert!(near(rx, 1024.0) && near(tx, 512.0), "{rx} {tx}");
    assert_eq!(f.disks.len(), 1);
    assert_eq!((f.disks[0].mount.as_str(), f.disks[0].filesystem.as_str()), ("/", "overlay"));
    assert_eq!(f.processes, Some(5));
}

/// A host with no `/proc`: the system's name, and no other fact.
#[test]
fn a_host_with_no_proc_gives_its_system_only() {
    let f = read("podssh-health 1\n@ system\nFreeBSD\n@ end\n");
    assert_eq!(f, Facts { system: Some("FreeBSD".into()), ..Facts::default() });
    let f = read("podssh-health 1\n@ system\n@ end\n");
    assert_eq!(f.system.as_deref(), Some("an unknown system"));
}

/// No `sleep`: one sample, so no rate and no busy share, and the rest.
#[test]
fn one_sample_gives_no_rate() {
    let text = "podssh-health 1\n@ uptime\n100.00 300.00\n@ stat\ncpu  1 2 3 4 5 6 7 8 0 0\ncpu0 1 2 3 4 5 6 7 8 0 0\n\
                @ net/dev\n  eth0: 10 1 0 0 0 0 0 0 20 2 0 0 0 0 0 0\n@ end\n";
    let f = read(text);
    assert_eq!((f.cpus, f.cpu_busy, f.interval), (Some(1), None, None));
    assert_eq!(f.network[0].per_second, None);
    assert_eq!((f.network[0].rx_bytes, f.network[0].tx_bytes), (10, 20));
    assert_eq!(f.memory, None);
}

/// A kernel before 3.14 has no `MemAvailable`: free, buffers and the cache
/// stand for it, and the facts say so.
#[test]
fn no_mem_available_is_an_estimate() {
    let text = "podssh-health 1\n@ meminfo\nMemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 20 kB\n\
                Cached: 300 kB\n@ end\n";
    let memory = read(text).memory.expect("the memory");
    assert_eq!((memory.total_kib, memory.available_kib, memory.estimated), (1000, 420, true));
}

/// A count that fills its column, a name with the controls of a terminal,
/// and a mount point with a blank.
#[test]
fn odd_lines_are_read_and_names_are_made_safe() {
    let text = "podssh-health 1\n@ net/dev\nwlan0:12345678901 9 0 0 0 0 0 0 42 1 0 0 0 0 0 0\n\
                ev\u{1b}[2Jil: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n\
                @ df\nFilesystem 1024-blocks Used Available Capacity Mounted on\n\
                /dev/sdb1 100 40 60 40% /mnt/my disk\n@ end\n";
    let f = read(text);
    assert_eq!((f.network[0].name.as_str(), f.network[0].rx_bytes, f.network[0].tx_bytes), ("wlan0", 12345678901, 42));
    assert_eq!(f.network[1].name, "ev[2Jil");
    assert_eq!(f.disks[0].mount, "/mnt/my disk");
}

/// What a login printed before the mark is not read; `@ end` ends the
/// answer.
#[test]
fn only_the_lines_after_the_mark_count() {
    assert_eq!(sections("Welcome!\n@ system\nnot this\n"), None);
    let got = sections("motd\n@ loadavg\n9 9 9\npodssh-health 1\n@ loadavg\n1 2 3\n@ end\n@ processes\n7\n").unwrap();
    assert_eq!(got, vec![("loadavg".to_string(), vec!["1 2 3".to_string()])]);
}

/// No mark: no `sh` when the status is 127, else no facts, with what the
/// server said on stderr.
#[test]
fn no_mark_says_why() {
    let got = Captured { status: Some(127), stdout: Vec::new(), stderr: b"fish: Unknown command: sh\n".to_vec() };
    assert_eq!(answer(&got).unwrap_err(), "the server has no sh: fish: Unknown command: sh");
    let got = Captured { status: Some(1), stdout: b"This account is not available.\n".to_vec(), stderr: Vec::new() };
    assert_eq!(answer(&got).unwrap_err(), "the server gave no facts, and the status 1");
    let got = Captured { status: Some(0), stdout: DEBIAN.as_bytes().to_vec(), stderr: Vec::new() };
    assert_eq!(answer(&got).map(|f| f.processes), Ok(Some(146)));
}
