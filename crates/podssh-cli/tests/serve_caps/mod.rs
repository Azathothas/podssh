//! What `podssh relay serve` holds after its bind (T-629): the role started
//! as a process, its port known once its runtime runs, then each of its
//! threads read in `/proc/PID/task/*/status`: no effective, permitted or
//! inheritable capability, and no new privileges, whether this test started
//! it with capabilities (as root, or in a container) or with none; with
//! `CAP_SETPCAP` in its start, its bounding set empty too, and its first
//! line says the drop. Where `/proc` gives no task of the role, it says
//! that it did not run.

#![cfg(target_os = "linux")]

use std::process::Stdio;

use super::serve_certs::{ca_and_leaf, podssh, replace, until, Killed, Scratch};

/// `CAP_SETPCAP`.
const SETPCAP: u32 = 8;

/// The value of `name` in a thread's status: hex for a set, decimal for a flag.
fn value(text: &str, name: &str, radix: u32) -> Option<u64> {
    let line = text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))?;
    u64::from_str_radix(line.trim(), radix).ok()
}

#[test]
fn each_thread_of_the_role_holds_no_capability_after_the_bind() {
    let name = format!("podssh-t629-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let s = Scratch(std::env::temp_dir().join(name));
    std::fs::create_dir_all(s.0.join("cache")).unwrap();
    let (_, leaf, key) = ca_and_leaf("caps");
    let (cert, key_file) = (s.0.join("cert.pem"), s.0.join("key.pem"));
    replace(&cert, &leaf);
    replace(&key_file, &key);
    let (log, port_file) = (s.0.join("role.log"), s.0.join("port"));
    let role = podssh(&s.0)
        .args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone"])
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key_file)
        .arg("--port-file")
        .arg(&port_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let pid = role.id();
    let _role = Killed(role);
    // The port file is written once the runtime and its workers run.
    until("the role's port", &log, || {
        std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()).is_some_and(|p| p != 0)
    });
    let tasks = std::path::PathBuf::from(format!("/proc/{pid}/task"));
    let Ok(dir) = std::fs::read_dir(&tasks) else {
        eprintln!("did not run: {} cannot be read here", tasks.display());
        return;
    };
    // What the role started with: this test's sets, as an exec as root
    // gives each capability of the bounding set, and none to another user.
    let own = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    // SAFETY: geteuid(2) cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let ambient = value(&own, "CapAmb", 16).unwrap_or(0) != 0;
    let setpcap = root && value(&own, "CapBnd", 16).is_some_and(|b| (b >> SETPCAP) & 1 == 1);
    let mut threads = 0;
    for entry in dir.flatten() {
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else { continue };
        threads += 1;
        let set = |name: &str| value(&status, name, 16).unwrap_or_else(|| panic!("no {name} in {status}"));
        assert_eq!(
            (set("CapEff"), set("CapPrm"), set("CapInh")),
            (0, 0, 0),
            "a thread of the role keeps a capability after the bind: {status}"
        );
        assert_eq!(value(&status, "NoNewPrivs", 10), Some(1), "no new privileges on each thread: {status}");
        if setpcap {
            assert_eq!(set("CapBnd"), 0, "the bounding set goes with CAP_SETPCAP: {status}");
        }
    }
    assert!(threads >= 3, "the first thread, the command's and the runtime's: {threads}");
    let said = std::fs::read_to_string(&log).unwrap();
    let first = said.lines().next().unwrap_or_default();
    if root {
        assert!(first.contains("the capabilities of its start dropped after the bind"), "{first}");
        assert!(first.contains("stays uid 0"), "{first}");
    } else if !ambient {
        assert!(!first.contains("capabilities"), "a start with none says nothing of them: {first}");
    }
}
