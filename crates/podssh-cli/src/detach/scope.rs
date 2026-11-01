//! On Linux a detached run leaves the scope of the user's login session for
//! a scope of its own in the user's systemd, as tmux does, so that logind's
//! `KillUserProcesses` at a logout does not end it (T-381; the operator's
//! ruling of Q61). Asked once the run is ready, over D-Bus on a socket of
//! this host; a failure is a line in the run's log, never its end.
//! `PODSSH_SYSTEMD=no` asks nothing; `yes` asks outside a session scope too.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::dbus::{Bus, Call, Writer};

/// The variable that turns the request off (`no`) or asks always (`yes`).
pub const VARIABLE: &str = "PODSSH_SYSTEMD";
/// The bound of each read and write on the socket, and of the wait for the
/// run's cgroup to move.
const LIMIT: Duration = Duration::from_secs(3);

/// The run's cgroup of the unified hierarchy, from `/proc/self/cgroup`.
pub fn cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_string)
}

/// Whether `path` is the scope of a login session of logind.
pub fn in_session(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|leaf| leaf.starts_with("session-") && leaf.ends_with(".scope"))
}

/// The scope's name for the run of `pid`.
pub fn unit_name(pid: u32) -> String {
    format!("podssh-detached-{pid}.scope")
}

/// The body of `StartTransientUnit` (`ssa(sv)a(sa(sv))`): the scope `unit`,
/// the mode `fail`, the processes `pids` and a description; no auxiliary
/// units.
pub fn start_body(unit: &str, pids: &[u32], description: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(unit);
    w.string("fail");
    w.array(8, |w| {
        w.align(8);
        w.string("PIDs");
        w.signature("au");
        w.array(4, |w| pids.iter().for_each(|p| w.u32(*p)));
        w.align(8);
        w.string("Description");
        w.signature("s");
        w.string(description);
    });
    w.array(8, |_| {});
    w.buf
}

/// The sockets to ask, the user's bus first, then the private socket of
/// the user's systemd, which is a peer that takes no `Hello`.
fn sockets() -> Vec<(PathBuf, bool)> {
    let mut found = Vec::new();
    if let Ok(address) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        for part in address.split(';') {
            let path = part
                .strip_prefix("unix:")
                .and_then(|rest| rest.split(',').find_map(|kv| kv.strip_prefix("path=")).map(PathBuf::from));
            found.extend(path.map(|p| (p, true)));
        }
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    // The user's runtime directory: logind's, unless the environment names
    // another.
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    found.push((runtime.join("bus"), true));
    found.push((runtime.join("systemd").join("private"), false));
    found.dedup();
    found
}

/// Ask for the scope of `pids` (this run, and its supervisor's when it has
/// one): the line to say, or nothing when nothing was asked.
pub fn leave_session(pids: &[u32]) -> Option<String> {
    let wanted = std::env::var(VARIABLE).unwrap_or_default();
    if wanted == "no" {
        return None;
    }
    let before = cgroup()?;
    if wanted != "yes" && !in_session(&before) {
        return None;
    }
    let pid = std::process::id();
    let unit = unit_name(pid);
    let body = start_body(&unit, pids, &format!("podssh --detach, pid {pid}"));
    let mut tried = Vec::new();
    for (path, bus) in sockets() {
        if !path.exists() {
            continue;
        }
        let call = Call {
            destination: bus.then_some("org.freedesktop.systemd1"),
            path: "/org/freedesktop/systemd1",
            interface: "org.freedesktop.systemd1.Manager",
            member: "StartTransientUnit",
            signature: "ssa(sv)a(sa(sv))",
            body: &body,
        };
        match Bus::connect(&path, bus, LIMIT).and_then(|mut b| b.call(&call)) {
            Ok(_) => return Some(moved(&unit, &before)),
            Err(why) => tried.push(why),
        }
    }
    let why = match tried.is_empty() {
        true => "no socket of the user's D-Bus or systemd was found".to_string(),
        false => tried.join("; "),
    };
    Some(format!(
        "the run stays in {before}, which a logout may end: the user's systemd gave it no scope ({why}); {VARIABLE}=no asks nothing"
    ))
}

/// The line once systemd took the request: the run's cgroup read again
/// until it names `unit`, for the limit at most.
fn moved(unit: &str, before: &str) -> String {
    let end = Instant::now() + LIMIT;
    loop {
        let now = cgroup().unwrap_or_default();
        if now.ends_with(&format!("/{unit}")) {
            return moved_line(unit, before, lingering());
        }
        if Instant::now() >= end {
            return format!("the user's systemd took the scope {unit}, but the run's cgroup is still {now}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What a run in its scope can count on: the user's systemd, and its
/// scopes, stay after the user's last logout only with lingering on.
fn moved_line(unit: &str, before: &str, lingering: Option<bool>) -> String {
    let left = format!("the run left {before} for the scope {unit} of the user's systemd");
    match lingering {
        Some(false) => format!(
            "{left}: a logout does not end it while another session of the user stays; lingering is off, so the \
             user's last logout ends the user's systemd and the run with it (loginctl enable-linger keeps them)"
        ),
        _ => format!("{left}: a logout does not end it"),
    }
}

/// Whether logind keeps this user's systemd with no session
/// (`/var/lib/systemd/linger/NAME`); `None` where that is not known.
fn lingering() -> Option<bool> {
    let dir = std::path::Path::new("/var/lib/systemd/linger");
    if !dir.is_dir() {
        return None;
    }
    // SAFETY: passwd is plain data, for which all zeros is a value.
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut text = vec![0 as libc::c_char; 4096];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes into `record` and `text`, which outlive the
    // call, and sets `found` to `record` or to null.
    let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut record, text.as_mut_ptr(), text.len(), &mut found) };
    if rc != 0 || found.is_null() {
        return None;
    }
    // SAFETY: pw_name points into `text`, a NUL-terminated string.
    let name = unsafe { std::ffi::CStr::from_ptr(record.pw_name) }.to_str().ok()?.to_string();
    Some(dir.join(name).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With lingering off, the line says that the user's last logout still
    /// ends the run; on, or not known, that a logout does not.
    #[test]
    fn the_line_says_what_lingering_off_leaves() {
        let off = moved_line("u.scope", "/s/session-1.scope", Some(false));
        assert!(off.contains("lingering is off") && off.contains("loginctl enable-linger"), "{off}");
        for on in [Some(true), None] {
            let line = moved_line("u.scope", "/s/session-1.scope", on);
            assert!(line.ends_with("a logout does not end it"), "{line}");
        }
    }

    #[test]
    fn a_session_scope_is_known_by_its_leaf() {
        assert!(in_session("/user.slice/user-1000.slice/session-3.scope"));
        assert!(!in_session("/user.slice/user-1000.slice/user@1000.service/app.slice/podssh-detached-9.scope"));
        assert!(!in_session("/"));
        assert_eq!(unit_name(42), "podssh-detached-42.scope");
    }

    /// The body that sd-bus's `busctl call ... StartTransientUnit
    /// 'ssa(sv)a(sa(sv))' u.scope fail 2 PIDs au 1 7 Description s d 0`
    /// sent, captured from a dbus-daemon with `dbus-monitor --pcap`
    /// (systemd's busctl, 2026-11-01).
    const BUSCTL: &str = "07000000752e73636f706500040000006661696c00000000320000000000000004000000\
                          50494473000261750000000004000000070000000b0000004465736372697074696f6e00\
                          01730000010000006400000000000000";

    #[test]
    fn the_body_is_the_bytes_that_sd_bus_sends() {
        let want: Vec<u8> =
            (0..BUSCTL.len()).step_by(2).map(|i| u8::from_str_radix(&BUSCTL[i..i + 2], 16).unwrap()).collect();
        assert_eq!(start_body("u.scope", &[7], "d"), want);
    }

    #[test]
    fn the_body_aligns_each_struct_at_8_and_ends_with_an_empty_array() {
        let b = start_body("u.scope", &[7], "d");
        // "u.scope": 4 + 7 + 1 = 12; "fail": at 12, 4 + 4 + 1 -> 21; the
        // array's length at 24, its first struct at 32.
        assert_eq!(&b[12..16], &4u32.to_le_bytes());
        assert_eq!(&b[32..36], &4u32.to_le_bytes(), "the key PIDs at 32");
        // After the first array, the empty one: its length 0 at 4, then
        // the padding to its elements' 8.
        let len = u32::from_le_bytes(b[24..28].try_into().unwrap()) as usize;
        let at = (32 + len).div_ceil(4) * 4;
        assert_eq!(&b[at..at + 4], &0u32.to_le_bytes());
        assert_eq!(b.len(), (at + 4).div_ceil(8) * 8);
    }
}
