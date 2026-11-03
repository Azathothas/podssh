//! `podssh job` (T-193) against the test's SSH server, whose commands run
//! in sh as on a POSIX host (`job_harness`), so that the far script of the
//! binary runs as it runs there. With tmux: two jobs start, the list shows
//! both running, a stop of one ends its tmux session and leaves the other
//! running (the planted defect, a stop of each session named podssh-job-,
//! ends both), and the log gives a job's output after its end, with its
//! status in the list. With no tmux on PATH: start exits 255, names tmux,
//! and starts nothing; with a stand-in apt-get there, start and --persist
//! name the command that installs it (T-481). With --no-tmux, with no tmux
//! on PATH (T-481): two jobs run under nohup, a stop of one ends it and
//! leaves the other, a job's status stays, a PID file that names another
//! process never gets it signalled (the planted defect, a stop by the PID
//! of the file, kills it), and with no setsid a stop ends the command and
//! the server lives. With no tmux on this host, the test of tmux says so
//! and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use job_harness::{alive, bin_of, on_path, scratch, Far};

/// The tools of the far script with no tmux, and setsid where this host
/// has it.
fn plain_tools(setsid: bool) -> Vec<&'static str> {
    let mut tools = vec!["sh", "mkdir", "cat", "mv", "rm", "sleep", "nohup"];
    if setsid && on_path("setsid").is_some() {
        tools.push("setsid");
    }
    tools
}

/// Whether the process `pid` ends within 20 s.
fn ends(pid: i32) -> bool {
    let until = Instant::now() + Duration::from_secs(20);
    while alive(pid) {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

/// `podssh job start --no-tmux HOST -- COMMAND`: the ID that it printed.
fn start_plain(far: &Far, command: &str) -> String {
    let (code, out, err) = far.job("start", &["--no-tmux", "--", command]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim().to_string();
    assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{out}");
    id
}

#[test]
fn two_jobs_run_and_a_stop_of_one_leaves_the_other() {
    let Some(far) = Far::with_tmux("two") else { return };
    let (a, b) = (far.start("sleep 300"), far.start("sleep 300"));
    let (code, list, err) = far.job("list", &[]);
    assert_eq!(code, 0, "{err}");
    for id in [&a, &b] {
        let running = |l: &str| l.starts_with(id.as_str()) && l.contains("running") && l.ends_with("sleep 300");
        assert!(list.lines().any(running), "{id}: {list}");
    }
    assert!(far.has_session(&format!("podssh-job-{a}")));
    let (code, _, err) = far.job("stop", &[a.as_str()]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("stopped"), "{err}");
    assert!(!far.has_session(&format!("podssh-job-{a}")), "the stopped job's session is gone");
    let (_, list, _) = far.job("list", &[]);
    assert!(!list.contains(&a), "{list}");
    // The planted defect ends each session named podssh-job-: the other job
    // would be lost here.
    assert!(list.lines().any(|l| l.starts_with(b.as_str()) && l.contains("running")), "{list}");
    assert!(far.has_session(&format!("podssh-job-{b}")));
    // A job that prints and ends: its output and its status stay.
    let c = far.start("printf 'J\\n'; exit 5");
    let line = far.line_of(&c, Duration::from_secs(20), |l| l.contains("done")).expect("the job is listed");
    assert!(line.contains("done") && line.contains("  5  "), "{line}");
    let (code, out, err) = far.job("log", &[c.as_str()]);
    assert_eq!((code, out.as_str()), (0, "J\n"), "{err}");
    for id in [&b, &c] {
        assert_eq!(far.job("stop", &[id.as_str()]).0, 0);
    }
    let (_, list, _) = far.job("list", &[]);
    assert_eq!(list, "", "each job is removed");
}

#[test]
fn with_no_tmux_start_exits_255_names_tmux_and_starts_nothing() {
    // A PATH of the tools that the far script needs, sleep among them
    // (T-481), and no tmux.
    let bin = scratch("no-tmux-bin");
    for tool in ["sh", "mkdir", "cat", "mv", "rm", "sleep"] {
        let found = on_path(tool).unwrap_or_else(|| panic!("{tool} is on no PATH of this host"));
        std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
    }
    let far = Far::new("no-tmux", bin.display().to_string(), None);
    let (code, out, err) = far.job("start", &["--", "sleep", "300"]);
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("has no tmux on PATH") && err.contains("starts none"), "{err}");
    let jobs = far.home.join(".podssh/jobs");
    let names: Vec<String> =
        std::fs::read_dir(&jobs).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, ["jobs.sh"], "no job was made");
    let mode = std::fs::metadata(&jobs).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "the jobs' directory is the user's alone");
    let (code, out, err) = far.job("list", &[]);
    assert_eq!((code, out.as_str()), (0, ""), "{err}");
    let (code, _, err) = far.job("log", &["00000000"]);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("has no job 00000000"), "{err}");
}

/// T-481: the far host has no tmux and a package manager, a stand-in that
/// nothing runs; the refusals of `job start` and of `ssh --persist` name
/// the command that installs tmux, and `job` names --no-tmux. Whether sudo
/// comes first or "(as root)" after depends on the user that runs the test.
#[test]
fn with_no_tmux_and_apt_get_start_and_persist_name_the_command_that_installs_it() {
    let bin = bin_of("hint-bin", &["sh", "mkdir", "cat", "mv", "rm", "sleep"], &["apt-get"]);
    let far = Far::new("hint", bin.display().to_string(), None);
    let (code, out, err) = far.job("start", &["--", "sleep", "300"]);
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("has no tmux on PATH") && err.contains("apt-get install -y tmux"), "{err}");
    assert!(err.contains("--no-tmux runs the job without it"), "{err}");
    let host = far.host();
    let (code, _, err) = far.podssh("ssh", &["--persist", "-o", "BatchMode=yes", host.as_str()]);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("the server has no tmux on PATH; --persist needs it; to install it"), "{err}");
    assert!(err.contains("apt-get install -y tmux"), "{err}");
}

/// T-481: with --no-tmux and no tmux on PATH, two jobs run; a stop of one
/// ends its command and leaves the other; a job that ends keeps its
/// status and its output.
#[test]
fn with_no_tmux_two_jobs_run_and_a_stop_of_one_leaves_the_other() {
    let bin = bin_of("plain-bin", &plain_tools(true), &[]);
    let far = Far::new("plain", bin.display().to_string(), None);
    let a = start_plain(&far, "echo $$ > a.pid; exec sleep 300");
    let b = start_plain(&far, "echo $$ > b.pid; exec sleep 300");
    let (apid, bpid) = (far.pid_in("a.pid"), far.pid_in("b.pid"));
    let (code, list, err) = far.job("list", &[]);
    assert_eq!(code, 0, "{err}");
    for id in [&a, &b] {
        assert!(list.lines().any(|l| l.starts_with(id.as_str()) && l.contains("running")), "{id}: {list}");
    }
    let (code, _, err) = far.job("stop", &[a.as_str()]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("stopped"), "{err}");
    assert!(ends(apid), "the stopped job's command ends");
    assert!(alive(bpid), "the other job's command runs on");
    let (_, list, _) = far.job("list", &[]);
    assert!(!list.contains(&a) && list.lines().any(|l| l.starts_with(b.as_str()) && l.contains("running")), "{list}");
    let c = start_plain(&far, "printf 'J\\n'; exit 5");
    let line = far.line_of(&c, Duration::from_secs(20), |l| l.contains("done")).expect("the job is listed");
    assert!(line.contains("done") && line.contains("  5  "), "{line}");
    let (code, out, err) = far.job("log", &[c.as_str()]);
    assert_eq!((code, out.as_str()), (0, "J\n"), "{err}");
    for id in [&b, &c] {
        assert_eq!(far.job("stop", &[id.as_str()]).0, 0);
    }
    assert!(ends(bpid));
    assert_eq!(far.job("list", &[]).1, "", "each job is removed");
}

/// T-481: a PID file that names another process, a `sleep` of the test's:
/// the stop never signals it, as only the runner signals, and only its own
/// child. The planted defect, a stop that sends TERM to the PID of the
/// file, ends the test's sleep.
#[test]
fn a_pid_file_that_names_another_process_never_gets_it_signalled() {
    let bin = bin_of("pidfile-bin", &plain_tools(true), &[]);
    let far = Far::new("pidfile", bin.display().to_string(), None);
    let id = start_plain(&far, "echo $$ > x.pid; exec sleep 300");
    let xpid = far.pid_in("x.pid");
    let mut other = std::process::Command::new("sleep").arg("300").spawn().expect("a sleep of the test's");
    let dir = far.job_dir(&id).expect("the job's directory");
    // The runner wrote its own PID; the test's process takes its place.
    std::fs::write(dir.join("pid"), format!("{}\n", other.id())).unwrap();
    let _ = std::fs::remove_file(dir.join("pid.start"));
    let (code, _, err) = far.job("stop", &[id.as_str()]);
    let lives = other.try_wait().unwrap().is_none();
    let _ = other.kill();
    let _ = other.wait();
    assert_eq!(code, 0, "{err}");
    assert!(lives, "the process that the PID file named was signalled: {err}");
    assert!(ends(xpid), "the job's own command ends, by its runner");
}

/// T-481: with no setsid on PATH, the runner leads no group of its own, so
/// TERM goes to the command alone: the command ends, and the test's server,
/// in whose process group the runner is, lives and answers.
#[test]
fn with_no_setsid_a_stop_ends_the_command_and_the_server_lives() {
    let bin = bin_of("nosetsid-bin", &plain_tools(false), &[]);
    let far = Far::new("nosetsid", bin.display().to_string(), None);
    let id = start_plain(&far, "echo $$ > s.pid; exec sleep 300");
    let spid = far.pid_in("s.pid");
    let (code, _, err) = far.job("stop", &[id.as_str()]);
    assert_eq!(code, 0, "{err}");
    assert!(ends(spid), "the command ends");
    let (code, list, err) = far.job("list", &[]);
    assert_eq!((code, list.as_str()), (0, ""), "the server answers: {err}");
}
