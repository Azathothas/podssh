//! `podssh job` (T-193) against the test's SSH server, whose commands run
//! in sh as on a POSIX host (`job_harness`), so that the far script of the
//! binary runs as it runs there. With tmux: two jobs start, the list shows
//! both running, a stop of one ends its tmux session and leaves the other
//! running (the planted defect, a stop of each session named podssh-job-,
//! ends both), and the log gives a job's output after its end, with its
//! status in the list. With no tmux on PATH: start exits 255, names tmux,
//! and starts nothing. With no tmux on this host, the test of tmux says so
//! and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use job_harness::{on_path, scratch, Far};

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
    // A PATH of the tools that the far script needs, and no tmux.
    let bin = scratch("no-tmux-bin");
    for tool in ["sh", "mkdir", "cat", "mv", "rm"] {
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
