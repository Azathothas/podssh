//! `podssh run` (T-192) against the test's SSH server, whose commands run
//! in sh as on a POSIX host and whose subsystem sftp is OpenSSH's
//! `sftp-server` in the same home (`job_harness`). A project holds `run.sh`
//! (`exit 6`), `target/big.bin`, `src/a.txt`, and a `.podsshignore` that
//! leaves out `*.tmp`: the run exits 6, and `target/` and `x.tmp` are not on
//! the server (the planted defect, no default excludes, copies `target/`);
//! a second run sends no file; after a change, one. With no `sftp-server`
//! on this host, the test says so and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use job_harness::{scratch, Far};

/// What the run said of its copy, with -v: `files sent N, unchanged M`.
fn copied(err: &str) -> Option<&str> {
    err.lines().find_map(|l| l.split_once(": files sent ").map(|(_, rest)| rest))
}

#[test]
fn a_run_copies_what_changed_leaves_out_target_and_gives_the_status() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let far = Far::new("run", std::env::var("PATH").unwrap_or_default(), None);
    let proj = scratch("run-project").join("proj");
    std::fs::create_dir_all(proj.join("target")).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("run.sh"), "echo ran; exit 6\n").unwrap();
    std::fs::write(proj.join("target").join("big.bin"), vec![7u8; 1 << 20]).unwrap();
    std::fs::write(proj.join("src").join("a.txt"), "a\n").unwrap();
    std::fs::write(proj.join(".podsshignore"), "*.tmp\n").unwrap();
    std::fs::write(proj.join("x.tmp"), "scratch\n").unwrap();
    let from = proj.display().to_string();
    let host = far.host();
    let run = || far.podssh("run", &["-v", "--from", from.as_str(), host.as_str(), "--", "sh", "run.sh"]);
    let (code, out, err) = run();
    assert_eq!(code, 6, "{err}");
    assert_eq!(out, "ran\n", "the command's output, on stdout");
    let there = far.home.join(".podssh").join("run").join("proj");
    assert!(there.join("run.sh").is_file() && there.join("src").join("a.txt").is_file(), "{err}");
    assert!(there.join(".podsshignore").is_file(), "the ignore file is the project's, and goes");
    assert!(!there.join("target").exists(), "target/ is never copied");
    assert!(!there.join("x.tmp").exists(), ".podsshignore leaves *.tmp out");
    assert_eq!(copied(&err), Some("3, unchanged 0"), "{err}");
    // As it was: nothing goes again.
    let (code, _, err) = run();
    assert_eq!(code, 6, "{err}");
    assert_eq!(copied(&err), Some("0, unchanged 3"), "{err}");
    // One file changed: it alone goes.
    std::fs::write(proj.join("src").join("a.txt"), "a, and more\n").unwrap();
    let (code, _, err) = run();
    assert_eq!(code, 6, "{err}");
    assert_eq!(copied(&err), Some("1, unchanged 2"), "{err}");
    assert_eq!(std::fs::read_to_string(there.join("src").join("a.txt")).unwrap(), "a, and more\n");
}
