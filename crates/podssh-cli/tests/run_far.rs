//! `podssh run` (T-192) against the test's SSH server, whose commands run
//! in sh as on a POSIX host and whose subsystem sftp is OpenSSH's
//! `sftp-server` in the same home (`job_harness`). A project holds `run.sh`
//! (`exit 6`), `target/big.bin`, `src/a.txt`, and a `.podsshignore` that
//! leaves out `*.tmp`: the run exits 6, and `target/` and `x.tmp` are not on
//! the server (the planted defect, no default excludes, copies `target/`);
//! a second run sends no file; after a change, one. Each run's summary says
//! so with no `-v`, before the command's output (T-472). With no
//! `sftp-server` on this host, the test says so and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use job_harness::{scratch, Far};

/// What the run's summary said of its copy, at the default level (T-472):
/// `N copied (BYTES), M unchanged, in S s (RATE/s)`.
fn copied(err: &str) -> Option<&str> {
    err.lines().filter_map(|l| l.strip_prefix("podssh: ")).find(|l| l.contains(" copied"))
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
    // run's destination is [user@]host[:DIR], as cp's: the port goes with -p.
    let port = far.port.to_string();
    // With no -v: the summary is at the default level (T-472).
    let run =
        || far.podssh("run", &["--from", from.as_str(), "-p", port.as_str(), "a@127.0.0.1", "--", "sh", "run.sh"]);
    let (code, out, err) = run();
    assert_eq!(code, 6, "{err}");
    assert_eq!(out, "ran\n", "the command's output, on stdout");
    let there = far.home.join(".podssh").join("run").join("proj");
    assert!(there.join("run.sh").is_file() && there.join("src").join("a.txt").is_file(), "{err}");
    assert!(there.join(".podsshignore").is_file(), "the ignore file is the project's, and goes");
    assert!(!there.join("target").exists(), "target/ is never copied");
    assert!(!there.join("x.tmp").exists(), ".podsshignore leaves *.tmp out");
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("3 copied (") && !said.contains("unchanged"), "{err}");
    // As it was: nothing goes again.
    let (code, _, err) = run();
    assert_eq!(code, 6, "{err}");
    assert!(copied(&err).is_some_and(|said| said.starts_with("0 copied, 3 unchanged, in ")), "{err}");
    // One file changed: it alone goes.
    std::fs::write(proj.join("src").join("a.txt"), "a, and more\n").unwrap();
    let (code, _, err) = run();
    assert_eq!(code, 6, "{err}");
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("1 copied (") && said.contains(", 2 unchanged, in "), "{err}");
    assert_eq!(std::fs::read_to_string(there.join("src").join("a.txt")).unwrap(), "a, and more\n");
}
