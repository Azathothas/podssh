//! `podssh run` (T-192) against the test's SSH server, whose commands run
//! in sh as on a POSIX host and whose subsystem sftp is OpenSSH's
//! `sftp-server` in the same home (`job_harness`). A project holds `run.sh`
//! (`exit 6`), `target/big.bin`, `src/a.txt`, and a `.podsshignore` that
//! leaves out `*.tmp`: the run exits 6, and `target/` and `x.tmp` are not on
//! the server (the planted defect, no default excludes, copies `target/`);
//! a second run sends no file; after a change, one. Each run's summary says
//! so with no `-v`, before the command's output (T-472), and counts the 2
//! paths that the excludes left out (T-475). `--dry-run` plans the copy and
//! names the command, and changes and runs nothing (the planted defect, a
//! dry run that runs its command, is caught by the look for its output);
//! `--no-ignore` sends `target/` and `x.tmp` (T-475). With no `sftp-server`
//! on this host, each test says so and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use std::path::{Path, PathBuf};

use job_harness::{scratch, Far};

/// What the run's summary said of its copy, at the default level (T-472):
/// `N copied (BYTES), M unchanged, in S s (RATE/s)`.
fn copied(err: &str) -> Option<&str> {
    err.lines().filter_map(|l| l.strip_prefix("podssh: ")).find(|l| l.contains(" copied"))
}

/// A far host of the test, or `None` when this host has no `sftp-server`,
/// said.
fn far(name: &str) -> Option<Far> {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return None;
    }
    Some(Far::new(name, std::env::var("PATH").unwrap_or_default(), None))
}

/// The project of the tests: `run.sh` (`echo ran; exit 6`), `src/a.txt`,
/// `target/big.bin`, `x.tmp`, and a `.podsshignore` that leaves out `*.tmp`.
fn project(name: &str) -> PathBuf {
    let proj = scratch(name).join("proj");
    std::fs::create_dir_all(proj.join("target")).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("run.sh"), "echo ran; exit 6\n").unwrap();
    std::fs::write(proj.join("target").join("big.bin"), vec![7u8; 1 << 20]).unwrap();
    std::fs::write(proj.join("src").join("a.txt"), "a\n").unwrap();
    std::fs::write(proj.join(".podsshignore"), "*.tmp\n").unwrap();
    std::fs::write(proj.join("x.tmp"), "scratch\n").unwrap();
    proj
}

/// `podssh run FLAGS... --from PROJ -p PORT a@127.0.0.1 -- sh run.sh`, with
/// no -v: (exit code, stdout, stderr).
fn run(far: &Far, proj: &Path, flags: &[&str]) -> (i32, String, String) {
    let (from, port) = (proj.display().to_string(), far.port.to_string());
    // run's destination is [user@]host[:DIR], as cp's: the port goes with -p.
    let mut args: Vec<&str> = flags.to_vec();
    args.extend(["--from", from.as_str(), "-p", port.as_str(), "a@127.0.0.1", "--", "sh", "run.sh"]);
    far.podssh("run", &args)
}

#[test]
fn a_run_copies_what_changed_leaves_out_target_and_gives_the_status() {
    let Some(far) = far("run") else { return };
    let proj = project("run-project");
    // With no -v: the summary is at the default level (T-472).
    let (code, out, err) = run(&far, &proj, &[]);
    assert_eq!(code, 6, "{err}");
    assert_eq!(out, "ran\n", "the command's output, on stdout");
    let there = far.home.join(".podssh").join("run").join("proj");
    assert!(there.join("run.sh").is_file() && there.join("src").join("a.txt").is_file(), "{err}");
    assert!(there.join(".podsshignore").is_file(), "the ignore file is the project's, and goes");
    assert!(!there.join("target").exists(), "target/ is never copied");
    assert!(!there.join("x.tmp").exists(), ".podsshignore leaves *.tmp out");
    // target/ and x.tmp: the paths that the excludes left out (T-475).
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("3 copied (") && !said.contains("unchanged"), "{err}");
    assert!(said.contains(", 2 left out, in "), "{err}");
    // As it was: nothing goes again.
    let (code, _, err) = run(&far, &proj, &[]);
    assert_eq!(code, 6, "{err}");
    assert!(copied(&err).is_some_and(|said| said.starts_with("0 copied, 3 unchanged, 2 left out, in ")), "{err}");
    // One file changed: it alone goes.
    std::fs::write(proj.join("src").join("a.txt"), "a, and more\n").unwrap();
    let (code, _, err) = run(&far, &proj, &[]);
    assert_eq!(code, 6, "{err}");
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("1 copied (") && said.contains(", 2 unchanged, 2 left out, in "), "{err}");
    assert_eq!(std::fs::read_to_string(there.join("src").join("a.txt")).unwrap(), "a, and more\n");
}

/// The lines of a dry run's plan that copy a file, by the path under the
/// project: `copy PROJ/PATH -> .podssh/run/proj/PATH`.
fn copies(out: &str, proj: &Path) -> Vec<String> {
    let mut paths: Vec<String> = out
        .lines()
        .filter_map(|l| l.strip_prefix("copy "))
        .filter_map(|l| l.split_once(" -> "))
        .map(|(from, to)| {
            let rel = from.strip_prefix(&format!("{}/", proj.display())).unwrap_or(from).to_string();
            assert_eq!(to, format!(".podssh/run/proj/{rel}"), "the far name of {from}");
            rel
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn a_dry_run_plans_the_copy_and_the_command_and_changes_nothing() {
    let Some(far) = far("run-dry") else { return };
    let proj = project("run-dry-project");
    let (code, out, err) = run(&far, &proj, &["--dry-run"]);
    assert!(!out.lines().any(|l| l == "ran"), "a dry run ran the command: {out}{err}");
    assert_eq!(code, 0, "{err}");
    // A copy for each file that would go, and nothing that the excludes
    // leave out; then the command, last.
    assert_eq!(copies(&out, &proj), [".podsshignore", "run.sh", "src/a.txt"], "{out}");
    for dir in ["mkdir .podssh", "mkdir .podssh/run", "mkdir .podssh/run/proj", "mkdir .podssh/run/proj/src"] {
        assert!(out.lines().any(|l| l == dir), "{dir}: {out}");
    }
    assert!(!out.contains("target") && !out.contains("x.tmp"), "{out}");
    assert_eq!(out.lines().last(), Some("run cd '.podssh/run/proj' && sh run.sh"), "{out}");
    assert!(!far.home.join(".podssh").exists(), "a dry run made nothing on the server");
    assert!(err.contains("2 paths left out by the excludes"), "{err}");
    assert!(copied(&err).is_none(), "a dry run gives no summary: {err}");
}

#[test]
fn a_dry_run_after_a_change_plans_that_file_alone_and_runs_nothing() {
    let Some(far) = far("run-dry-again") else { return };
    let proj = project("run-dry-again-project");
    let (code, _, err) = run(&far, &proj, &[]);
    assert_eq!(code, 6, "{err}");
    let there = far.home.join(".podssh").join("run").join("proj");
    std::fs::write(proj.join("src").join("a.txt"), "a, and more\n").unwrap();
    let (code, out, err) = run(&far, &proj, &["--dry-run"]);
    // First, so that the planted defect, a dry run that runs its command,
    // fails here.
    assert!(!out.lines().any(|l| l == "ran"), "a dry run ran the command: {out}{err}");
    assert_eq!(code, 0, "{err}");
    let plan: Vec<&str> = out.lines().collect();
    assert_eq!(plan.len(), 2, "the changed file, then the command: {out}");
    assert_eq!(copies(&out, &proj), ["src/a.txt"], "{out}");
    assert_eq!(plan[1], "run cd '.podssh/run/proj' && sh run.sh");
    assert_eq!(std::fs::read_to_string(there.join("src").join("a.txt")).unwrap(), "a\n", "nothing changed there");
    // As it was once more: the plan is the command alone.
    let (code, _, err) = run(&far, &proj, &[]);
    assert_eq!(code, 6, "{err}");
    let (code, out, err) = run(&far, &proj, &["--dry-run"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "run cd '.podssh/run/proj' && sh run.sh\n");
}

#[test]
fn no_ignore_sends_target_and_what_the_ignore_file_names() {
    let Some(far) = far("run-noignore") else { return };
    let proj = project("run-noignore-project");
    let (code, out, err) = run(&far, &proj, &["--no-ignore"]);
    assert_eq!(code, 6, "{err}");
    assert_eq!(out, "ran\n", "{err}");
    let there = far.home.join(".podssh").join("run").join("proj");
    assert!(there.join("target").join("big.bin").is_file(), "--no-ignore sends target/: {err}");
    assert!(there.join("x.tmp").is_file(), "--no-ignore reads no .podsshignore: {err}");
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("5 copied (") && !said.contains("left out"), "{err}");
    // --exclude still applies with it.
    std::fs::write(proj.join("y.log"), "log\n").unwrap();
    let (code, _, err) = run(&far, &proj, &["--no-ignore", "--exclude", "*.log"]);
    assert_eq!(code, 6, "{err}");
    assert!(!there.join("y.log").exists(), "--exclude with --no-ignore: {err}");
    let said = copied(&err).unwrap_or_default();
    assert!(said.starts_with("0 copied, 5 unchanged, 1 left out, in "), "{err}");
}
