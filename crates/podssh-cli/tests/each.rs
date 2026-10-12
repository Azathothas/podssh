//! `podssh each` (T-183): the rule of the exit status, the statuses 0, 3
//! and 255 in each order; `--fail-fast`, which starts no host after a
//! failure; the refusals of the command line (64) against the binary,
//! offline; and real sessions against the test's SSH server on the
//! loopback: a line for each host with its label, a status file of
//! `--output-dir`, and a host key that no question can accept; and the
//! braces and the groups of T-184 through the binary. Against OpenSSH and
//! Dropbear it runs in the gate (`scripts/interop-each.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_cli::each::fan::{exit_status, fan_out, summary, Ended};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-each-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Each order of `items`.
fn orders<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut tail in orders(&rest) {
            tail.insert(0, first.clone());
            out.push(tail);
        }
    }
    out
}

#[test]
fn the_exit_is_the_largest_status_in_each_order() {
    let ends = [Ended::Status(0), Ended::Status(3), Ended::Failed("no connection".into())];
    assert_eq!(orders(&ends).len(), 6);
    for order in orders(&ends) {
        assert_eq!(exit_status(&order), 255, "{order:?}");
    }
    // The plant of the entry: the first host's status gives 0 here.
    for order in orders(&ends[..2]) {
        assert_eq!(exit_status(&order), 3, "{order:?}");
    }
    assert_eq!(exit_status(&[Ended::Status(0), Ended::Status(0)]), 0);
    assert_eq!(exit_status(&[Ended::Status(0), Ended::Status(255)]), 255, "a remote 255 counts as it is");
    assert_eq!(exit_status(&[Ended::Status(3), Ended::NotStarted]), 3, "a host that never ran adds nothing");
}

/// The fan-out with the ends of `given`, in that order of the hosts, the
/// first host's end at once and each other's after a second: which hosts
/// started, and the ends.
async fn fanned(given: &[Ended], parallel: usize, fail_fast: bool) -> (Vec<usize>, Vec<Ended>) {
    let started = Arc::new(Mutex::new(Vec::new()));
    let seen = started.clone();
    let ends = fan_out(given.len(), parallel, fail_fast, |i| {
        seen.lock().unwrap().push(i);
        let end = given[i].clone();
        async move {
            if i > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            end
        }
    })
    .await;
    let started = started.lock().unwrap().clone();
    (started, ends)
}

#[tokio::test(start_paused = true)]
async fn fail_fast_starts_no_host_after_a_failure_and_the_running_ones_end() {
    let given = [Ended::Status(3), Ended::Status(0), Ended::Status(0), Ended::Status(0)];
    // Two at once: the first fails while the second runs; the second ends,
    // and no other starts.
    let (started, ends) = fanned(&given, 2, true).await;
    assert_eq!(started, [0, 1]);
    assert_eq!(ends, [Ended::Status(3), Ended::Status(0), Ended::NotStarted, Ended::NotStarted]);
    assert_eq!(exit_status(&ends), 3);
    // Without it each host runs.
    let (started, ends) = fanned(&given, 2, false).await;
    assert_eq!(started, [0, 1, 2, 3]);
    assert_eq!(ends, given);
    // One at once, all good: each runs, in order.
    let good = [Ended::Status(0), Ended::Status(0), Ended::Status(0)];
    let (started, ends) = fanned(&good, 1, true).await;
    assert_eq!((started, exit_status(&ends)), (vec![0, 1, 2], 0));
    let lines = summary(&["a".to_string(), "bb".to_string()], &[Ended::Status(3), Ended::NotStarted]);
    assert_eq!(lines, ["2 hosts: 0 gave 0, 1 failed, 1 not started", "  a   3", "  bb  not started (--fail-fast)"]);
}

/// `podssh each` with `args`, its home in `home`, with no settings file and
/// no ssh_config: (exit code, stdout, stderr).
fn each(home: &Path, args: &[&str], offline: bool) -> (i32, String, String) {
    let mut words = vec!["each"];
    words.extend_from_slice(args);
    podssh(home, &words, offline, None)
}

/// `podssh` with `args`, its home in `home`, with the settings file
/// `settings` or none, and no ssh_config.
fn podssh(home: &Path, args: &[&str], offline: bool, settings: Option<&Path>) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", settings.map_or_else(|| "none".into(), |p| p.as_os_str().to_owned()))
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    if offline {
        cmd.env("PODSSH_OFFLINE", "1");
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn a_bad_command_line_is_64_before_anything_connects() {
    let home = scratch("refused");
    let dir = home.join("out").display().to_string();
    for (args, says) in [
        (&[][..], "give the hosts and the command"),
        (&["a,b"][..], "give the command to run on each host"),
        (&["a,,b", "--", "true"][..], "an empty host"),
        (&["--parallel", "0", "a", "--", "true"][..], "--parallel 0"),
        (&["--parallel", "65", "a", "--", "true"][..], "from 1 to 64"),
        // A name that the relay cannot carry; a blank would part two hosts.
        (&["a,bad!host", "--", "true"][..], "bad!host"),
        (&["-o", "SessionType=none", "a", "--", "true"][..], "SessionType"),
        (&["--output-dir", dir.as_str(), "Web1,web1", "--", "true"][..], "would share their files"),
        (&["--no-such-flag", "a", "--", "true"][..], "--no-such-flag"),
    ] {
        let (code, out, err) = each(&home, args, true);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
    assert!(!home.join("out").exists(), "a refusal made the files of --output-dir");
}

#[test]
fn offline_each_host_fails_with_255_and_is_named() {
    let home = scratch("offline");
    let (code, out, err) = each(&home, &["web1.example.org,u@web2.example.org", "--", "true"], true);
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("podssh each: 2 hosts: 0 gave 0, 2 failed, 0 not started"), "{err}");
    for host in ["web1.example.org", "u@web2.example.org"] {
        assert!(err.contains(&format!("podssh: {host}: ")), "{host}: {err}");
        assert!(err.contains(&format!("  {host}")), "{host}: {err}");
    }
    // -q: no word from podssh, and the same status.
    let (code, _, err) = each(&home, &["-q", "web1.example.org", "--", "true"], true);
    assert_eq!((code, err.as_str()), (255, ""));
}

/// Braces and groups (T-184), offline: `each` expands them before anything
/// connects, `ssh` takes a pattern of one host and refuses one of more,
/// naming `podssh each`, and a cycle of groups is the file's fault (78).
#[test]
fn braces_and_groups_give_the_hosts_and_ssh_takes_one() {
    let home = scratch("groups");
    let dir = home.join("conf");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let file = dir.join("settings");
    std::fs::write(&file, include_str!("fixtures/groups.settings")).unwrap();
    let run = |args: &[&str]| podssh(&home, args, true, Some(&file));
    let (code, _, err) = run(&["each", "@web,db{1..2}.example.org", "--", "true"]);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("podssh each: 5 hosts: 0 gave 0, 5 failed"), "{err}");
    for host in ["web01.example.org", "web03.example.org", "db2.example.org"] {
        assert!(err.contains(&format!("podssh: {host}: ")), "{host}: {err}");
    }
    for (args, says) in [
        (&["each", "web{3..1}", "--", "true"][..], "runs backwards"),
        (&["each", "@nope", "--", "true"][..], "no group of that name"),
        (&["ssh", "web{1..3}.example.org", "true"][..], "podssh each"),
        (&["ssh", "@web", "true"][..], "gives 3 hosts"),
        (&["ssh", "a,b", "true"][..], "gives 2 hosts"),
    ] {
        let (code, out, err) = run(args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says) && out.is_empty(), "{args:?}: {err}");
    }
    // A group of one host is that host: ssh goes on, and offline ends 255.
    let (code, _, err) = run(&["ssh", "@one", "true"]);
    assert_eq!(code, 255, "{err}");
    std::fs::write(&file, "[groups]\na @b\nb @a\n").unwrap();
    let (code, _, err) = run(&["each", "x", "--", "true"]);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("make a cycle"), "{err}");
}

/// The test's server on a runtime of its own, and a port where nothing
/// listens.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    (runtime, port, closed)
}

/// The flags of a run on the loopback: no relay, this test's known_hosts.
fn direct(home: &Path, accept: bool) -> Vec<String> {
    let known = home.join("known_hosts").display().to_string();
    let mut args = vec!["--direct".to_string(), "-o".into(), format!("UserKnownHostsFile={known}")];
    if accept {
        args.extend(["-o".into(), "StrictHostKeyChecking=accept-new".into()]);
    }
    args
}

/// What the summary says of `host`, after its label.
fn said_of<'a>(err: &'a str, host: &str) -> Option<&'a str> {
    err.lines()
        .filter_map(|l| l.strip_prefix("podssh each:   ")?.strip_prefix(host))
        .find(|rest| rest.starts_with(' '))
        .map(str::trim_start)
}

fn run(home: &Path, flags: &[String], hosts: &[String], command: &str) -> (i32, String, String) {
    let mut args: Vec<&str> = flags.iter().map(String::as_str).collect();
    let hosts = hosts.join(",");
    args.extend([hosts.as_str(), "--", command]);
    each(home, &args, false)
}

#[test]
fn each_order_of_0_127_and_255_exits_255_and_each_host_is_named() {
    let home = scratch("orders");
    let (_runtime, port, closed) = server(&home);
    let flags = direct(&home, true);
    // `cat` with no input ends with 0; for a user bare-..., whose host has no
    // cat, with 127; the closed port has no session.
    let hosts = [format!("a@127.0.0.1:{port}"), format!("bare-b@127.0.0.1:{port}"), format!("c@127.0.0.1:{closed}")];
    for order in orders(&hosts) {
        let (code, _, err) = run(&home, &flags, &order, "cat");
        assert_eq!(code, 255, "{order:?}: {err}");
        assert!(said_of(&err, &hosts[2]).is_some_and(|s| s.starts_with("255, no session")), "{order:?}: {err}");
        assert_eq!(said_of(&err, &hosts[1]), Some("127"), "{order:?}: {err}");
        assert!(err.contains(&format!("{}: sh: cat: not found", hosts[1])), "{order:?}: {err}");
    }
    for order in orders(&hosts[..2]) {
        let (code, _, err) = run(&home, &flags, &order, "cat");
        assert_eq!(code, 127, "{order:?}: {err}");
    }
    // Two sessions met the new host key at once: it is recorded once.
    let known = std::fs::read_to_string(home.join("known_hosts")).unwrap();
    assert_eq!(known.lines().count(), 1, "{known}");
}

#[test]
fn each_line_starts_with_its_host_or_goes_unchanged_to_its_files() {
    let home = scratch("lines");
    let (_runtime, port, _) = server(&home);
    let flags = direct(&home, true);
    let hosts = [format!("a@127.0.0.1:{port}"), format!("b@127.0.0.1:{port}")];
    // `exit 3` writes `out` on stdout and `err!` on stderr.
    let (code, out, err) = run(&home, &flags, &hosts, "exit 3");
    assert_eq!(code, 3, "{err}");
    for host in &hosts {
        assert!(out.lines().any(|l| l == format!("{host}: out")), "{out}");
        assert!(err.lines().any(|l| l == format!("{host}: err!")), "{err}");
    }
    assert_eq!(out.lines().count(), 2, "{out}");
    let dir = home.join("out");
    let mut with_dir = flags.clone();
    with_dir.extend(["--output-dir".to_string(), dir.display().to_string()]);
    let (code, out, err) = run(&home, &with_dir, &hosts, "exit 3");
    assert_eq!((code, out.as_str()), (3, ""), "{err}");
    for host in &hosts {
        let file = |ext: &str| std::fs::read(dir.join(format!("{}.{ext}", host.replace(':', "%3A")))).unwrap();
        let want = (b"out\n".to_vec(), b"err!\n".to_vec(), b"3\n".to_vec());
        assert_eq!((file("out"), file("err"), file("status")), want, "{host}");
    }
}

#[test]
fn fail_fast_starts_no_host_after_the_first_failed() {
    let home = scratch("fail-fast");
    let (_runtime, port, closed) = server(&home);
    let mut flags = direct(&home, true);
    flags.extend(["--parallel".to_string(), "1".into(), "--fail-fast".into()]);
    let hosts = [format!("c@127.0.0.1:{closed}"), format!("a@127.0.0.1:{port}")];
    let (code, out, err) = run(&home, &flags, &hosts, "exit 0");
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "the second host ran: {out}");
    assert_eq!(said_of(&err, &hosts[1]), Some("not started (--fail-fast)"), "{err}");
}

#[test]
fn an_unknown_host_key_refuses_its_host_and_names_accept_new() {
    let home = scratch("host-key");
    let (_runtime, port, _) = server(&home);
    let host = format!("a@127.0.0.1:{port}");
    let (code, out, err) = run(&home, &direct(&home, false), std::slice::from_ref(&host), "exit 0");
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains(&format!("podssh: {host}: host key verification failed")), "{err}");
    assert!(err.contains("SHA256:") && err.contains("StrictHostKeyChecking=accept-new"), "{err}");
    assert!(!home.join("known_hosts").exists(), "a key was recorded with no question");
}
