//! `podssh doctor` as a process: the report on stdout, the counts, the exit
//! code, and nothing secret in the output. The default tests run offline
//! (`PODSSH_OFFLINE`), where the network checks must be reported as not
//! attempted, never as passing. The live test is opt-in:
//!
//! ```sh
//! cargo test -p podssh-cli --test doctor -- --ignored
//! ```

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Every variable that could steer the doctor somewhere this test did not
/// choose.
const STEERING: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "PODSSH_RELAY",
    "PODSSH_RELAY_ADDR",
    "PODSSH_RELAY_TOKEN",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
];

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// A fresh directory to stand in for HOME, removed when the test ends. The
/// count of the calls tells apart two tests that run at once, as the time
/// alone may not (two calls can read the same clock, as on Windows).
fn scratch_home() -> PathBuf {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-doctor-test-{}-{call}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Run `podssh doctor ARGS` with HOME in a scratch directory, nothing
/// steering it but `set`, and every variable in `unset` removed.
fn doctor(args: &[&str], set: &[(&str, &str)], unset: &[&str], offline: bool) -> Run {
    let home = scratch_home();
    let run = doctor_in(&home, args, set, unset, offline);
    let _ = std::fs::remove_dir_all(&home);
    run
}

/// One doctor at a time: each copies its binary into the directories that it
/// probes, and two copies of a debug build at once filled /dev/shm in the
/// container (measured), which changed what the other run reported.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// As [`doctor`], with HOME in `home`, which the caller removes.
fn doctor_in(home: &Path, args: &[&str], set: &[(&str, &str)], unset: &[&str], offline: bool) -> Run {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", home).env("USERPROFILE", home);
    for name in STEERING {
        cmd.env_remove(name);
    }
    if offline {
        cmd.env("PODSSH_OFFLINE", "1");
    } else {
        cmd.env_remove("PODSSH_OFFLINE");
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    for name in unset {
        cmd.env_remove(name);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("the podssh binary runs");
    // The report is read as it comes, so a long one cannot fill the pipe
    // and hold the process.
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || std::io::read_to_string(&mut out).unwrap_or_default());
    let err = std::thread::spawn(move || std::io::read_to_string(&mut err).unwrap_or_default());
    let deadline = std::time::Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh doctor {args:?} still ran after {LIMIT:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    Run { code: status.code().unwrap_or(-1), out: out.join().unwrap(), err: err.join().unwrap() }
}

/// The bound on each run of doctor: a path that answers takes seconds.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

/// The counts on the summary line: (ok, FAIL, ????).
fn counts(out: &str) -> (usize, usize, usize) {
    let line = out.lines().rev().find(|l| l.contains(" ok, ")).unwrap_or_else(|| panic!("no summary:\n{out}"));
    let mut numbers = line.split([' ', ',']).filter_map(|w| w.parse::<usize>().ok());
    (numbers.next().unwrap(), numbers.next().unwrap(), numbers.next().unwrap())
}

#[test]
fn offline_the_network_is_not_attempted_and_never_reported_ok() {
    let run = doctor(&[], &[], &[], true);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    assert!(run.err.is_empty(), "the report belongs on stdout: {}", run.err);
    for section in ["this host", "egress"] {
        assert!(run.out.lines().any(|l| l == section), "no {section} section:\n{}", run.out);
    }
    assert!(run.out.contains("  ????  network        not attempted: PODSSH_OFFLINE is set"), "{}", run.out);
    assert!(!run.out.contains("\nrelay\n"), "the relay section ran offline:\n{}", run.out);
    let (ok, failed, unknown) = counts(&run.out);
    assert_eq!(failed, 0, "{}", run.out);
    assert!(ok >= 5 && unknown >= 1, "{}", run.out);
    // The compiled-in roots are named with their version and age.
    let roots = run.out.lines().find(|l| l.contains("roots age")).unwrap_or_else(|| panic!("{}", run.out));
    assert!(roots.starts_with("  ok") && roots.contains("compiled-in roots are webpki-roots"), "{roots}");
    // Every check line carries one of the three labels and nothing else.
    for line in run.out.lines().filter(|l| l.starts_with("  ")) {
        let label = line.split_whitespace().next().unwrap();
        assert!(["ok", "FAIL", "????"].contains(&label), "{line}");
    }
}

#[test]
fn without_home_host_keys_cannot_be_recorded_and_the_run_fails() {
    // The planted defect: no HOME at all. Exit 1, and the line says why.
    let run = doctor(&[], &[], &["HOME", "USERPROFILE"], true);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("  FAIL  known_hosts    HOME is not set"), "{}", run.out);
    assert_eq!(counts(&run.out).1, 1, "{}", run.out);
}

#[test]
fn a_proxy_is_named_and_its_credentials_never_appear() {
    let run = doctor(&[], &[("https_proxy", "http://alice:s3cr3t-pass@proxy.example:3128")], &[], true);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("https_proxy names proxy.example:3128 with credentials (not shown)"), "{}", run.out);
    assert!(!run.out.contains("s3cr3t") && !run.out.contains("alice"), "{}", run.out);
}

#[test]
fn an_unusable_proxy_fails_without_echoing_its_credentials() {
    // SOCKS5 is taken since T-070; SOCKS4 has no authentication, and is not.
    let run = doctor(&[], &[("HTTPS_PROXY", "socks4://alice:s3cr3t-pass@proxy.example:1080")], &[], true);
    assert_eq!(run.code, 1, "{}", run.out);
    // Windows reads variable names without regard to case, so the name
    // reported can be either spelling.
    let lower = run.out.to_ascii_lowercase();
    assert!(lower.contains("  fail  proxy          https_proxy is set but cannot be used"), "{}", run.out);
    assert!(!run.out.contains("s3cr3t") && !run.out.contains("alice"), "{}", run.out);
}

/// A SOCKS5 proxy is named as one (T-070), with no credentials shown.
#[test]
fn a_socks5_proxy_is_named_and_its_credentials_never_appear() {
    let run = doctor(&[], &[("ALL_PROXY", "socks5h://alice:s3cr3t-pass@proxy.example:1080")], &[], true);
    let lower = run.out.to_ascii_lowercase();
    assert!(
        lower.contains("all_proxy names the socks5 proxy proxy.example:1080 with credentials (not shown)"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("s3cr3t") && !run.out.contains("alice"), "{}", run.out);
}

#[test]
fn a_token_in_the_environment_is_never_printed() {
    let token = "podssh-test-token-0123456789abcdef";
    let run = doctor(&[], &[("PODSSH_RELAY_TOKEN", token)], &[], true);
    assert!(!run.out.contains(token) && !run.err.contains(token), "{}{}", run.out, run.err);
}

#[test]
fn bad_relay_settings_are_usage_errors_with_nothing_on_stdout() {
    for args in [["--relay-addr", "not-a-pin"], ["--relay-host", "not a host"]] {
        let run = doctor(&args, &[], &[], true);
        assert_eq!(run.code, 64, "{args:?}: {}{}", run.out, run.err);
        assert!(run.out.is_empty(), "{args:?}: {}", run.out);
        assert!(run.err.starts_with("podssh doctor: "), "{args:?}: {}", run.err);
    }
}

#[test]
#[ignore = "network: checks the live relay and reaches github.com:22 through it"]
fn the_live_relay_path_checks_out_end_to_end() {
    let run = doctor(&[], &[], &[], false);
    assert_eq!(run.code, 0, "{}{}", run.out, run.err);
    assert!(run.out.contains("certificate verified for tcp.ssh.relay.ajam.dev"), "{}", run.out);
    assert!(run.out.contains("  ok    token"), "{}", run.out);
    let forward = run.out.lines().find(|l| l.contains("forward")).unwrap_or_default();
    assert!(forward.starts_with("  ok") && forward.contains("one of GitHub"), "{}", run.out);
    assert_eq!(counts(&run.out).1, 0, "{}", run.out);
}

/// A detail with each run of digits as `#`: two runs bind different ports.
fn masked(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            if !out.ends_with('#') {
                out.push('#');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `--json` gives the text's report as one object: each line of the text has
/// an item, in order, with the same section, check, status and detail, and
/// the counts agree. Both runs share one HOME, so their details are equal
/// but for the numbers (a port that a bind got).
#[test]
fn json_has_each_check_of_the_text() {
    let home = scratch_home();
    let text = doctor_in(&home, &[], &[], &[], true);
    let json = doctor_in(&home, &["--json"], &[], &[], true);
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(json.code, text.code, "{}", json.out);
    assert!(json.err.is_empty(), "{}", json.err);
    let doc: serde_json::Value = serde_json::from_str(&json.out).expect("stdout is one JSON object");
    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["podssh"], env!("CARGO_PKG_VERSION"));
    let checks = doc["checks"].as_array().expect("checks");
    let mut section = "";
    let mut lines = Vec::new();
    for line in text.out.lines() {
        if line.starts_with("  ") {
            lines.push((section, line));
        } else if ["this host", "egress", "relay", "pairs"].contains(&line) {
            section = line;
        }
    }
    assert_eq!(checks.len(), lines.len(), "{}\n{}", text.out, json.out);
    for ((section, line), item) in lines.iter().zip(checks) {
        let label = match item["status"].as_str() {
            Some("ok") => "ok",
            Some("FAIL") => "FAIL",
            Some("unknown") => "????",
            other => panic!("status {other:?}"),
        };
        let check = item["check"].as_str().unwrap();
        let detail = item["detail"].as_str().unwrap();
        assert_eq!(masked(line), masked(&format!("  {label:<4}  {check:<14} {detail}")));
        assert_eq!(item["section"], *section, "{line}");
    }
    let (ok, failed, unknown) = counts(&text.out);
    assert_eq!(doc["counts"], serde_json::json!({ "ok": ok, "fail": failed, "unknown": unknown }));
}

/// A relay host inside a block of `no_proxy` goes direct, and the line names
/// the entry that matched, which a block does not make plain (T-316).
#[test]
fn a_block_of_no_proxy_is_named_on_the_proxy_line() {
    let set = [("https_proxy", "http://proxy.example:3128"), ("no_proxy", "localhost,10.0.0.0/8")];
    let run = doctor(&["--relay-host", "10.1.2.3"], &set, &[], true);
    assert!(run.out.contains("NO_PROXY's entry 10.0.0.0/8 excludes 10.1.2.3, so podssh connects"), "{}", run.out);
    let run = doctor(&["--relay-host", "11.1.2.3"], &set, &[], true);
    assert!(run.out.contains("https_proxy names proxy.example:3128"), "{}", run.out);
}

/// The JSON hides proxy credentials and a token as the text does.
#[test]
fn json_shows_no_proxy_password_and_no_token() {
    let token = "podssh-test-token-0123456789abcdef";
    let set = [("https_proxy", "http://alice:s3cr3t-pass@proxy.example:3128"), ("PODSSH_RELAY_TOKEN", token)];
    let run = doctor(&["--json"], &set, &[], true);
    let doc: serde_json::Value = serde_json::from_str(&run.out).expect("stdout is one JSON object");
    for secret in ["s3cr3t", "alice", token] {
        assert!(!run.out.contains(secret) && !run.err.contains(secret), "{secret}: {}{}", run.out, run.err);
    }
    let named =
        doc["checks"].as_array().unwrap().iter().any(|c| {
            c["check"] == "proxy" && c["detail"].as_str().unwrap_or_default().contains("credentials (not shown)")
        });
    assert!(named, "{}", run.out);
}

/// `--full` offline: the login check is one more `????` line, and nothing
/// fails.
#[test]
fn full_offline_adds_one_unknown_line() {
    let plain = doctor(&[], &[], &[], true);
    let full = doctor(&["--full"], &[], &[], true);
    assert_eq!(full.code, 0, "{}", full.out);
    let (ok, failed, unknown) = counts(&plain.out);
    assert_eq!(counts(&full.out), (ok, failed, unknown + 1), "{}", full.out);
    assert!(full.out.contains("  ????  login          not attempted: PODSSH_OFFLINE is set"), "{}", full.out);
}

/// The live relay and GitHub: `--full` logs in as git with a key made for
/// the check, and GitHub refuses it.
#[test]
#[ignore = "network: logs in to github.com through the live relay"]
fn full_live_logs_in_to_github() {
    let run = doctor(&["--full"], &[], &[], false);
    let line = run.out.lines().find(|l| l.contains(" login ")).unwrap_or_else(|| panic!("{}", run.out));
    assert!(line.starts_with("  ok") && line.contains("GitHub refused a key made for this check"), "{line}");
}

/// A proxy on the loopback that drops each third CONNECT, closing with no
/// answer, and answers the others with 200, then closes. Its port.
fn lossy_proxy() -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for (n, conn) in listener.incoming().enumerate() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                if n % 3 != 2 {
                    let _ = conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            });
        }
    });
    port
}

/// Each CONNECT probe is tried nine times, and through a proxy that drops
/// one in three, each line says a loss of 33 %, and `--json` the counts
/// (T-324, GitHub #54).
#[test]
fn a_proxy_that_drops_one_connect_in_three_shows_a_loss_of_33_percent() {
    let proxy = format!("http://127.0.0.1:{}", lossy_proxy());
    let set = [("https_proxy", proxy.as_str())];
    let args = ["--relay-host", "relay.example"];
    let run = doctor(&args, &set, &[], false);
    let lines: Vec<&str> = run.out.lines().filter(|l| l.split_whitespace().nth(1) == Some("CONNECT")).collect();
    assert_eq!(lines.len(), 3, "{}", run.out);
    for line in &lines {
        assert!(line.contains("loss 3 of 9 (33 %: 3 broke)"), "{line}");
    }
    let json = doctor(&["--json", "--relay-host", "relay.example"], &set, &[], false);
    let doc: serde_json::Value = serde_json::from_str(&json.out).expect("stdout is one JSON object");
    let probes: Vec<&serde_json::Value> =
        doc["checks"].as_array().unwrap().iter().filter(|c| c["check"] == "CONNECT").collect();
    assert_eq!(probes.len(), 3, "{}", json.out);
    for probe in probes {
        let s = &probe["samples"];
        assert_eq!((s["tries"].as_u64(), s["connected"].as_u64(), s["broke"].as_u64()), (Some(9), Some(6), Some(3)));
        assert!(s["best_ms"].as_u64().is_some() && s["p95_ms"].as_u64() >= s["best_ms"].as_u64(), "{probe}");
    }
}
