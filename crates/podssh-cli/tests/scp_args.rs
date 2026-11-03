//! `podssh scp` and `podssh sftp` with OpenSSH's command lines (T-139),
//! against the binary and offline: each letter that podssh does not carry is
//! refused by name (64) with nothing attempted, each that it carries or
//! accepts goes on to connect, which offline cannot (69), and neither verb
//! asks for `--timeout`, which each takes as a bound (T-508): against a
//! server of the test that sends its version line and then nothing, it ends
//! the run with 75, and ConnectTimeout ends one with none.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run the binary offline with no terminal; (exit code, stdout, stderr).
fn podssh(args: &[&str]) -> (i32, Vec<u8>, String) {
    podssh_with(args, None)
}

/// [`podssh`] with `PODSSH_TIMEOUT` set to `timeout`, or unset.
fn podssh_with(args: &[&str], timeout: Option<&str>) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        // No test may reach the network: a copy that would connect stops here.
        .env("PODSSH_OFFLINE", "1")
        .env_remove("PODSSH_TIMEOUT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = timeout {
        cmd.env("PODSSH_TIMEOUT", value);
    }
    let out = cmd.output().expect("the podssh binary runs");
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A batch of `sftp` that does nothing, in a file of its own.
fn batch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("podssh-batch-{name}-{}", std::process::id()));
    std::fs::write(&path, "pwd\n").expect("a batch");
    path
}

/// `--timeout` of `scp` and `sftp` (T-508, the operator's ruling Q72): a
/// bound that is never required. With no terminal each goes on to connect
/// with it and without it (offline, 69); a value of the flag that does not
/// parse is 64, a bad `PODSSH_TIMEOUT` 78, and a good one goes on, as for
/// `cp`.
#[test]
fn timeout_is_a_bound_that_scp_and_sftp_never_require() {
    let file = batch("bound");
    let b = file.display().to_string();
    for words in [
        &["scp", "--timeout", "30s", "a", "host:b"][..],
        &["scp", "a", "host:b"],
        &["sftp", "--timeout", "30s", "-b", b.as_str(), "host"],
        &["sftp", "-b", b.as_str(), "host"],
    ] {
        let (rc, out, err) = podssh(words);
        assert_eq!(rc, 69, "{words:?}: {err}");
        assert!(out.is_empty() && !err.contains("is required"), "{words:?}: {err}");
    }
    for words in
        [&["scp", "--timeout", "30x", "a", "host:b"][..], &["sftp", "--timeout", "0", "-b", b.as_str(), "host"]]
    {
        let (rc, _, err) = podssh(words);
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(err.contains("bad --timeout"), "{words:?}: {err}");
    }
    let (rc, _, err) = podssh_with(&["scp", "a", "host:b"], Some("30x"));
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("bad PODSSH_TIMEOUT"), "{err}");
    let (rc, _, err) = podssh_with(&["sftp", "-b", b.as_str(), "host"], Some("30s"));
    assert_eq!(rc, 69, "{err}");
    // cp keeps its rule: required with no terminal.
    let (rc, _, err) = podssh(&["cp", "a", "host:b"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--timeout DURATION is required"), "{err}");
    let _ = std::fs::remove_file(&file);
}

/// A server on the loopback that sends its version line, then nothing: each
/// connection stays open and silent.
fn silent_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port on the loopback");
    let port = listener.local_addr().expect("its address").port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.9 silent\r\n");
            held.push(stream);
        }
    });
    port
}

/// Run the binary online in `home`, `limit` at most, then kill it: its exit
/// code (-1 when killed), how long it ran, and its stderr.
fn bounded(home: &std::path::Path, args: &[&str], limit: Duration) -> (i32, Duration, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for name in ["PODSSH_OFFLINE", "PODSSH_TIMEOUT", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(name);
    }
    let started = Instant::now();
    let mut child = cmd.env_remove("SSH_AUTH_SOCK").spawn().expect("the podssh binary runs");
    while child.try_wait().expect("a status").is_none() {
        if started.elapsed() > limit {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let out = child.wait_with_output().expect("its output");
    (out.status.code().unwrap_or(-1), took, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The report's server that sends its version line and then nothing
/// (T-508): `scp --timeout 2s` ends with 75 within 5 s, and so does `sftp
/// --timeout 2s -b`; with no `--timeout`, `-o ConnectTimeout=3` ends `scp`
/// within 10 s with 69, `cp`'s code of a server that cannot be reached.
#[test]
fn timeout_ends_scp_and_sftp_at_a_server_that_says_nothing() {
    let home = std::env::temp_dir().join(format!("podssh-scp-silent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("a"), b"a").unwrap();
    std::fs::write(home.join("batch"), "pwd\n").unwrap();
    let port = silent_server().to_string();
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let common = ["--direct", "-P", port.as_str(), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"];
    let with = |verb: &'static str, before: &[&'static str], after: &[&str]| -> Vec<String> {
        let mut words: Vec<String> = [verb].iter().chain(before).map(|w| w.to_string()).collect();
        words.extend(common.iter().map(|w| w.to_string()));
        words.extend(["-o".to_string(), known.clone()]);
        words.extend(after.iter().map(|w| w.to_string()));
        words
    };
    let run = |words: Vec<String>, limit: u64| {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        bounded(&home, &words, Duration::from_secs(limit))
    };
    let (rc, took, err) = run(with("scp", &["--timeout", "2s"], &["a", "u@127.0.0.1:b"]), 30);
    assert_eq!(rc, 75, "scp --timeout 2s: {err}");
    assert!(took < Duration::from_secs(5), "scp ended after {took:?}: {err}");
    assert!(err.contains("the --timeout of 2 s passed"), "{err}");
    let (rc, took, err) = run(with("sftp", &["--timeout", "2s"], &["-b", "batch", "u@127.0.0.1"]), 30);
    assert_eq!(rc, 75, "sftp --timeout 2s: {err}");
    assert!(took < Duration::from_secs(5), "sftp ended after {took:?}: {err}");
    let (rc, took, err) = run(with("scp", &[], &["-o", "ConnectTimeout=3", "a", "u@127.0.0.1:b"]), 60);
    assert_eq!(rc, 69, "scp with ConnectTimeout=3: {err}");
    assert!(took < Duration::from_secs(10), "scp ended after {took:?}: {err}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn each_scp_letter_that_podssh_does_not_carry_is_refused_by_name() {
    for flag in [&["-O"][..], &["-R"], &["-S", "ssh"], &["-D", "/x"], &["-c", "aes128-ctr"]] {
        let mut args = vec!["scp"];
        args.extend_from_slice(flag);
        args.extend_from_slice(&["a", "host:b"]);
        let (rc, out, err) = podssh(&args);
        assert_eq!(rc, 64, "{flag:?}: {err}");
        assert!(out.is_empty(), "{flag:?} wrote to stdout");
        assert!(err.contains("is refused") && !err.contains("unknown flag"), "{flag:?}: {err}");
    }
}

#[test]
fn scp_goes_on_to_connect_with_its_own_letters_and_no_timeout() {
    // Offline nothing answers: 69, after the command line and the settings
    // passed. No --timeout: OpenSSH's scp has none, and each wait has a limit.
    for words in [
        &["a", "host:b"][..],
        &["-P", "2222", "-B", "-C", "-q", "-v", "-4", "a", "host:b"],
        &["-3", "-s", "-T", "host:a", "."],
        &["-A", "a", "host:b"],
        // The times too (T-146).
        &["-p", "-r", "a", "host:b"],
        &["-o", "BatchMode=yes", "-i", "id_test", "-J", "jump", "a", "host:b"],
        &["a", "scp://u@host:2222/dir/b"],
        &["scp://host//srv/a", "."],
        &["--direct", "a", "host:b"],
        // SFTP's requests in flight and their size (T-140).
        &["-X", "nrequests=4", "-X", "buffer=64K", "a", "host:b"],
    ] {
        let mut args = vec!["scp"];
        args.extend_from_slice(words);
        let (rc, out, err) = podssh(&args);
        assert_eq!(rc, 69, "{words:?}: {err}");
        assert!(out.is_empty(), "{words:?} wrote to stdout");
        assert!(!err.contains("--timeout"), "{words:?} asked for --timeout: {err}");
    }
}

#[test]
fn scp_refuses_as_cp_does_in_its_own_name() {
    for (words, says) in [
        (&["a"][..], "podssh scp: give a source and a destination"),
        (&["a", "b"][..], "podssh scp: both sides are local paths"),
        (&["a", "scp://host:0/x"][..], "no port from 1 to 65535"),
        (&["a", "scp://host/%zz"][..], "bad % escape"),
    ] {
        let mut args = vec!["scp"];
        args.extend_from_slice(words);
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 64, "{words:?}: {err}");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{words:?}: {err}");
    }
}

#[test]
fn each_sftp_letter_that_podssh_does_not_carry_is_refused_by_name() {
    for flag in [&["-S", "ssh"][..], &["-D", "/x"], &["-c", "aes128-ctr"]] {
        let mut args = vec!["sftp"];
        args.extend_from_slice(flag);
        args.push("host");
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 64, "{flag:?}: {err}");
        assert!(err.contains("is refused") && !err.contains("unknown flag"), "{flag:?}: {err}");
    }
}

#[test]
fn sftp_asks_for_its_destination_and_for_commands_with_no_terminal() {
    let (rc, _, err) = podssh(&["sftp"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("give a destination"), "{err}");
    // No terminal, no -b, and no file to fetch: nothing to do.
    let (rc, _, err) = podssh(&["sftp", "user@host"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("-b FILE") && err.contains("Nothing has been attempted"), "{err}");
    // A batch that cannot be read is a source that cannot be read.
    let (rc, _, err) = podssh(&["sftp", "-b", "no-such-batch-file", "host"]);
    assert_eq!(rc, 66, "{err}");
    // A batch, or a path to fetch, goes on to connect: offline, 69.
    let batch = std::env::temp_dir().join(format!("podssh-batch-{}", std::process::id()));
    std::fs::write(&batch, "pwd\n-rm x*\n@ls\nbye\n").expect("a batch");
    let shown = batch.display().to_string();
    for words in [
        &["-b", shown.as_str(), "host"][..],
        &["-b", "-", "-a", "-f", "-N", "-P", "2222", "u@host"],
        &["-A", "host:dir/file"],
        &["host:dir/file"],
        &["sftp://u@host:2222/x"],
        &["-s", "sftp", "-b", shown.as_str(), "host"],
        // Each get and put keeps the times (T-146), and copies a directory
        // (T-298).
        &["-p", "-b", shown.as_str(), "host"],
        &["-r", "-b", shown.as_str(), "host"],
        // SFTP's requests in flight and their size (T-140).
        &["-B", "32768", "-R", "16", "-X", "buffer=4", "-b", shown.as_str(), "host"],
    ] {
        let mut args = vec!["sftp"];
        args.extend_from_slice(words);
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 69, "{words:?}: {err}");
    }
    let _ = std::fs::remove_file(&batch);
}

/// A size or a count out of range is a usage error that names its flag, for
/// sftp and for scp, before anything connects (T-140).
#[test]
fn sftp_requests_and_their_size_out_of_range_are_refused_by_flag() {
    for (verb, words, says) in [
        ("sftp", &["-R", "0", "host:f"][..], "-R 0: give one request or more"),
        ("sftp", &["-B", "0", "host:f"], "-B 0: the buffer is 1 to 262144 bytes"),
        ("sftp", &["-B", "300K", "host:f"], "-B 300K: the buffer is 1 to 262144 bytes"),
        ("sftp", &["-X", "fast", "host:f"], "-X fast: the options are buffer=BYTES and nrequests=COUNT"),
        ("scp", &["-X", "nrequests=0", "a", "host:b"], "-X nrequests=0: give one request or more"),
    ] {
        let mut args = vec![verb];
        args.extend_from_slice(words);
        let (rc, _, err) = podssh(&args);
        assert_eq!(rc, 64, "{verb} {words:?}: {err}");
        assert!(err.contains(says) && err.contains("Nothing has been attempted"), "{verb} {words:?}: {err}");
    }
}
