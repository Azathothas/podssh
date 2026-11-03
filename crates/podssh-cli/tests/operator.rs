//! `podssh operator` and `podssh ssh node://NAME` (T-084) as processes,
//! offline, with a scratch HOME and cache: each refusal and its code, a pair
//! file of either form, stdout that stays empty, and no token in any output.
//! Through the stand-in relay of the reverse road (Python and openssl), an
//! operator that its parent hangs up closes its session (T-586), the bound
//! of `--ConnectTimeout` ends a wait for `ready` that the relay's own limit
//! would not (T-589), and an operator of `--no-resume` whose link is lost
//! leaves the node nothing (T-612).

mod operator_relayed;
mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use podssh_relay::pair;

use pair_harness::*;

#[test]
fn with_no_stored_pair_each_names_the_remedy_and_opens_nothing() {
    let home = scratch("op-none");
    let (rc, out, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh relay pair lab") && err.contains("--pair-file"), "{err}");
    assert!(out.is_empty());
    let (rc, out, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "OpenSSH's code for a failure of podssh: {err}");
    assert!(err.contains("node://lab") && err.contains("podssh relay pair lab"), "{err}");
    assert!(!err.contains("PODSSH_OFFLINE"), "refused before any connection: {err}");
    assert!(out.is_empty());
}

#[test]
fn an_expired_pair_is_refused_with_its_remedy() {
    let home = scratch("op-expired");
    store(&home, "lab", EXPIRED);
    let (rc, _, err) = podssh(&home, &["operator", "lab"], &[]);
    assert_eq!(rc, 77, "{err}");
    assert!(err.contains("expired") && err.contains("podssh relay pair lab"), "{err}");
    let (rc, _, err) = podssh(&home, &["ssh", "-T", "node://lab", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("expired"), "{err}");
}

/// A stored pair gets each command as far as the network, which
/// `PODSSH_OFFLINE` stops, and no output holds a token.
#[test]
fn a_stored_pair_reaches_the_network_and_no_token_is_shown() {
    let home = scratch("op-redact");
    store(&home, "lab", 0);
    let set = [("PODSSH_RELAY_TOKEN", FORWARD)];
    for (args, code) in [(vec!["operator", "lab"], 69), (vec!["ssh", "-T", "node://lab", "true"], 255)] {
        let (rc, out, err) = podssh(&home, &args, &set);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains("PODSSH_OFFLINE"), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout carries the node's bytes alone: {out:?}");
        no_token(&err);
    }
}

#[test]
fn a_pair_file_of_either_form_gives_the_operator_its_part() {
    let home = scratch("op-file");
    let operator_file = home.join("operator.json");
    pair::write_operator_file(&operator_file, &test_pair(0)).unwrap();
    let whole = pair::store_in_first(&[home.join("elsewhere")], "carried", &test_pair(0)).unwrap();
    for file in [&operator_file, &whole] {
        let path = file.to_str().unwrap();
        for args in
            [vec!["operator", "lab", "--pair-file", path], vec!["ssh", "-T", "--pair-file", path, "node://lab", "true"]]
        {
            let (rc, out, err) = podssh(&home, &args, &[]);
            assert!(
                err.contains("PODSSH_OFFLINE"),
                "{args:?}: the part was read, and only the network stopped it: {err}"
            );
            assert!(rc == 69 || rc == 255, "{args:?}: {rc}");
            no_token(&out);
            no_token(&err);
        }
    }
    let junk = home.join("junk.json");
    std::fs::write(&junk, b"{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (rc, _, err) = podssh(&home, &["operator", "lab", "--pair-file", junk.to_str().unwrap()], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no operator's part"), "{err}");
}

#[test]
fn operator_needs_a_name_and_takes_no_target() {
    let home = scratch("op-parse");
    let (rc, _, err) = podssh(&home, &["operator"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("missing NAME"), "{err}");
    let (rc, _, err) = podssh(&home, &["operator", "lab", "127.0.0.1:22"], &[]);
    assert_eq!(rc, 64, "the node, not the operator, names the TARGET: {err}");
    let (rc, _, err) = podssh(&home, &["operator", "../x"], &[]);
    assert_eq!(rc, 64, "{err}");
}

/// `--ConnectTimeout` (T-589): 0, or no number, is refused (64) on each of
/// the three verbs, before a pair is read or anything dialled; `operator`
/// and `proxy` take no `-o`, so `-o ConnectTimeout=N` stays refused.
#[test]
fn a_connect_timeout_of_zero_is_refused() {
    let home = scratch("op-bound-zero");
    let cases: [&[&str]; 6] = [
        &["operator", "lab", "--ConnectTimeout", "0"],
        &["operator", "lab", "--ConnectTimeout", "soon"],
        &["proxy", "--ConnectTimeout", "0", "host.example", "22"],
        &["proxy", "--ConnectTimeout", "0", "node://lab"],
        &["pipe", "--ConnectTimeout", "0", "stdio", "relay:host.example:22"],
        &["pipe", "--ConnectTimeout", "0s", "stdio", "node:lab"],
    ];
    for args in cases {
        let (rc, out, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains("--ConnectTimeout"), "{args:?}: {err}");
        assert!(!err.contains("PODSSH_OFFLINE"), "{args:?}: refused before any connection: {err}");
        assert!(out.is_empty(), "{args:?}");
    }
    for args in
        [&["operator", "-o", "ConnectTimeout=3", "lab"][..], &["proxy", "-o", "ConnectTimeout=3", "h", "22"][..]]
    {
        let (rc, _, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
    }
    // A listening pipe opens a road for each client: no bound of one open.
    let (rc, _, err) =
        podssh(&home, &["pipe", "--ConnectTimeout", "3", "tcp-listen:127.0.0.1:0", "relay:host.example:22"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("a listening side"), "{err}");
}

/// `--ConnectTimeout` (T-589): through a stand-in relay that takes the
/// operator's socket and never sends `ready` (its mode `noready`), a bound of
/// 3 s ends the operator within 5 s, with 69 and a line that names `ready`;
/// with none, its own 20 s for `ready` would pass first. It says that it did
/// not run where this host cannot run the stand-in.
#[test]
fn operator_s_connect_timeout_ends_a_wait_for_ready() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let s = throughput_harness::Session::start("op-bound");
    let cell = match throughput_harness::Cell::fake_relay_mode(&s, "noready", "the stand-in relay, never ready") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let command = |args: &[&str]| {
        let words: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        // The pin of the stand-in's name goes after the verb.
        let mut cmd = s.stand_in(&words[..1], &ca);
        cmd.args(["--relay-addr", "relay-a.test=127.0.0.1"]).args(&words[1..]);
        cmd
    };
    let out = command(&["relay", "pair", "lab", "--relay-host", relay.as_str()]).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let started = Instant::now();
    let mut operator = command(&["operator", "lab", "--ConnectTimeout", "3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Its stdin stays open: only the bound ends the wait.
    let _stdin = operator.stdin.take().expect("stdin");
    let said = throughput_harness::lines_of(&mut operator);
    let status = loop {
        if let Some(status) = operator.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = operator.kill();
            panic!("the operator did not end within 60 s: {:?}", said.try_iter().collect::<Vec<_>>());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = started.elapsed();
    std::thread::sleep(Duration::from_millis(100));
    let lines: Vec<String> = said.try_iter().collect();
    assert_eq!(status.code(), Some(69), "{lines:?}");
    assert!(took < Duration::from_secs(5), "the bound of 3 s ended the wait after {took:?}: {lines:?}");
    let line = lines.iter().find(|l| l.contains("(--ConnectTimeout)"));
    assert!(line.is_some_and(|l| l.contains("ready") && l.contains("within 3 s")), "{lines:?}");
}

/// GitHub #112 (T-586): OpenSSH ends its ProxyCommand with SIGHUP and does
/// not wait for it. Through the stand-in relay, after the target's last
/// byte and with its stdin still open, the operator gets SIGHUP: it closes
/// the session, so the node keeps none, and shuts its connection to the
/// target within 3 s; the operator exits 0, as at the end of its stdin. An
/// operator that died of the signal left the session to the node as a loss,
/// held with that connection for 10 minutes. Windows has no SIGHUP. It says
/// that it did not run where this host cannot run the stand-in.
#[cfg(unix)]
#[test]
fn an_operator_that_its_parent_hangs_up_closes_the_session() {
    operator_relayed::hung_up::run();
}

/// `--no-resume` (T-612): through the stand-in relay, an operator that asked
/// for no resume, killed with its session open (so that it sends nothing
/// more, as when its link is lost), leaves the node nothing: the relay tells
/// the node of the loss, and the node shuts its connection to the target
/// within 3 s. The control: an operator with no ask, killed the same way,
/// leaves the session to a resume, and the node keeps that connection for its
/// deadline. It says that it did not run where this host cannot run the
/// stand-in.
#[test]
fn an_operator_of_no_resume_leaves_the_node_nothing_at_a_loss() {
    operator_relayed::no_resume::run();
}

/// `--timeout` and `PODSSH_TIMEOUT` (T-613) are other names of
/// `--ConnectTimeout` on `operator`, `proxy` and `pipe`: a bad one is refused
/// before anything connects, 64 for the flag and 78 for the variable, each
/// naming itself; `--timeout` beside a listening side is refused as
/// `--ConnectTimeout` is, where the variable is no flag of the command line
/// and refuses no pipe.
#[test]
fn a_bad_timeout_is_refused_by_its_name() {
    let home = scratch("op-timeout-bad");
    let flags: [&[&str]; 5] = [
        &["operator", "lab", "--timeout", "0"],
        &["operator", "lab", "--timeout", "2x"],
        &["proxy", "--timeout", "soon", "host.example", "22"],
        &["proxy", "--timeout", "25h", "node://lab"],
        &["pipe", "--timeout", "0", "stdio", "node:lab"],
    ];
    for args in flags {
        let (rc, out, err) = podssh(&home, args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains("--timeout"), "{args:?}: {err}");
        assert!(!err.contains("PODSSH_OFFLINE"), "{args:?}: refused before any connection: {err}");
        assert!(out.is_empty(), "{args:?}");
    }
    let bad = [("PODSSH_TIMEOUT", "soon")];
    let read: [&[&str]; 3] =
        [&["operator", "lab"], &["proxy", "host.example", "22"], &["pipe", "stdio", "relay:h.example:22"]];
    for args in read {
        let (rc, _, err) = podssh(&home, args, &bad);
        assert_eq!(rc, 78, "{args:?}: {err}");
        assert!(err.contains("PODSSH_TIMEOUT \"soon\""), "{args:?}: {err}");
    }
    let listening = ["pipe", "--timeout", "3", "tcp-listen:127.0.0.1:0", "relay:host.example:22"];
    let (rc, _, err) = podssh(&home, &listening, &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--timeout bounds the open") && err.contains("a listening side"), "{err}");
    // No node: or relay: side: the variable bounds nothing here, and is not read.
    let (rc, _, err) = podssh(&home, &["pipe", "stdio", "tcp:127.0.0.1:1"], &bad);
    assert_ne!(rc, 78, "{err}");
    assert!(!err.contains("PODSSH_TIMEOUT"), "{err}");
}

/// The Prove of T-613: on a carrier whose program starts no node (Unix's
/// `sleep`), `operator --timeout 2`, `PODSSH_TIMEOUT=2s` and
/// `--ConnectTimeout 2` each end the run with 69 at 2 s, and the line names
/// the one that set the bound; `--ConnectTimeout` wins over `--timeout` and
/// the variable.
#[cfg(unix)]
#[test]
fn timeout_and_podssh_timeout_bound_the_open_as_connect_timeout_does() {
    use std::time::{Duration, Instant};

    let home = scratch("op-timeout");
    let cases: [(&[&str], &[(&str, &str)], &str); 4] = [
        (&["--ConnectTimeout", "2"], &[], "(--ConnectTimeout)"),
        (&["--timeout", "2"], &[], "(--timeout)"),
        (&[], &[("PODSSH_TIMEOUT", "2s")], "(PODSSH_TIMEOUT)"),
        (&["--timeout", "30s", "--ConnectTimeout", "2"], &[("PODSSH_TIMEOUT", "1h")], "(--ConnectTimeout)"),
    ];
    for (flags, set, named) in cases {
        let mut args = vec!["operator", "--carrier", "exec:sleep 10"];
        args.extend_from_slice(flags);
        args.push("box");
        // A carrier is no network: nothing but the bound may end the wait.
        let mut set = set.to_vec();
        set.push(("PODSSH_OFFLINE", "0"));
        let started = Instant::now();
        let (rc, out, err) = podssh(&home, &args, &set);
        let took = started.elapsed();
        assert_eq!(rc, 69, "{args:?} {set:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out:?}");
        let line = format!("the carrier's node did not read the stream within 2 s {named}");
        assert!(err.contains(&line), "{args:?} {set:?}: {err}");
        assert!(took >= Duration::from_millis(1900) && took < Duration::from_secs(5), "{args:?} {set:?}: {took:?}");
    }
}
