//! `podssh relay pair NAME --code` and `podssh relay join NAME` (T-086) as
//! processes, offline, with a scratch HOME and cache: each flag where it
//! means nothing is refused (64); a giver with no terminal is refused before
//! a pair is made; the taker reads the code from stdin, refuses a wrong one
//! with no word of it, and says none of a good one; `no` turns the pairing
//! off; a whole pair under the label is the node's host's; and the part that
//! a join keeps under a label is found by `relay status` and `operator`.

mod pair_harness;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pair_harness::*;
use podssh_relay::pair;
use zeroize::Zeroizing;

/// A code of the right form, which no mailbox holds.
const CODE: &str = "7-crossover-clockwork-adroitness";

/// `podssh ARGS` offline as `pair_harness::podssh` runs it, with `stdin`
/// on its stdin, and with no controlling terminal when `detached`, so that
/// it has none to show a code on.
fn podssh_in(home: &Path, args: &[&str], set: &[(&str, &str)], stdin: &str, detached: bool) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none");
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_PAIR_MAILBOX", "HTTPS_PROXY", "https_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home).env("PODSSH_OFFLINE", "1");
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd.envs(set.iter().copied());
    #[cfg(not(unix))]
    let _ = detached;
    #[cfg(unix)]
    if detached {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and touches no memory of the
        // parent; its result is ignored, as a child that leads a group
        // already has no terminal to lose.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let mut child =
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    // A run refused before it reads stdin may have closed it already.
    if let Some(mut input) = child.stdin.take() {
        let _ = input.write_all(stdin.as_bytes());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh {args:?} did not end within 30 s");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn each_flag_of_the_pairing_by_code_is_refused_where_it_means_nothing() {
    let home = scratch("code-flags");
    for (args, says) in [
        (vec!["relay", "pair", "lab", "--code", "--operator-file", "f"], "--code goes with"),
        (vec!["relay", "pair", "lab", "--code", "--renew"], "--code goes with"),
        (vec!["relay", "status", "lab", "--code"], "--code goes with"),
        (vec!["relay", "pair", "lab", "--allow", "f"], "--allow goes with"),
        (vec!["relay", "status", "lab", "--pair-mailbox", "wss://m.example/v1"], "--pair-mailbox goes with"),
        (vec!["relay", "pair", "lab", "--client-key", "k"], "--client-key goes with"),
        (vec!["relay", "join"], "missing NAME"),
        (vec!["relay", "join", "lab", "--once"], "--once goes with"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_giver_with_no_terminal_is_refused_before_a_pair_is_made() {
    let home = scratch("code-no-terminal");
    let (rc, out, err) = podssh_in(&home, &["relay", "pair", "lab", "--code"], &[], "", true);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("shows the code on this run's terminal alone") && err.contains("--operator-file"), "{err}");
    assert!(out.is_empty(), "stdout {out:?}");
    assert!(pair::load_from(&[cache_dir(&home)], "lab").unwrap().is_none(), "no pair was made");
}

#[test]
fn the_taker_reads_its_code_from_stdin_and_says_no_word_of_it() {
    let home = scratch("code-join");
    let (rc, out, err) = podssh_in(&home, &["relay", "join", "lab"], &[], "", false);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("no code came"), "{err}");
    let (rc, out2, err) = podssh_in(&home, &["relay", "join", "lab"], &[], "7-notaword-clockwork\n", false);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("word 1 of the code"), "{err}");
    assert!(!err.contains("notaword") && !out2.contains("notaword"), "{err}");
    let (rc, out3, err) = podssh_in(&home, &["relay", "join", "lab"], &[], &format!("{CODE}\n"), false);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    for word in CODE.split('-').skip(1) {
        assert!(!err.contains(word) && !out3.contains(word), "a word of the code in {err:?}");
    }
    assert!(out.is_empty() && out3.is_empty());
}

#[test]
fn no_turns_the_pairing_off_and_a_whole_pair_is_the_node_s_host_s() {
    let home = scratch("code-off");
    let (rc, _, err) = podssh_in(&home, &["relay", "join", "lab"], &[("PODSSH_PAIR_MAILBOX", "no")], CODE, false);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("turns pairing by code off") && err.contains("--operator-file"), "{err}");
    let (rc, _, err) = podssh_in(&home, &["relay", "join", "lab", "--pair-mailbox", "no"], &[], CODE, false);
    assert_eq!(rc, 64, "a flag's no is the user's word: {err}");
    store(&home, "lab", 0);
    let (rc, _, err) = podssh_in(&home, &["relay", "join", "lab"], &[], CODE, false);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("a pair is stored under \"lab\" on this host"), "{err}");
    no_token(&err);
}

#[test]
fn the_part_that_a_join_kept_is_found_by_its_label() {
    let home = scratch("code-part");
    let (rc, _, err) = podssh(&home, &["relay", "status", "lab"], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh relay join lab"), "the way of a code is named: {err}");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let token = Zeroizing::new(CONNECT.to_string());
    let part = pair::OperatorPart::checked("relay.example.org", NAME.into(), token, now + 3_600_000, now).unwrap();
    pair::part::store_in_first(&[cache_dir(&home)], "lab", &part).unwrap();
    for args in [vec!["relay", "status", "lab"], vec!["operator", "lab"]] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert!(!err.contains("no pair is stored"), "{args:?}: the part is found: {err}");
        assert_eq!(rc, 69, "{args:?}: offline, after the part was read: {err}");
        no_token(&out);
        no_token(&err);
    }
}
