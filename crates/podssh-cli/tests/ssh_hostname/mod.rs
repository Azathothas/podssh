//! The host names that each road dials (T-503), a module of
//! `tests/ssh_args.rs`, whose own file is near 500 lines. Resolved: `a$b`,
//! `a!b`, `a/b`, a blank and a name beyond ASCII are refused with 64, with
//! `--direct` and without, before anything connects; the zone of a
//! link-local address passes where this host or a jump host dials it, and
//! through the relay it is refused. Against the binary: with `PODSSH_OFFLINE`
//! set, `--direct` refuses `a$b` with 64, where a dial would say that
//! `PODSSH_OFFLINE` stops it (69).

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Transport};

/// `podssh ssh WORDS... DESTINATION true`, resolved: the refusal's code and
/// words, or none.
fn refused(words: &[&str], destination: &str) -> Option<(i32, String)> {
    let all: Vec<&str> = words.iter().copied().chain([destination, "true"]).collect();
    resolve_or_refuse(&super::ssh(&all), &super::env()).err().map(|refusal| (refusal.code, refusal.message))
}

#[test]
fn a_host_name_that_the_relay_refuses_is_refused_on_each_road() {
    for name in ["a$b", "a!b", "a/b", "a b", "a\tb", "bücher.example"] {
        for (words, road) in [(&["--direct"][..], "directly"), (&[][..], "through the relay")] {
            let Some((code, message)) = refused(words, name) else { panic!("{words:?} {name:?} was not refused") };
            assert_eq!(code, 64, "{words:?} {name:?}: {message}");
            assert!(message.contains("is not a host name"), "{words:?} {name:?}: {message}");
            assert!(message.contains(road), "{words:?} {name:?}: {message}");
        }
    }
    let (_, message) = refused(&["--direct"], "bücher.example").unwrap();
    assert!(message.contains("xn--"), "the ASCII form is named: {message}");
    // A HostName is the host that is dialed, and is checked as one.
    let (code, message) = refused(&["--direct", "-o", "HostName=a$b"], "alias").unwrap();
    assert_eq!(code, 64, "{message}");
    assert!(message.starts_with("cannot reach a$b directly: "), "{message}");
}

#[test]
fn a_host_name_with_a_zone_passes_where_this_host_or_a_jump_host_dials_it() {
    let direct = resolve(&super::ssh(&["--direct", "fe80::1%eth0", "true"]), &super::env()).unwrap();
    assert_eq!(direct.transport, Transport::Direct);
    assert_eq!(direct.options.destination.host, "fe80::1%eth0");
    let (code, message) = refused(&[], "fe80::1%eth0").unwrap();
    assert_eq!(code, 64, "the relay cannot use a zone of this host: {message}");
    // Behind a jump host the zone is that host's, which dials it.
    assert!(refused(&["-J", "bastion.example"], "fe80::1%eth0").is_none());
    assert!(refused(&["--direct", "-J", "bastion.example"], "[fe80::1%eth0]:22").is_none());
}

#[test]
fn a_host_name_behind_a_jump_host_is_checked_as_that_host_dials_it() {
    let (code, message) = refused(&["--direct", "-J", "bastion.example"], "a$b").unwrap();
    assert_eq!(code, 64, "{message}");
    assert!(message.starts_with("cannot reach a$b through the jump host bastion.example: "), "{message}");
    let (code, message) = refused(&["-J", "a!b"], "host.example").unwrap();
    assert_eq!(code, 64, "{message}");
    assert!(message.starts_with("cannot reach a!b through the relay: "), "{message}");
    let (_, message) = refused(&["-J", "one.example,two$.example"], "host.example").unwrap();
    assert!(message.contains("through the jump host one.example"), "{message}");
}

/// The run to its end within 30 s: a run that waits must fail the test,
/// not hold it.
fn within(cmd: &mut Command) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("no end within 30 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_host_name_refused_on_the_direct_road_is_never_dialed() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-F", "none", "tester@a$b", "true"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("PODSSH_OFFLINE", "1");
    cmd.env("HOME", std::env::temp_dir()).env("USERPROFILE", std::env::temp_dir());
    let out = within(&mut cmd);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(64), "{stderr}");
    assert!(stderr.contains("cannot reach a$b directly: "), "{stderr}");
    assert!(!stderr.contains("PODSSH_OFFLINE"), "a dial was tried: {stderr}");
}
