//! `ProxyCommand` in a file (T-502): the first value holds, as OpenSSH
//! reads the first alone, so `-o ProxyCommand=none` on the command line, or
//! the `ProxyCommand none` of an earlier block, goes past a `Host *` that
//! names a jump host for OpenSSH; a command with no value before it stays
//! refused with 78, and its line names that flag (Q70).

use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse};

use super::login::{direct, offline, server};
use super::{ssh, ssh_harness, Home};

/// The report's line: a jump host for OpenSSH, for each host.
const REPORT: &str = "Host *\n  ProxyCommand ssh -W %h:%p b\n  Port 2222\n";

#[test]
fn the_command_lines_none_beats_a_files_proxy_command_for_each_host() {
    let h = Home::new("proxy-none");
    let f = h.file("report", REPORT);
    for value in ["none", "NONE", "podssh proxy %h %p"] {
        let option = format!("ProxyCommand={value}");
        let r = resolve(&ssh(&["-F", &f, "-o", &option, "host"]), &h.env()).unwrap_or_else(|e| panic!("{value}: {e}"));
        assert_eq!(r.options.destination.port, 2222, "{value}: the file's other settings hold");
    }
    // A hop of -J reads its own blocks under the command line's value too.
    let words = ["-F", &f, "-o", "ProxyCommand=none", "-J", "bastion", "host"];
    let r = resolve(&ssh(&words), &h.env()).unwrap_or_else(|e| panic!("-J: {e}"));
    assert_eq!(r.options.jump[0].port, 2222, "the hop's own Port");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "host"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(
        err.message.contains(&format!("{f}:2: ProxyCommand")) && err.message.contains("-o ProxyCommand=none"),
        "the refusal names its line and the way out: {}",
        err.message
    );
}

#[test]
fn the_proxy_command_none_of_an_earlier_block_holds_against_host_star() {
    let h = Home::new("proxy-first");
    let f = h.file("first", "Host x\n  ProxyCommand none\nHost *\n  ProxyCommand ssh -W %h:%p b\n  Port 2222\n");
    let r = resolve(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_or_else(|e| panic!("x: {e}"));
    assert_eq!(r.options.destination.port, 2222);
    let err = resolve_or_refuse(&ssh(&["-F", &f, "other"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(
        err.message.contains(&format!("{f}:4:")) && err.message.contains("-o ProxyCommand=none"),
        "{}",
        err.message
    );
    // podssh's own proxy holds the same way, and -v names its place.
    let f = h.file("own", "Host x\n  ProxyCommand podssh proxy %h %p\nHost *\n  ProxyCommand nc %h %p\n");
    let r = resolve(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_or_else(|e| panic!("own: {e}"));
    let note = format!("ProxyCommand podssh proxy %h %p ({f}:2) is not run: podssh ssh carries the session itself");
    assert!(r.notes.contains(&note), "{:?}", r.notes);
}

/// A ProxyCommand that holds goes before a later ProxyJump, as OpenSSH
/// 10.3p1 reads them (`parse_jump` of its `readconf.c`): the block's
/// `ProxyCommand none` takes the host past a `Host *` with a jump host; a
/// host of no such block keeps its jump. The bastion's own block names no
/// jump: `Host *` would give it one through itself, a loop (T-290).
#[test]
fn a_proxy_command_that_holds_goes_before_a_later_proxy_jump() {
    let h = Home::new("proxy-jump");
    let f = h.file(
        "jump",
        "Host direct\n  ProxyCommand none\nHost bastion\n  ProxyJump none\nHost *\n  ProxyJump bastion\n",
    );
    let r = resolve(&ssh(&["-F", &f, "direct"]), &h.env()).unwrap_or_else(|e| panic!("direct: {e}"));
    assert!(r.options.jump.is_empty(), "{:?}", r.options.jump);
    let r = resolve(&ssh(&["-F", &f, "other"]), &h.env()).unwrap_or_else(|e| panic!("other: {e}"));
    assert_eq!(r.options.jump.iter().map(|j| j.host.as_str()).collect::<Vec<_>>(), ["bastion"]);
    let r = resolve(&ssh(&["-F", &f, "-o", "ProxyCommand=none", "other"]), &h.env()).unwrap();
    assert!(r.options.jump.is_empty(), "-o ProxyCommand=none: {:?}", r.options.jump);
}

/// Each verb that reaches a host reads the file through the same resolve:
/// with the command line's `none` it goes on to connect, which offline
/// cannot (69); without it, it is refused with 78 and the way out.
#[test]
fn proxy_command_none_goes_past_the_file_for_cp_mv_scp_and_sftp() {
    let h = Home::new("proxy-verbs");
    let f = h.file("report", REPORT);
    let verbs: [(&[&str], &[&str]); 4] = [
        (&["cp", "--timeout", "5s"], &["a", "host:b"]),
        (&["mv", "--timeout", "5s"], &["host:a", "."]),
        (&["scp"], &["a", "host:b"]),
        (&["sftp"], &["host:dir/file"]),
    ];
    for (verb, operands) in verbs {
        for (none, want) in [(true, 69), (false, 78)] {
            let mut words = verb.to_vec();
            words.extend(["-F", f.as_str()]);
            if none {
                words.extend(["-o", "ProxyCommand=none"]);
            }
            words.extend_from_slice(operands);
            let (rc, err) = offline(&words);
            assert_eq!(rc, want, "{words:?}: {err}");
            assert!(none || err.contains("-o ProxyCommand=none"), "{words:?}: {err}");
        }
    }
}

/// The report's file, with the port of the test's server: `-o
/// ProxyCommand=none` and `-o ProxyCommand='podssh proxy %h %p'` log in
/// with --direct, at the file's Port; with neither, 78 before anything
/// connects.
#[test]
fn proxy_command_none_logs_in_with_the_files_port() {
    let h = Home::new("proxy-login");
    let (_runtime, port) = server(&h.0, "ed25519", None);
    let f = h.file("report", &format!("Host *\n  ProxyCommand ssh -W %h:%p b\n  Port {port}\n"));
    for value in ["none", "podssh proxy %h %p"] {
        let option = format!("ProxyCommand={value}");
        let (rc, out, err) = direct(&h.0, &["-F", &f, "-o", &option, "tester@127.0.0.1", "greet"]);
        assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{value}: {err}");
    }
    let (rc, _, err) = direct(&h.0, &["-F", &f, "tester@127.0.0.1", "greet"]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("-o ProxyCommand=none"), "{err}");
}
