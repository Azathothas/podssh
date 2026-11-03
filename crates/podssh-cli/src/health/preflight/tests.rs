//! The verdicts of the preflight (T-482) on each answer that a probe can
//! get, the exec of the tools and its answer, and the lines and the JSON
//! of the checks. The probes themselves run against the test's server
//! (`tests/health.rs`) and OpenSSH and Dropbear (`scripts/interop-health.sh`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use podssh_relay::pool::Limits;
use podssh_ssh::missing::Found;
use podssh_ssh::preflight::{Answer, Forward, Jump, SftpFacts};
use podssh_ssh::russh::ChannelOpenFailure;
use podssh_ssh::sftp::SftpError;
use podssh_ws::Verdict;

use super::tools::{self, Probed};
use super::{judge, Check, Checks, Road};

const TEN: Duration = Duration::from_secs(10);

fn label(v: &Verdict) -> &'static str {
    v.label()
}

fn text(v: &Verdict) -> &str {
    super::detail(v)
}

fn facts(fixture: &str) -> crate::health::parse::Facts {
    crate::health::parse::facts(&crate::health::parse::sections(fixture).expect("the mark"))
}

/// A forward granted and cancelled is `ok`; a refusal, no answer, or a
/// connection that ended is `FAIL`, as `-R` cannot work there.
#[test]
fn each_answer_to_the_forward_has_its_verdict() {
    let granted = judge::forward(&Answer::Came(Forward::Listened { port: 40022, cancel: Answer::Came(true) }));
    assert_eq!(label(&granted), "ok", "{granted:?}");
    assert!(text(&granted).contains("port 40022, and stopped at the cancel: -R works on this host"), "{granted:?}");
    let kept = judge::forward(&Answer::Came(Forward::Listened { port: 0, cancel: Answer::Came(false) }));
    assert_eq!(label(&kept), "ok");
    assert!(text(&kept).contains("a port that it did not name") && text(&kept).contains("until this connection ends"));
    for (answer, words) in [
        (Answer::Came(Forward::Refused), "refused tcpip-forward"),
        (Answer::Silent(TEN), "no answer to tcpip-forward in 10 s"),
        (Answer::Lost("the connection ended".into()), "at tcpip-forward: the connection ended"),
    ] {
        let got = judge::forward(&answer);
        assert_eq!(label(&got), "FAIL", "{answer:?}");
        assert!(text(&got).contains(words) && text(&got).ends_with("-R cannot work on this host"), "{got:?}");
    }
}

/// A channel that opened, or one refused as `connect failed`, shows a
/// server that opens them; `administratively prohibited`, an unknown type
/// and no answer fail; a shortage is not known.
#[test]
fn each_answer_to_the_jump_has_its_verdict() {
    let ok = |answer: Answer<Jump>| {
        let got = judge::jump(&answer);
        assert_eq!(label(&got), "ok", "{got:?}");
        assert!(text(&got).ends_with("-J, -L, -D and -W through this host work"), "{got:?}");
    };
    ok(Answer::Came(Jump::Opened));
    ok(Answer::Came(Jump::Refused(ChannelOpenFailure::ConnectFailed)));
    for (answer, words) in [
        (Answer::Came(Jump::Refused(ChannelOpenFailure::AdministrativelyProhibited)), "administratively prohibited"),
        (Answer::Came(Jump::Refused(ChannelOpenFailure::UnknownChannelType)), "unknown channel type"),
        (Answer::Silent(TEN), "in 10 s"),
        (Answer::Lost("the connection ended".into()), "the connection ended"),
    ] {
        let got = judge::jump(&answer);
        assert_eq!(label(&got), "FAIL", "{answer:?}");
        assert!(text(&got).contains(words) && text(&got).ends_with("cannot work"), "{got:?}");
    }
    let short = judge::jump(&Answer::Came(Jump::Refused(ChannelOpenFailure::ResourceShortage)));
    assert_eq!(label(&short), "????", "{short:?}");
}

/// A reply, a success or a failure, is `ok`; no reply, or an end at it,
/// fails with the way round.
#[test]
fn each_answer_to_the_keepalive_has_its_verdict() {
    let failure = judge::keepalive(&Answer::Came(false));
    assert_eq!(label(&failure), "ok");
    assert!(text(&failure).contains("keepalive@openssh.com with a failure, as OpenSSH's sshd does"));
    assert_eq!(label(&judge::keepalive(&Answer::Came(true))), "ok");
    for answer in [Answer::Silent(TEN), Answer::Lost("the connection ended".into())] {
        let got = judge::keepalive(&answer);
        assert_eq!(label(&got), "FAIL", "{answer:?}");
        assert!(text(&got).ends_with("-o ServerAliveInterval=0 turns them off"), "{got:?}");
    }
}

/// The extensions that `cp` uses, each missing one with what `cp` does
/// without it; no subsystem is `ok`, one that does not answer is `FAIL`.
#[test]
fn the_sftp_line_names_what_cp_does_without_each_extension() {
    let extensions: BTreeMap<String, String> = [("copy-data", "1"), ("limits@openssh.com", "1")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let got = judge::sftp(&Ok(SftpFacts { extensions, read_len: 261120, write_len: 32768 }));
    assert_eq!(label(&got), "ok");
    let detail = text(&got);
    assert!(detail.starts_with("version 3, reads of 255.0 KiB and writes of 32.0 KiB; extensions: copy-data, "));
    assert!(detail.contains("; no posix-rename@openssh.com: ") && detail.contains("; no hardlink@openssh.com: "));
    assert!(!detail.contains("no copy-data") && !detail.contains("no limits@openssh.com"), "{detail}");
    let none = judge::sftp(&Err(SftpError::NoSftp));
    assert_eq!((label(&none), text(&none).contains("copies by exec")), ("ok", true));
    let late = judge::sftp(&Err(SftpError::Timeout { what: "the SFTP subsystem and its version".into(), limit: TEN }));
    assert_eq!(label(&late), "FAIL", "{late:?}");
}

/// The login and the road: the hops, the method, the version; the relay's
/// limits from its document or podssh's own, and a road with none.
#[test]
fn the_login_and_the_road_say_what_carried_the_session() {
    let hops = vec!["a".to_string(), "u@b:2222".to_string()];
    let got = judge::login("u@h", &hops, Some("SSH-2.0-OpenSSH_9.9"), Some("publickey"));
    assert_eq!(text(&got), "u@h by publickey, through -J a,u@b:2222; the server's version: SSH-2.0-OpenSSH_9.9");
    assert!(text(&judge::login("u@h", &[], None, Some("none"))).starts_with("u@h with no method"));
    let relay = Road { name: "relay", relay: true, ..Road::default() };
    let read = Limits { max_session_bytes: Some(64 << 20), idle_timeout_ms: Some(180_000), ..Limits::default() };
    let got = text(&judge::road(&relay, Some("relay.example.org"), &read)).to_string();
    assert!(got.starts_with("the relay relay.example.org ends a session at 64.0 MiB both ways, after 180 s"), "{got}");
    assert!(got.contains("and at 12 h (its /relays.json)"), "{got}");
    let own = text(&judge::road(&relay, None, &Limits::default())).to_string();
    assert!(own.contains("(podssh's own: no /relays.json was read)"), "{own}");
    let direct = Road { name: "direct", proxy: true, ..Road::default() };
    let got = judge::road(&direct, None, &Limits::default());
    assert_eq!(text(&got), "direct, through HTTPS_PROXY: not the relay, so none of its limits on a session");
}

/// The cgroup's CPUs and memory where it limits them, else the host's;
/// `????` with no facts.
#[test]
fn the_cgroup_line_gives_what_to_plan_from() {
    let limited = facts(include_str!("../../../tests/fixtures/health/container-v2.txt"));
    let got = judge::cgroup(Ok(&limited));
    assert!(text(&got).starts_with("the cgroup leaves 4 CPUs (cgroup v2 cpu.max), 3.3 GiB available of 4.0 GiB"));
    let host = facts(include_str!("../../../tests/fixtures/health/debian.txt"));
    let got = judge::cgroup(Ok(&host));
    assert!(text(&got).starts_with("no cgroup limits this shell: the host's 2 CPUs (host), "), "{got:?}");
    assert_eq!(label(&judge::cgroup(Err("the server has no sh"))), "????");
}

/// The exec of the tools is one quoted line for each login shell, with the
/// probe of a missing tmux at its end; its answer is read after the mark.
#[test]
fn the_exec_of_the_tools_is_one_line_and_its_answer_is_read_after_the_mark() {
    let command = tools::command();
    assert!(command.starts_with("sh -c 'echo podssh-preflight 1; for t in cat mv ") && command.ends_with("' sh tmux"));
    let script = &command["sh -c '".len()..command.len() - "' sh tmux".len()];
    assert!(!script.contains(['\'', '\\', '\n']), "{script}");
    assert!(script.ends_with(&podssh_ssh::missing::script()), "the probe of T-481 ends it");
    let answer = b"motd: have rm\npodssh-preflight 1\nhave cat\nhave mv\nhave nope\nmissing tmux apk alpine root\n";
    let (found, install) = tools::parse(answer).expect("the mark");
    let found: Vec<&str> = found.iter().map(String::as_str).collect();
    assert_eq!(found, ["cat", "mv"], "before the mark, and a name it never asked, are not read");
    assert_eq!(install.and_then(|f| f.system), Some("alpine".to_string()));
    assert_eq!(tools::parse(b"sh: not found\n"), None);
}

fn ran(names: &[&str], install: Option<Found>) -> Probed {
    Probed::Ran { tools: names.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>(), install }
}

/// Every tool: `ok`; a tool that a command needs: `FAIL`; another: `ok`,
/// named with what it stops; no sh: `FAIL`; tmux with its hint.
#[test]
fn the_tools_and_tmux_name_what_each_missing_one_stops() {
    let every: Vec<&str> = tools::TOOLS.iter().map(|(name, ..)| *name).chain(["sha256sum", "tmux"]).collect();
    assert_eq!(label(&tools::exec_tools(&ran(&every, None))), "ok");
    assert_eq!(label(&tools::tmux(&ran(&every, None))), "ok");
    let no_mkdir: Vec<&str> = every.iter().copied().filter(|t| *t != "mkdir").collect();
    let got = tools::exec_tools(&ran(&no_mkdir, None));
    assert_eq!((label(&got), text(&got)), ("FAIL", "sh runs, and has no mkdir (podssh job)"));
    let no_dd: Vec<&str> = every.iter().copied().filter(|t| !["dd", "sha256sum"].contains(t)).collect();
    let got = tools::exec_tools(&ran(&no_dd, None));
    assert_eq!(label(&got), "ok", "{got:?}");
    assert!(text(&got).contains("missing: dd (") && text(&got).contains("sha256sum, shasum and openssl ("));
    let failed = Probed::Failed("the server has no sh".into());
    assert_eq!(label(&tools::exec_tools(&failed)), "FAIL");
    assert_eq!(label(&tools::tmux(&failed)), "????");
    assert_eq!(label(&tools::exec_tools(&Probed::NotAsked)), "????");
    let found = Found::parse("apk alpine root");
    let no_tmux: Vec<&str> = every.iter().copied().filter(|t| *t != "tmux").collect();
    let got = tools::tmux(&ran(&no_tmux, found));
    assert_eq!(label(&got), "FAIL");
    assert!(text(&got).ends_with("needs --no-tmux; to install it on alpine: apk add tmux"), "{got:?}");
}

/// The lines are doctor's, with the counts; the JSON has doctor's keys.
#[test]
fn the_checks_are_doctor_s_lines_and_keys() {
    let checks = Checks(vec![
        Check { name: "login", verdict: Verdict::Ok { detail: "u@h by none".into() } },
        Check { name: "remote forward", verdict: Verdict::Failed { detail: "refused\x1b[2J".into() } },
        Check { name: "keepalive", verdict: Verdict::Unknown { why: "not asked".into() } },
    ]);
    let lines = checks.lines();
    assert_eq!(lines[..2], ["", "preflight"]);
    assert_eq!(lines[2], "  ok    login          u@h by none");
    assert!(lines[3].starts_with("  FAIL  remote forward refused") && !lines[3].contains('\x1b'), "{lines:?}");
    assert_eq!(lines[4], "  ????  keepalive      not asked");
    assert_eq!(lines.last().map(String::as_str), Some("1 ok, 1 FAIL, 1 ???? (could not be checked)"));
    assert!(checks.failed());
    let doc = checks.json();
    assert_eq!(doc["counts"], serde_json::json!({ "ok": 1, "fail": 1, "unknown": 1 }));
    assert_eq!(doc["checks"][1]["status"], "FAIL");
    assert_eq!(doc["checks"][2]["status"], "unknown");
    assert_eq!(doc["checks"][0]["section"], "preflight");
    let failed = Checks::not_logged_in("no connection");
    assert_eq!((failed.0.len(), failed.failed()), (1, true));
}
