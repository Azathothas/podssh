//! `podssh doctor`'s line `ipv6` (T-253) as a process, in its section
//! `relay`: against podssh's own relay role on the loopback, whose
//! `/relays.json` says what the role knows of its host's way out to IPv6,
//! and against the stand-in relay (`scripts/fake-relay.py`), whose document
//! says nothing of it, as the default relay's says nothing. The role and
//! doctor run on one host, each with no proxy, so the relay's half and the
//! direct one read the same probes and agree. The checks say that they did
//! not run when this host has no Python or no openssl for the stand-in's
//! certificates.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// The bound on each run of doctor.
const LIMIT: Duration = Duration::from_secs(180);

/// The label and the detail of the line `ipv6` of `podssh doctor --quick`
/// at `cell`'s relay host, with no proxy and no relay of the machine.
fn ipv6_line(s: &Session, cell: &Cell) -> (String, String) {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    let args: Vec<String> =
        ["doctor", "--quick", "--relay-host", &host, "--relay-addr", "relay-a.test=127.0.0.1", "--ca-file", &ca]
            .map(String::from)
            .to_vec();
    let mut cmd = s.stand_in(&args, &ca);
    cmd.env_remove("PODSSH_RELAY_TOKEN").env_remove("PODSSH_RELAY").env_remove("PODSSH_OFFLINE");
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh doctor still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let relay = text.split("\nrelay\n").nth(1).unwrap_or_else(|| panic!("no section relay: {text}"));
    // `  LABEL  CHECK          DETAIL`: the label in 4, the check in 14.
    let line = relay
        .lines()
        .take_while(|l| l.starts_with("  "))
        .find(|l| l.get(8..22).map(str::trim) == Some("ipv6"))
        .unwrap_or_else(|| panic!("no line ipv6 in the section relay: {text}"));
    (line[2..6].trim().to_string(), line[23..].to_string())
}

/// The role says what its host's probes tell, and doctor's own probes of
/// the same host tell the same: yes or none by the table of routes, or
/// nothing before a dial where there is no table, as on a host whose kernel
/// makes no IPv6 socket.
#[test]
fn the_role_s_word_and_this_host_s_own_probes_agree() {
    let s = Session::start("doctor-ipv6-role");
    // The role's own proxy would decide for it: an empty value is unset.
    let unset: Vec<(&str, String)> =
        ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"].iter().map(|v| (*v, String::new())).collect();
    let cell = match Cell::podssh_relay_env(&s, "podssh's relay role", &[], &unset) {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let (label, detail) = ipv6_line(&s, &cell);
    assert_eq!(label, "ok", "{detail}");
    let (relay, direct) = detail.split_once("; direct: ").unwrap_or_else(|| panic!("no direct half: {detail}"));
    let relay = relay.strip_prefix("through relay-a.test: ").unwrap_or_else(|| panic!("no relay half: {detail}"));
    let untold = direct.starts_with("none, as this host makes no IPv6 socket") || direct.starts_with("unknown before");
    let said = if untold {
        "unknown, the relay cannot tell (nothing before a dial)"
    } else if direct == "yes, by the routes of this host" {
        "yes, the relay says that its host routes IPv6 out (the routes of this host)"
    } else if direct == "none, by the routes of this host" {
        "none, the relay says that its host has no IPv6 route out (the routes of this host), so it refuses an IPv6 \
         target before the upgrade"
    } else {
        panic!("a direct half of no known form: {detail}")
    };
    assert_eq!(relay, said, "{detail}");
}

/// A relay whose `/relays.json` has no word of IPv6, as the stand-in's:
/// the line says so, and is `ok`.
#[test]
fn a_relay_that_says_nothing_of_ipv6_is_named_so() {
    // With the role in the stand-in's place (T-169), the role says it.
    if std::env::var("PODSSH_RELAY_UNDER_TEST").as_deref() == Ok("podssh") {
        return eprintln!("did not run: PODSSH_RELAY_UNDER_TEST=podssh puts the role in the stand-in's place");
    }
    let s = Session::start("doctor-ipv6-stand-in");
    let cell = match Cell::fake_relay_mode(&s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let (label, detail) = ipv6_line(&s, &cell);
    assert_eq!(label, "ok", "{detail}");
    let silent =
        "through relay-a.test: unknown, as its /relays.json says nothing of IPv6 (podssh relay serve says it); \
                  direct: ";
    assert!(detail.starts_with(silent), "{detail}");
}
