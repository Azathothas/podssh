//! The fallback to the forwarders that the binary names follows only a
//! failure where no relay host answered about the target (Q69, T-509): the
//! relay's 502 of a target that it could not reach, and its refusal of a
//! target by policy, end the run with the relay's words and send the target
//! to no forwarder; a refused token is no word about the target, and the
//! fallback carries the session as before. `doctor`'s line of the fallback
//! measured nothing, and says so.

use super::forwarder_support::is_relay;
use super::{no_token, podssh, run, ssh, world, World};

/// The hosts of the forwarders that the binary names.
const FORWARDERS: [&str; 4] =
    ["web-proxy.mudlet.org", "ssheasy.com", "mudix.delwing.workers.dev", "wisp.mercurywork.shop"];

/// A token in the environment, which no stand-in checks: no mint is asked.
const TOKEN: (&str, &str) = ("PODSSH_RELAY_TOKEN", "a-token-of-the-test");

/// No forwarder was asked, and a relay host was.
fn no_forwarder(w: &World, case: &str) {
    assert!(w.stands.seen.lock().unwrap().is_empty(), "{case}: a forwarder was asked");
    let connects = w.proxy.connects.lock().unwrap().clone();
    assert!(connects.iter().any(|c| is_relay(c.rsplit_once(':').map_or(c.as_str(), |(h, _)| h))), "{connects:?}");
    for host in FORWARDERS {
        assert!(!connects.iter().any(|c| c.starts_with(host)), "{case}: {host} was dialed: {connects:?}");
    }
}

#[test]
fn the_relay_s_answer_about_the_target_ends_the_run_with_no_fallback() {
    let w = world("fallback-answered");
    let target = format!("127.0.0.1:{}", w.sshd);
    let set = [TOKEN, ("PODSSH_DIRECT", "no")];
    let unreached = format!("the relay could not reach {target}");
    let policy = format!("the relay's policy does not allow {target}");
    let cases = [
        (502, format!("relay: cannot reach {target}: connection refused"), unreached),
        (400, "blocked address range".to_string(), policy.clone()),
        (403, format!("forward: {target} not in the ALLOW list"), policy),
    ];
    for (status, body, says) in cases {
        *w.stands.relay.lock().unwrap() = Some((status, body));
        let (code, out, err) = run(podssh(&w, &ssh(&w, &["-v"], "greet"), &set), Vec::new());
        assert_eq!(code, Some(255), "{status}: {err}");
        assert!(out.is_empty(), "{status}: {err}");
        assert!(err.contains(&says), "{status}: the relay's words: {err}");
        assert!(!err.contains("podssh sends") && !err.contains("no forwarder carried"), "{status}: {err}");
        let why = "the public forwarders are not tried: a relay host answered about the target";
        assert!(err.contains(why), "{status}: -v says why: {err}");
        no_forwarder(&w, &status.to_string());
    }
    // podssh proxy, the same: the relay's refusal by policy, 77.
    *w.stands.relay.lock().unwrap() = Some((400, "blocked address range".to_string()));
    let (ca, port) = (w.proxy.ca_file.display().to_string(), w.sshd.to_string());
    let args = ["proxy", "--ca-file", ca.as_str(), "127.0.0.1", port.as_str()].map(String::from);
    let (code, out, err) = run(podssh(&w, &args, &[TOKEN]), Vec::new());
    assert_eq!(code, Some(77), "{err}");
    assert!(out.is_empty() && err.contains(&format!("the relay's policy does not allow {target}")), "{err}");
    assert!(!err.contains("podssh sends"), "{err}");
    no_forwarder(&w, "proxy");
}

/// A refused token says nothing of the target, and a forwarder takes no
/// token: the fallback goes on, and its line says what goes to whom.
#[test]
fn a_refused_token_is_no_word_about_the_target_and_the_fallback_follows() {
    let w = world("fallback-token");
    *w.stands.relay.lock().unwrap() = Some((403, "invalid token".to_string()));
    let set = [TOKEN, ("PODSSH_DIRECT", "no")];
    let (code, out, err) = run(podssh(&w, &ssh(&w, &[], "greet"), &set), Vec::new());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), super::ssh_harness::GREETING);
    assert!(err.contains("the token in PODSSH_RELAY_TOKEN was rejected"), "{err}");
    let line = format!(
        "each relay host failed: podssh sends 127.0.0.1:{} to the public forwarders of other products, in order: \
         mudlet, ssheasy, mudix, wisp, 10 s at most each; PODSSH_FORWARDER_FALLBACK=no turns this off",
        w.sshd
    );
    assert!(err.contains(&line), "{err}");
    assert!(err.contains("the forwarder mudlet (wss://web-proxy.mudlet.org/) carries the session"), "{err}");
    no_token(&w);
}

/// When no forwarder carries the session, one line names each one's
/// reason, in order, in place of a line for each.
#[test]
fn a_fallback_that_none_carries_ends_with_one_line_for_all() {
    let w = world("fallback-none");
    for host in FORWARDERS {
        w.stands.closing.lock().unwrap().insert(host.into());
    }
    let (code, _, err) = run(podssh(&w, &ssh(&w, &[], "greet"), &[("PODSSH_DIRECT", "no")]), Vec::new());
    assert_eq!(code, Some(255), "{err}");
    let lines: Vec<&str> = err.lines().filter(|l| l.contains("the forwarder ")).collect();
    assert_eq!(lines.len(), 1, "{err}");
    let line = lines[0];
    assert!(line.contains(&format!("no forwarder carried the session to 127.0.0.1:{}: ", w.sshd)), "{line}");
    let at: Vec<usize> = ["mudlet (", "ssheasy (", "mudix (", "wisp ("].iter().map(|n| line.find(n).unwrap()).collect();
    assert!(at.windows(2).all(|p| p[0] < p[1]), "in order: {line}");
    no_token(&w);
}

/// `doctor` with no forwarder named: the line of the fallback is ????, and
/// `unknown` in --json, as it asked nothing.
#[test]
fn doctor_s_line_of_the_fallback_is_not_measured() {
    let w = world("fallback-doctor");
    let ca = w.proxy.ca_file.display().to_string();
    let args = ["doctor", "--json", "--ca-file", ca.as_str()].map(String::from);
    let (_, out, err) = run(podssh(&w, &args, &[]), Vec::new());
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{e}: {err}"));
    let checks = doc["checks"].as_array().unwrap_or_else(|| panic!("{doc}"));
    let line = checks.iter().find(|c| c["check"] == "fallback").unwrap_or_else(|| panic!("no fallback line: {doc}"));
    assert_eq!(line["status"], "unknown", "{line}");
    assert!(line["detail"].as_str().unwrap_or_default().starts_with("not asked here: on: "), "{line}");
    assert!(w.stands.seen.lock().unwrap().is_empty(), "doctor asked a forwarder");
}
