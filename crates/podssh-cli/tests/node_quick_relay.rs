//! `podssh node --quick-tunnel --relay` (T-428) as a process, offline, with a
//! scratch HOME and cache: the role's flags need `--relay`, and `--relay`
//! the quick tunnel; `--mint` takes the words of `podssh relay serve`, and a
//! list that cannot be read stops the start; the relay alone needs no
//! TARGET. Each refusal comes before any connection, and with
//! PODSSH_OFFLINE nothing is asked.

mod pair_harness;

use pair_harness::*;

#[test]
fn the_relay_s_flags_are_refused_before_any_connection_without_their_needs() {
    let home = scratch("quick-relay");
    let allow = home.join("allow");
    std::fs::write(&allow, "").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    for (args, says) in [
        (vec!["node", "lab", "127.0.0.1:22", "--relay"], "--relay is for --quick-tunnel"),
        (
            vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--allow", &allow, "--mint", "anyone"],
            "--mint is a setting of the relay role",
        ),
        (
            vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--allow", &allow, "--pairs", "pairs.json"],
            "--pairs is a setting of the relay role",
        ),
        (vec!["node", "lab", "127.0.0.1:22", "--allow-private"], "--allow-private is a setting of the relay role"),
        (
            vec!["node", "lab", "--quick-tunnel", "--relay", "--allow", &allow, "--mint", "everyone"],
            "anyone, nobody or keys:FILE",
        ),
        (vec!["node", "lab", "--quick-tunnel", "--relay"], "needs --allow FILE"),
        (vec!["node", "lab", "--quick-tunnel", "--allow", &allow], "missing TARGET"),
        (vec!["node", "lab", "web=127.0.0.1:80", "--quick-tunnel", "--relay", "--allow", &allow], "one TARGET"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// The list of `--mint keys:FILE` is read as the node starts, as `relay
/// serve` reads it: one that cannot be read stops it (78), before anything
/// connects.
#[test]
fn a_list_that_cannot_be_read_stops_the_start() {
    let home = scratch("quick-relay-list");
    let allow = home.join("allow");
    std::fs::write(&allow, "").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    let keys = format!("keys:{}", home.join("no-such-list").to_string_lossy());
    let args = ["node", "lab", "--quick-tunnel", "--relay", "--allow", &allow, "--mint", &keys];
    let (rc, out, err) = podssh(&home, &args, &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("no-such-list") && out.is_empty(), "{err}");
}

/// The relay alone, and beside a TARGET, pass each check that needs no
/// network; PODSSH_OFFLINE then stops each before it asks for a tunnel.
#[test]
fn the_relay_alone_needs_no_target() {
    let home = scratch("quick-relay-alone");
    let allow = home.join("allow");
    std::fs::write(&allow, "").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    for args in [
        vec!["node", "lab", "--quick-tunnel", "--relay", "--allow", &allow],
        vec!["node", "lab", "127.0.0.1:22", "--quick-tunnel", "--relay", "--allow", &allow, "--mint", "anyone"],
        vec!["node", "lab", "--quick-tunnel", "--relay", "--allow", &allow, "--mint", "nobody", "--allow-private"],
    ] {
        let (rc, out, err) = podssh(&home, &args, &[("PODSSH_OFFLINE", "1")]);
        assert_eq!(rc, 69, "{args:?}: {err}");
        assert!(err.contains("PODSSH_OFFLINE") && out.is_empty(), "{args:?}: {err}");
    }
}
