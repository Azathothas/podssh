//! T-617 against podssh's relay role on the loopback: a member of the net
//! with the role `relay` and its host in the net's document. A client that
//! holds the net, with no `--relay-host` and no key of `PODSSH_RELAY_KEYS`,
//! asks that host's `/relays.json` before its race, takes the role's signed
//! list by the member's key, and reaches a server through the list's host,
//! which mints its own token; `relay status` names the member and that its
//! list was taken, and asks it no more that day. On another host, a list at
//! the member's host that another key signed is not the member's, also when
//! `PODSSH_RELAY_KEYS` trusts that key. The certificates of the harness need
//! Python and openssl; the test says that it did not run without them.

use std::path::{Path, PathBuf};
use std::process::Command;

use podssh_relay::identity::file::{existing, Place};
use podssh_relay::identity::Identity;
use serde_json::Value;

use super::{client, listed, shown, signing_role};
use crate::throughput_harness::{self, Cell, Session};
use crate::{ran, text, words};

/// `podssh ARGS` under `home` with the net's document in `doc`, as each
/// end keeps its own.
fn with_net(home: &Path, doc: &Path, args: &[&str]) -> Command {
    let mut cmd = throughput_harness::command_in(home, &words(args));
    cmd.env("PODSSH_NET", doc);
    cmd
}

/// A net `home` of one member, `lab`, with the role relay, the key `key` and
/// its host `host`, signed by `owner` into `doc`.
fn net_of(home: &Path, doc: &Path, owner: &str, key: &str, host: &str) {
    let init = ran(with_net(home, doc, &["net", "init", "home", "--owner-key", owner]));
    assert_eq!(init.status.code(), Some(0), "net init: {}", text(&init.stderr));
    let add = ["net", "add", "lab", key, "--roles", "relay", "--relay-host", host, "--owner-key", owner];
    let added = ran(with_net(home, doc, &add));
    assert_eq!(added.status.code(), Some(0), "net add: {}", text(&added.stderr));
}

/// A private directory under `home`, as the files of a net and its owner's
/// key need.
fn private(home: &Path) -> PathBuf {
    let dir = home.join("net-private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    dir
}

#[test]
fn the_net_s_relay_member_gives_its_list_with_no_relay_host() {
    let s = Session::start("relay-members");
    // The deployment of the list, relay-b.test: a role of the harness.
    let backup = match Cell::podssh_relay(&s, "the role of the deployment backup", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| backup.args.iter().position(|a| a == flag).map(|i| backup.args[i + 1].clone()).unwrap();
    let port_b: u16 = at("--relay-host").rsplit(':').next().and_then(|p| p.parse().ok()).unwrap();
    let ca = at("--ca-file");
    let dir = Path::new(&ca).parent().unwrap().to_path_buf();
    let key = s.home.join("list.key");
    let port_a = signing_role(&s, &dir, &key, &format!("backup=relay-b.test:{port_b}"));
    let role = existing(&Place::File(key)).unwrap().expect("the role made its key").public();
    let print = role.fingerprint();
    // The net, whose owner names the role as its member lab, at its host.
    let safe = private(&s.home);
    let (owner, doc) = (safe.join("owner"), safe.join("net.doc"));
    let keygen = words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &shown(&owner)]);
    let made = ran(throughput_harness::command_in(&s.home, &keygen));
    assert_eq!(made.status.code(), Some(0), "keygen: {}", text(&made.stderr));
    let role_host = format!("relay-a.test:{port_a}");
    net_of(&s.home, &doc, &shown(&owner), &role.hex(), &role_host);
    // The default's hosts are pinned where nothing listens, and the hosts of
    // the roles to the loopback.
    let mut pins: Vec<String> = podssh_relay::pool::seed().iter().map(|h| format!("{h}=127.0.0.1")).collect();
    pins.push(format!("{}=127.0.0.1", podssh_relay::relay::default_relay_host()));
    pins.push("relay-a.test=127.0.0.1,relay-b.test=127.0.0.1".into());
    let pins = pins.join(",");
    let member = |home: &Path, doc: &Path, args: &[String], keys: Option<&str>| {
        let mut cmd = client(home, args, keys);
        cmd.env("PODSSH_NET", doc);
        ran(cmd)
    };
    // A session on the default list, with no --relay-host and no key named:
    // the member's list is asked first, and its host carries the session.
    let mut ssh = words(&["ssh"]);
    ssh.extend(s.common());
    ssh.extend(words(&["--relay-addr", &pins, "--ca-file", &ca, "-p", &s.port.to_string(), "tester@127.0.0.1"]));
    ssh.push("greet".into());
    let out = member(&s.home, &doc, &ssh, None);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), crate::ssh_harness::GREETING);
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(events.lines().any(|l| l == "mint") && events.contains("upgrade"), "backup minted and upgraded: {events}");
    // relay status names the deployment, signed by the member's key, and the
    // member with its list taken.
    let status = words(&["relay", "status", "--ca-file", &ca, "--relay-addr", &pins]);
    let out = member(&s.home, &doc, &status, None);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let named = format!("deployment backup: relay-b.test:{port_b}; signed by {print} (the member lab of the net home)");
    assert!(stdout.contains(&named), "{stdout}");
    let taken = format!("member lab of the net home: the role relay at {role_host}; its list taken, serial ");
    assert!(stdout.contains(&taken), "{stdout}");
    // Once a day: two runs more read the ask of the session, and make none.
    let mut json = status.clone();
    json.push("--json".into());
    let asked = |home: &Path| -> Value {
        let out = member(home, &doc, &json, None);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let answer: Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
        answer["members"][0].clone()
    };
    let (first, second) = (asked(&s.home), asked(&s.home));
    assert_eq!((first["name"].as_str(), first["taken"].as_bool()), (Some("lab"), Some(true)), "{first}");
    assert_eq!(first["host"].as_str(), Some(role_host.as_str()), "{first}");
    assert!(first["asked_ms"].as_i64().is_some() && first["asked_ms"] == second["asked_ms"], "{first} {second}");
    // Another host, whose net names lab with another key at the same host:
    // the role's list there is not lab's, though PODSSH_RELAY_KEYS trusts it.
    let elsewhere = throughput_harness::scratch("relay-members-another");
    let other = Identity::from_seed(&[0x61; 32]).public();
    let doc2 = private(&elsewhere).join("net.doc");
    net_of(&elsewhere, &doc2, &shown(&owner), &other.hex(), &role_host);
    let out = member(&elsewhere, &doc2, &status, Some(print.as_str()));
    let stdout = text(&out.stdout);
    let refused = format!(
        "member lab of the net home: the role relay at {role_host}; its list not taken: its list is signed by \
         {print}, not by the member's key {}",
        other.fingerprint()
    );
    assert!(stdout.contains(&refused), "{stdout}\nstderr: {}", text(&out.stderr));
    assert!(!listed(&elsewhere, Some(print.as_str()), "relay-b.test", port_b), "nothing was kept");
    let _ = std::fs::remove_dir_all(&elsewhere);
}
