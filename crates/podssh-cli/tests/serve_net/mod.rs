//! `podssh relay serve --mint net` (T-455): the role mints, and makes pairs,
//! for the members of the net that its host holds, each by its key's
//! signature of the role's challenge. The owner signs the net with `podssh
//! net` in a private directory, and the role reads it from `PODSSH_NET`, for
//! each request: a member mints and pairs; a stranger gets `403` that names
//! its key and not the net; the owner removes the member, and the next
//! document's serial refuses it. A host that holds no net does not start.

use std::path::Path;
use std::process::Command;

use podssh_relay::identity::Identity;
use podssh_relay::keyed;

use super::{ran, relay_flags, role_env, said, LIMIT};
use crate::throughput_harness::Session;

/// `podssh net ARGS` of the owner, with the net's document in `doc`.
fn net(s: &Session, doc: &Path, args: &[&str]) {
    let words: Vec<String> = ["net"].iter().chain(args).map(|w| w.to_string()).collect();
    let mut cmd = s.command(&words);
    cmd.env("PODSSH_NET", doc);
    let out = ran(cmd);
    assert!(out.status.success(), "podssh net {args:?}: {}", said(&out));
}

#[test]
fn a_relay_that_mints_for_the_net_takes_its_members_and_a_member_removed_is_refused() {
    let s = Session::start("serve-net");
    let dir = s.home.join("net");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let (doc, owner) = (dir.join("home.doc"), dir.join("owner"));
    let mut keygen = s.command(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].map(String::from));
    keygen.arg(&owner);
    assert!(ran(keygen).status.success(), "the owner's key");
    let owner_arg = owner.display().to_string();
    net(&s, &doc, &["init", "home", "--owner-key", &owner_arg]);
    let (member, stranger) = (Identity::from_seed(&[0x61; 32]), Identity::from_seed(&[0x62; 32]));
    let hex = member.public().hex();
    net(&s, &doc, &["add", "laptop", &hex, "--roles", "node", "--owner-key", &owner_arg]);

    let env = [("PODSSH_NET", doc.display().to_string())];
    let Some(cell) = role_env(&s, &["--mint", "net"], &env) else { return };
    let started = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    assert!(started.contains("minting for the members of the net home (serial 2, 1 member"), "{started}");
    let flags = relay_flags(&cell);
    let (host, port) = flags[1].rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())).unwrap();
    let trust = podssh_ws::Trust::File(flags[3].clone().into());
    podssh_ws::resolve::set_pins(podssh_ws::resolve::parse_pins("relay-a.test=127.0.0.1").unwrap());
    let proxy = podssh_ws::ProxyChoice::Direct;
    let post = |path: &str, body: Vec<u8>| {
        s.runtime
            .block_on(podssh_ws::https_post_json(&host, port, path, &body, &trust, &proxy, LIMIT))
            .expect("the role answers")
    };
    let sent_host = keyed::host_header(&host, port);
    let signed = |key: &Identity, path: &str| {
        let challenge = keyed::challenge_of(&post(path, b"{}".to_vec())).expect("a 401 with a challenge");
        post(path, keyed::proof(key, &sent_host, path, &challenge))
    };

    // The member mints, and makes a pair.
    let minted = signed(&member, "/v1/mint");
    assert_eq!(minted.status, 200, "{}", minted.body_text(300));
    let paired = signed(&member, "/v1/pair");
    assert_eq!(paired.status, 200, "{}", paired.body_text(300));
    assert!(paired.body_text(300).contains("node_token"), "{}", paired.body_text(300));
    // A stranger: 403, which names its key and the serial, never the net.
    let refused = signed(&stranger, "/v1/mint");
    let text = refused.body_text(300);
    assert_eq!(refused.status, 403, "a stranger minted: {text}");
    assert!(text.contains(&stranger.public().fingerprint()) && text.contains("not a member"), "{text}");
    // Words with a space, which no fingerprint holds.
    assert!(text.contains("(serial 2)") && !text.contains(" home") && !text.contains(" laptop"), "{text}");

    // The owner removes the member: from the next serial on, it mints no more.
    net(&s, &doc, &["rm", "laptop", "--owner-key", &owner_arg]);
    let removed = signed(&member, "/v1/mint");
    let text = removed.body_text(300);
    assert_eq!(removed.status, 403, "a member removed: {text}");
    assert!(text.contains("not a member") && text.contains("(serial 3)"), "{text}");
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    let print = member.public().fingerprint();
    assert!(
        events.contains(&format!("/v1/mint: the key {print}, the member laptop of the net home (serial 2)")),
        "{events}"
    );
    assert!(events.contains(&format!("/v1/pair: the key {print}, the member laptop")), "{events}");
}

#[test]
fn a_relay_for_a_net_that_this_host_does_not_hold_does_not_start() {
    let s = Session::start("serve-net-none");
    let serve = ["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c.pem", "--key", "k.pem", "--mint"];
    for (net, mint, says) in [
        (s.home.join("none.doc").display().to_string(), "net", "this host holds no net"),
        ("no".to_string(), "net,keys:allow", "PODSSH_NET=no turns the net off"),
    ] {
        let words: Vec<String> = serve.iter().map(|w| w.to_string()).chain([mint.to_string()]).collect();
        let mut cmd: Command = s.command(&words);
        cmd.env("PODSSH_NET", &net);
        let out = ran(cmd);
        assert_eq!(out.status.code(), Some(78), "{mint}: {}", said(&out));
        assert!(said(&out).contains(says), "{mint}: {}", said(&out));
    }
}
