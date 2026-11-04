//! T-346 against podssh's relay role on the loopback: a role that signs its
//! list of deployments with a key of its own, and a client that takes the
//! list's host outside the default's domain only while it trusts that key,
//! then reaches a server through that host with a token of its own. The
//! keys are made here; they need Python and openssl for the certificates of
//! the harness, and say that they did not run without them.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::identity::file::{existing, Place};
use podssh_relay::identity::PublicKey;
use podssh_relay::pool::signed;
use serde_json::Value;

use super::throughput_harness::{self, Cell, Session};
use super::{ran, text, words};

/// `podssh ARGS` under `home`, with nothing of this machine's relay
/// settings, net, cache or proxy, no direct road, and the keys of `keys`.
fn client(home: &Path, args: &[String], keys: Option<&str>) -> Command {
    let mut cmd = throughput_harness::without_proxy(throughput_harness::command_in(home, args));
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_TOKEN", "PODSSH_RELAY_KEYS", "PODSSH_CACHE_DIR", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_NET", "no").env("PODSSH_DIRECT", "no");
    if let Some(keys) = keys {
        cmd.env("PODSSH_RELAY_KEYS", keys);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// The role that signs its list, a process of its own beside the harness's,
/// with the harness's certificate in `dir`: its port.
fn signing_role(s: &Session, dir: &Path, key: &Path, deployment: &str) -> u16 {
    let port_file = dir.join("port-signing-role");
    let log = s.home.join("signing-role.log");
    let mut args = words(&["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--cert"]);
    args.extend([shown(&dir.join("relay.pem")), "--key".into(), shown(&dir.join("relay.key"))]);
    args.extend(["--port-file".into(), shown(&port_file), "--list-key".into(), shown(key)]);
    args.extend(["--deployment".into(), deployment.to_string()]);
    let file = std::fs::File::create(&log).unwrap();
    let mut cmd = throughput_harness::without_proxy(throughput_harness::command_in(&s.home, &args));
    cmd.stdin(Stdio::null()).stdout(file.try_clone().unwrap()).stderr(file);
    s.keep(cmd.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()) {
            return port;
        }
        let said = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(Instant::now() < deadline, "the signing role did not start within 30 s: {said}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether the list of `podssh status` holds `host:port`.
fn listed(home: &Path, keys: Option<&str>, host: &str, port: u16) -> bool {
    let out = ran(client(home, &words(&["status"]), keys));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).expect("one JSON line");
    let relays = doc["relays"].as_array().cloned().unwrap_or_default();
    relays.iter().any(|r| r["host"] == host && r["port"] == port)
}

#[test]
fn a_role_s_signed_list_names_a_deployment_outside_the_domain() {
    let s = Session::start("relay-signed");
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
    // The key that the role made, read as a test reads a file of its own.
    let print = existing(&Place::File(key)).unwrap().expect("the role made its key").public().fingerprint();
    let said = std::fs::read_to_string(s.home.join("signing-role.log")).unwrap_or_default();
    assert!(said.contains(&format!("signed by the key {print}")), "the first line names the key: {said}");
    let names = "relay-a.test=127.0.0.1,relay-b.test=127.0.0.1";
    let info = |home: &Path, keys: Option<&str>| {
        let mut args = words(&["info", "--relay-host", &format!("relay-a.test:{port_a}"), "--ca-file", &ca]);
        args.extend(words(&["--relay-addr", names]));
        let mut all = words(&["relay"]);
        all.extend(args);
        ran(client(home, &all, keys))
    };
    // Trusted: the list is kept, and its host joins the default list.
    let trusted = Some(print.as_str());
    let out = info(&s.home, trusted);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    let head = format!("signed list: signed by {print} (PODSSH_RELAY_KEYS), serial ");
    assert!(stdout.contains(&head) && stdout.contains("kept; its deployments follow the default list"), "{stdout}");
    assert!(stdout.contains(&format!("  deployment backup: relay-b.test:{port_b}")), "{stdout}");
    assert!(listed(&s.home, trusted, "relay-b.test", port_b), "the host outside the domain is in the list");
    assert!(!listed(&s.home, Some("none"), "relay-b.test", port_b), "none trusts no key");
    let bad = ran(client(&s.home, &words(&["status"]), Some("not-a-key")));
    assert_eq!(bad.status.code(), Some(78), "{}", text(&bad.stderr));
    // relay status names each deployment, and that the list was signed; the
    // default's hosts are pinned where nothing listens.
    let mut pins: Vec<String> = podssh_relay::pool::SEED.iter().map(|h| format!("{h}=127.0.0.1")).collect();
    pins.extend([format!("{}=127.0.0.1", podssh_relay::relay::DEFAULT_RELAY_HOST), names.to_string()]);
    let pins = pins.join(",");
    let out = ran(client(&s.home, &words(&["relay", "status", "--ca-file", &ca, "--relay-addr", &pins]), trusted));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}\nstderr: {}", text(&out.stderr));
    assert!(stdout.contains("relay-b.test: tcp-ssh-relay podssh "), "{stdout}");
    assert!(stdout.contains("deployment default: "), "{stdout}");
    let named = format!("deployment backup: relay-b.test:{port_b}; signed by {print} (PODSSH_RELAY_KEYS)");
    assert!(stdout.contains(&named), "{stdout}");
    // A session on the default list goes through the other deployment,
    // which mints its own token: the default's hosts are not reached.
    let mut ssh = words(&["ssh"]);
    ssh.extend(s.common());
    ssh.extend(words(&["--relay-addr", &pins, "--ca-file", &ca, "-p", &s.port.to_string(), "tester@127.0.0.1"]));
    ssh.push("greet".into());
    let out = ran(client(&s.home, &ssh, trusted));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), super::ssh_harness::GREETING);
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(events.lines().any(|l| l == "mint") && events.contains("upgrade"), "backup minted and upgraded: {events}");
    // Untrusted, on another host: the list is not used, nor kept.
    let elsewhere = throughput_harness::scratch("relay-signed-untrusted");
    let out = info(&elsewhere, None);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let refused = format!("signed list: not used: signed by {print}, a key that this podssh does not trust");
    assert!(stdout.contains(&refused), "{stdout}");
    assert!(!listed(&elsewhere, None, "relay-b.test", port_b), "an untrusted list adds no host");
    let _ = std::fs::remove_dir_all(&elsewhere);
}

/// A list that OpenSSL signed, software that podssh did not write, with an
/// Ed25519 key that it made here: podssh takes its signature of the label and
/// the text, and refuses it once a byte of the text changed.
#[test]
fn a_list_that_openssl_signed_is_taken() {
    if !throughput_harness::found("openssl", &["version"]) {
        eprintln!("did not run: no openssl here");
        return;
    }
    let dir = throughput_harness::scratch("relay-signed-openssl");
    let at = |name: &str| shown(&dir.join(name));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let deployments = vec![signed::parse_deployment("backup=relay.example.org").unwrap()];
    let doc = signed::Doc { serial: 3, issued: now - 60, not_after: now + 86_400, deployments };
    let body = doc.to_text();
    std::fs::write(dir.join("message"), [signed::LABEL, body.as_bytes()].concat()).unwrap();
    let openssl = |args: &[&str]| {
        let out = Command::new("openssl").args(args).stdin(Stdio::null()).output().unwrap();
        out.status.success().then_some(()).ok_or_else(|| format!("openssl {args:?}: {}", text(&out.stderr)))
    };
    // An openssl with no Ed25519, or no raw signature (LibreSSL's, of some
    // versions), makes none: said, as each test of the harness says it.
    let (pem, message, sig_file) = (at("key.pem"), at("message"), at("sig"));
    let made = openssl(&["genpkey", "-algorithm", "ed25519", "-out", &pem])
        .and_then(|()| openssl(&["pkeyutl", "-sign", "-rawin", "-inkey", &pem, "-in", &message, "-out", &sig_file]));
    if let Err(why) = made {
        eprintln!("did not run: {why}");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    openssl(&["pkey", "-in", &pem, "-pubout", "-outform", "DER", "-out", &at("public.der")]).unwrap();
    // The key's 32 bytes end its SubjectPublicKeyInfo.
    let der = std::fs::read(dir.join("public.der")).unwrap();
    let key = PublicKey(der[der.len() - 32..].try_into().unwrap());
    let sig: [u8; 64] = std::fs::read(dir.join("sig")).unwrap().try_into().expect("64 bytes of signature");
    let list = signed::Signed { text: body.clone(), key, sig };
    let print = key.fingerprint();
    let keys = signed::Keys::from_parts(Some(print.as_str()), Vec::new());
    let checked = signed::check(&list, &keys, now).expect("OpenSSL's signature verifies");
    assert_eq!(checked.doc, doc);
    let changed = signed::Signed { text: body.replace("relay.example.org", "relay.example.orh"), ..list };
    assert_eq!(signed::check(&changed, &keys, now), Err(signed::Refused::Signature(key)));
    let _ = std::fs::remove_dir_all(&dir);
}
