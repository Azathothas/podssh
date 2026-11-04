//! The net's routes (T-432) from end to end, on the stand-in relay: an exit
//! `gw` whose routes the owner lists in the net's document, beside its own
//! `--routes`, and an exit `far` with a wider route that never runs. A
//! member reaches a target through `--exit auto`, which picks the exit
//! whose narrowest route holds the target's address: `podssh ssh` to the
//! test's SSH server and `podssh proxy` to a service, on the loopback that
//! `gw` names alone; `far` for an address of its route alone, which fails
//! as no pair is kept for it; and none for an address that no route holds,
//! or a name. Where podman runs a container on its bridge, a service there,
//! on a private address of a range that `gw` routes, is reached the same
//! way, and the host's own address on that bridge, which the range holds
//! too, is refused and never dialled. A check that needs Python and openssl
//! for the stand-in, OpenSSH's sshd, or podman says that it did not run.

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use podssh_relay::identity::Identity;
use throughput_harness::{command_in, lines_of, wait_for, Cell, Session};

/// The image of the container, as the box pins it.
const IMAGE: &str =
    "docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a";
/// The port of the container's service.
const ROUTED_PORT: u16 = 7007;

/// What a run gave: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// An end's key in a private file of `dir`, from one byte; and its hex.
fn key_file(dir: &Path, name: &str, seed: u8) -> (String, String) {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    (path.display().to_string(), Identity::from_seed(&[seed; 32]).public().hex())
}

/// A TCP service on `at` that writes `word` to each connection, and counts
/// them.
fn service(at: &str, word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((at, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes());
        }
    });
    (port, count)
}

/// A container of podman on its bridge, which writes `routed` to each
/// connection on [`ROUTED_PORT`], removed when the test ends.
struct Routed {
    id: String,
    /// Its address, on the bridge's private network.
    addr: IpAddr,
}

impl Routed {
    /// The container, or why it could not run here.
    fn start() -> Result<Routed, String> {
        let loop_ = format!("while true; do nc -l -p {ROUTED_PORT} -e echo routed; done");
        let run = ["run", "-d", "--rm", "--network", "bridge", IMAGE, "sh", "-c", &loop_];
        let out = Command::new("podman").args(run).stdin(Stdio::null()).output().map_err(|e| format!("podman: {e}"))?;
        if !out.status.success() {
            return Err(format!("podman run: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let routed = |addr| Routed { id: id.clone(), addr };
        let inspect = ["inspect", "-f", "{{.NetworkSettings.IPAddress}}", &id];
        let out = Command::new("podman").args(inspect).output().map_err(|e| format!("podman inspect: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        match text.parse::<IpAddr>() {
            Ok(addr) if !addr.is_loopback() => Ok(routed(addr)),
            _ => {
                drop(routed(IpAddr::from([0, 0, 0, 0])));
                Err(format!("the container has no address on the bridge: {text:?}"))
            }
        }
    }
}

impl Drop for Routed {
    fn drop(&mut self) {
        let _ =
            Command::new("podman").args(["rm", "-f", &self.id]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// This host's address toward `peer`, as its routes choose it; no packet is
/// sent.
fn own_toward(peer: IpAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((peer, 9)).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

/// The /16 of an IPv4 address, as a route names it.
fn sixteen(addr: IpAddr) -> Option<String> {
    let IpAddr::V4(v4) = addr else { return None };
    let [a, b, _, _] = v4.octets();
    Some(format!("{a}.{b}.0.0/16"))
}

/// A scratch directory that goes when the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_owner_lists_routes_of_an_exit_alone_and_auto_is_no_member_s_name() {
    let scratch = Scratch(throughput_harness::scratch("exit-routes-refusals"));
    let home = &scratch.0;
    let doc = home.join("net.doc");
    let owner = home.join("owner");
    let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &owner.display().to_string()].map(String::from);
    assert_eq!(ran(&mut command_in(home, &keygen)).0, 0);
    let net = |args: &[&str]| {
        let mut words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
        words.extend(["--owner-key".to_string(), owner.display().to_string()]);
        ran(command_in(home, &words).env("PODSSH_NET", &doc))
    };
    assert_eq!(net(&["net", "init", "home"]).0, 0);
    let key = "ab".repeat(32);
    for (args, says) in [
        (vec!["net", "add", "gw", &key, "--routes", "10.0.0.0/8"], "give --roles with exit too"),
        (vec!["net", "add", "gw", &key, "--roles", "node,exit", "--routes", "10.0.0.0/33"], "is not a range"),
        (vec!["net", "add", "auto", &key, "--roles", "node,exit"], "the word of --exit auto"),
    ] {
        let (rc, _, err) = net(&args);
        assert!(rc == 64 && err.contains(says), "{args:?}: {rc} {err}");
    }
    let (rc, _, err) = net(&["net", "add", "gw", &key, "--roles", "node,exit", "--routes", "10.1.0.0/16, fd00::/8"]);
    assert_eq!(rc, 0, "{err}");
    let text = std::fs::read_to_string(&doc).unwrap();
    assert!(text.contains(r#""routes":["10.1.0.0/16","fd00::/8"]"#), "{text}");
}

#[test]
fn exit_auto_picks_the_exit_whose_narrowest_route_holds_the_address() {
    let session = Session::start("exit-routes");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let routed = Routed::start();
    if let Err(why) = &routed {
        eprintln!("the container's checks did not run: {why}");
    }
    let bridge = routed.as_ref().ok().and_then(|r| sixteen(r.addr));
    let mut routes = "127.0.0.1/32".to_string();
    if let Some(range) = &bridge {
        routes = format!("{routes},{range}");
    }
    let dir = session.home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let ((gw_key, gw), (_, far), (a_key, a)) =
        (key_file(&dir, "gw.key", 0x51), key_file(&dir, "far.key", 0x52), key_file(&dir, "a.key", 0x61));
    let owner = dir.join("owner").display().to_string();
    let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &owner].map(String::from);
    assert_eq!(ran(&mut command_in(&session.home, &keygen)).0, 0);
    let owner_doc = dir.join("owner.doc");
    let owner_says = |args: &[&str]| {
        let mut words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
        words.extend(["--owner-key".to_string(), owner.clone()]);
        let (rc, _, err) = ran(command_in(&session.home, &words).env("PODSSH_NET", &owner_doc));
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home"]);
    owner_says(&["net", "add", "gw", &gw, "--roles", "node,exit", "--routes", &routes]);
    owner_says(&["net", "add", "far", &far, "--roles", "node,exit", "--routes", "10.0.0.0/8"]);
    owner_says(&["net", "add", "a", &a]);
    let policy = dir.join("policy.json");
    let mut reach = vec!["exit:gw", "exit:far", "127.0.0.1/32", "10.0.0.0/8"];
    if let Some(range) = &bridge {
        reach.push(range);
    }
    let rules = serde_json::json!({"rules": [{"from": ["a"], "to": reach}]});
    std::fs::write(&policy, rules.to_string()).unwrap();
    owner_says(&["net", "policy", "set", &policy.display().to_string()]);
    let doc = dir.join("net.doc");
    let take = ["net", "take", &owner_doc.display().to_string()].map(String::from);
    let (rc, _, err) = ran(command_in(&session.home, &take).env("PODSSH_NET", &doc));
    assert_eq!(rc, 0, "{err}");
    let end = |args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", &doc);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&mut end(&words(&["relay", "pair", "gw", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair gw: {err}");
    let node_args = words(&["node", "gw", "--exit", "--routes", &routes, "--key", &gw_key]);
    let mut node = end(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "an exit of the net home as gw").expect("the node says its exit");
    wait_for(&lines, "online").expect("the node is online");
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    assert!(!said().contains("lists the routes"), "the document lists the node's own --routes");
    let proxy = |host: &str, port: u16, exit: &str| {
        ran(&mut end(&words(&["proxy", "--exit", exit, "--client-key", &a_key, host, &port.to_string()])))
    };
    // The loopback, which gw's route names alone.
    let (word, _) = service("127.0.0.1", "web\n");
    let (rc, out, err) = proxy("127.0.0.1", word, "auto");
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{err}\nthe node:\n{}", said());
    assert!(err.contains("--exit auto: 127.0.0.1 is in 127.0.0.1/32, a route of the exit gw"), "{err}");
    // SSH, its exit picked once the first hop is known.
    let mut ssh = vec!["ssh".to_string(), "-v".to_string()];
    ssh.extend(session.common());
    ssh.extend(words(&["--exit", "auto", "--client-key", &a_key, "-p", &session.port.to_string(), "tester@127.0.0.1"]));
    ssh.push("greet".into());
    let (rc, out, err) = ran(&mut end(&ssh));
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}\nthe node:\n{}", said());
    assert!(err.contains("a route of the exit gw"), "{err}");
    // far's route alone holds it: far is picked, and has no pair here.
    let (rc, out, err) = proxy("10.200.0.1", 9, "auto");
    assert!(rc != 0 && out.is_empty() && err.contains("a route of the exit far"), "{rc} {err}");
    // No route holds it, and a name is resolved at the exit alone.
    let (rc, out, err) = proxy("192.168.77.1", 9, "auto");
    assert!(rc == 78 && out.is_empty() && err.contains("no exit of the net home"), "{rc} {err}");
    let (rc, _, err) = proxy("db.example", 22, "auto");
    assert!(rc == 64 && err.contains("db.example is a name"), "{rc} {err}");
    let Ok(routed) = routed else { return };
    // A service on the bridge's private network, in gw's route.
    let host = routed.addr.to_string();
    let reached = (0..20).find_map(|_| {
        let (rc, out, err) = proxy(&host, ROUTED_PORT, "auto");
        if rc == 0 && out == "routed\n" {
            return Some(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        None
    });
    let err = reached.unwrap_or_else(|| panic!("the container's service was not reached\nthe node:\n{}", said()));
    assert!(err.contains(&format!("is in {}, a route of the exit gw", bridge.unwrap())), "{err}");
    // This host's own address on that bridge, which the range holds too:
    // refused, and never dialled.
    let Some(own) = own_toward(routed.addr) else {
        return eprintln!("the check of the host's own address did not run: no address toward the bridge");
    };
    let (port, dials) = service("0.0.0.0", "own\n");
    let (rc, out, err) = proxy(&own.to_string(), port, "gw");
    assert!(rc != 0 && out.is_empty(), "the host's own service was reached: {rc} {out} {err}");
    assert!(err.contains("an address of the exit's host"), "{err}\nthe node:\n{}", said());
    assert_eq!(dials.load(Ordering::SeqCst), 0, "the exit dialled its own host's address");
}
