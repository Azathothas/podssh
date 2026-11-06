//! A member that relays between two other members (T-434). Three ends on the
//! loopback, each with its own key and its own copy of the net: a node `lab`
//! whose own pair is at a relay role that the client has no pair of, and two
//! members `hub2` and `hub3`, each `podssh relay serve --mint net` with its
//! host in the net's document. The node makes a pair at each hub by its own
//! key; the client `a`, in a home of its own with no pair, reaches `lab` by
//! its name alone through a hub's leg, and its session resumes through the
//! other hub when the one that carried it is killed. With the node's pairs
//! at the hubs turned off (the planted defect), the client reaches nothing.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::{copy_of, key_hex, net, owner_key, ran};
use crate::throughput_harness::{command_in, lines_of, scratch, wait_for, Cell, Session};

/// The bound of each line through the session.
const LINE_LIMIT: Duration = Duration::from_secs(60);

/// `podssh relay serve --mint net` on the stand-ins' certificate in `dir`,
/// for the net of `doc`: its child and its host, `relay-a.test:PORT`.
// The hub's child goes back to the caller, which kills it and waits.
#[allow(clippy::zombie_processes)]
fn hub(s: &Session, dir: &Path, doc: &Path, name: &str) -> (Child, String) {
    let port_file = dir.join(format!("port-{name}"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "net", "--allow-private"]);
    cmd.arg("--cert").arg(dir.join("relay.pem")).arg("--key").arg(dir.join("relay.key"));
    cmd.arg("--port-file").arg(&port_file).env("PODSSH_NET", doc).env("HOME", &s.home);
    let log = std::fs::File::create(s.home.join(format!("{name}.log"))).unwrap();
    let mut child = cmd.stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return (child, format!("relay-a.test:{port}"));
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the hub {name} did not start");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The client's line `text` through the session, and its echo back.
fn echoed(stdin: &mut impl Write, out: &mut impl BufRead, text: &str, said: &Path) {
    writeln!(stdin, "{text}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    // The harness's `echo` sends each line back; a session that cannot
    // resume ends the client, and the read ends with nothing.
    let started = Instant::now();
    out.read_line(&mut line).unwrap();
    let words = || std::fs::read_to_string(said).unwrap_or_default();
    let took = started.elapsed();
    assert!(took < LINE_LIMIT, "the echo of {text:?} came after {took:?}; the client said: {}", words());
    assert_eq!(line.trim_end(), text, "the echo of {text:?}; the client said: {}", words());
}

#[test]
fn a_member_relays_between_two_members_that_share_no_road() {
    let s = Session::start("net-relay");
    // The node's own relay, which mints for anyone; the hubs share its
    // certificate of relay-a.test, each on its own port.
    let own = match Cell::podssh_relay(&s, "the node's own relay", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| own.args.iter().position(|a| a == flag).map(|i| own.args[i + 1].clone()).unwrap();
    let (own_relay, ca) = (at("--relay-host"), at("--ca-file"));
    let certs = PathBuf::from(&ca).parent().unwrap().to_path_buf();
    let dir = s.home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let key_file = |name: &str, seed: u8| {
        let path = dir.join(name);
        let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
        podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
        path.display().to_string()
    };
    let (node_key, a_key) = (key_file("node.key", 0x21), key_file("a.key", 0x31));
    let (owner_doc, node_doc, a_doc) = (dir.join("owner.doc"), dir.join("node.doc"), dir.join("a.doc"));
    let (owner, _) = owner_key(&dir, "owner");
    let o = owner.display().to_string();
    let owner_says = |args: &[&str]| {
        let (rc, _, err) = net(&s.home, &owner_doc, args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home", "--owner-key", &o]);
    owner_says(&["net", "add", "lab", &key_hex(0x21), "--owner-key", &o]);
    owner_says(&["net", "add", "a", &key_hex(0x31), "--owner-key", &o]);
    // The hubs read the owner's document at each request: their hosts go in
    // once they listen.
    let (mut hub2, host2) = hub(&s, &certs, &owner_doc, "hub2");
    let (mut hub3, host3) = hub(&s, &certs, &owner_doc, "hub3");
    for (name, seed, host) in [("hub2", 0x52, &host2), ("hub3", 0x53, &host3)] {
        owner_says(&["net", "add", name, &key_hex(seed), "--roles", "relay", "--relay-host", host, "--owner-key", &o]);
    }
    let given = copy_of(&owner_doc, &dir, "given");
    for doc in [&node_doc, &a_doc] {
        let (rc, _, err) = net(&s.home, doc, &["net", "take", &given]);
        assert_eq!(rc, 0, "{err}");
    }
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    // Each end's commands: its home, its net, the stand-ins' CA, the pins
    // after the verb, and no Piping Server road.
    let end = |home: &Path, doc: &Path, args: &[String]| {
        let mut cmd = command_in(home, &args[..1]);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", doc).env("SSL_CERT_FILE", &ca);
        cmd.env("PODSSH_PIPING", "no").env_remove("HTTPS_PROXY").env_remove("https_proxy");
        cmd
    };
    let (rc, _, err) = ran(&mut end(&s.home, &node_doc, &words(&["relay", "pair", "lab", "--relay-host", &own_relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let node_args = words(&["node", "lab", &format!("127.0.0.1:{}", s.port), "--key", &node_key]);
    let mut node = end(&s.home, &node_doc, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    for host in [&host2, &host3] {
        let made = wait_for(&lines, "at the net's relay member").expect("the node pairs at each hub");
        assert!(made.contains("by this node's key"), "{made} (for {host})");
    }
    wait_for(&lines, "online").expect("the node is online");

    // The client: a home of its own, with no pair of lab.
    let client_home = scratch("net-relay-client");
    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(s.common());
    args.extend(words(&["--client-key", &a_key, "node://tester@lab", "echo"]));
    // Its words go to a file, for the message of a line that did not come.
    let said = s.home.join("client.err");
    let mut ssh = end(&client_home, &a_doc, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&said).unwrap())
        .spawn()
        .unwrap();
    let mut stdin = ssh.stdin.take().unwrap();
    let mut out = BufReader::new(ssh.stdout.take().unwrap());
    echoed(&mut stdin, &mut out, "through a hub", &said);
    // The hub that carried it, or the other: either way, the session goes
    // on through a hub that lives.
    let _ = hub2.kill();
    let _ = hub2.wait();
    echoed(&mut stdin, &mut out, "after a hub went", &said);
    drop(stdin);
    let deadline = Instant::now() + LINE_LIMIT;
    while ssh.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the client did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    let code = ssh.wait().unwrap().code();
    let err = std::fs::read_to_string(&said).unwrap_or_default();
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("a member's relay role answered first"), "{err}");
    let _ = hub3.kill();
    let _ = hub3.wait();
    let _ = std::fs::remove_dir_all(&client_home);
}
