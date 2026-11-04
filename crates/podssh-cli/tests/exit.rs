//! The exit of the net (T-431) from end to end, on the stand-in relay. A
//! node `gw` with `--exit` and `--routes 127.0.0.1/32`, a member of a net
//! that gives it the role exit, and two members: `a`, whom the policy lets
//! out and lets reach the range, and `b`, whom it lets out to public
//! addresses alone. `a` reaches a test server on the loopback through
//! `podssh proxy --exit`, the test's SSH server through `podssh ssh --exit`,
//! and a page through `podssh exit --listen` by SOCKS5 and by HTTP CONNECT
//! (with curl too, software that podssh did not write, when this host has
//! it). Refused, and never dialled: the loopback for `b`, whose policy names
//! no range, by each client; an address of no range of `--routes` for `a`.
//! A node whose net gives it no role exit does not start (78). The
//! commands with no connection are refused as the manual says. Over a
//! carrier (T-596), with no relay: the node starts `podssh exit --listen
//! --carrier stdio` as its `exec:` program, whose proxy reaches a page
//! through the node; a member with no rule is refused, and the stream's end
//! ends the proxy. `ssh`, `proxy` and `pipe` take `--exit` beside `--carrier`
//! too (T-614, `exit/clients.rs`): each starts the exit's node as its `exec:`
//! program and carries its own session through the node's egress. A check
//! that needs Python and openssl for the stand-in, OpenSSH's sshd, or curl,
//! says that it did not run when this host has none.

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::Identity;
use throughput_harness::{command_in, found, lines_of, wait_for, without_proxy, Cell, Session, PROXY_VARS};

/// The bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(30);

/// What a run gave: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `podssh ARGS` with HOME under `home` and the net's document in `doc`.
fn net(home: &Path, doc: &Path, args: &[&str]) -> (i32, String, String) {
    let words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
    ran(command_in(home, &words).env("PODSSH_NET", doc))
}

/// An owner's key, made by podssh keygen: its file.
fn owner_key(home: &Path) -> PathBuf {
    let path = home.join("owner");
    let words = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].iter().map(|w| w.to_string());
    let words: Vec<String> = words.chain([path.display().to_string()]).collect();
    let (rc, _, err) = ran(&mut command_in(home, &words));
    assert_eq!(rc, 0, "podssh keygen: {err}");
    path
}

/// An end's key in a private file of `dir`, from one byte; and its hex, as
/// `net add` takes it.
fn key_file(dir: &Path, name: &str, seed: u8) -> (String, String) {
    let path = dir.join(name);
    let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
    (path.display().to_string(), Identity::from_seed(&[seed; 32]).public().hex())
}

/// A TCP service on the loopback that writes `word` to each connection, and
/// counts them.
fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

/// An HTTP server on the loopback that answers each request with `ok`.
fn page() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                    head.push(byte[0]);
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n");
            });
        }
    });
    port
}

/// A SOCKS5 CONNECT to `host:port` through the proxy on `proxy`, by name:
/// the reply code, and the stream when it is 0.
fn socks5(proxy: u16, host: &str, port: u16) -> (u8, Option<TcpStream>) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(LIMIT * 2)).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut chosen = [0u8; 2];
    s.read_exact(&mut chosen).unwrap();
    assert_eq!(chosen, [5, 0], "no authentication");
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    (reply[1], (reply[1] == 0).then_some(s))
}

/// An HTTP CONNECT to `target` through the proxy on `proxy`: its status
/// line, and the stream after the head.
fn connect(proxy: u16, target: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(LIMIT * 2)).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    (text.lines().next().unwrap_or_default().to_string(), s)
}

/// The page through `s`, an open tunnel.
fn fetch(mut s: TcpStream) -> String {
    s.write_all(b"GET / HTTP/1.1\r\nHost: page\r\nConnection: close\r\n\r\n").unwrap();
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    body
}

/// A scratch directory that goes when the test ends, pass or fail: the
/// gate fails on a test that leaves one in the temporary directory.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_commands_of_an_exit_are_refused_as_the_manual_says_with_no_connection() {
    let scratch = Scratch(throughput_harness::scratch("exit-refusals"));
    let home = scratch.0.as_path();
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    for (args, code, says) in [
        (words(&["node", "lab", "--routes", "10.0.0.0/8"]), 64, "give --exit too"),
        (words(&["node", "lab", "--exit", "--no-e2e"]), 64, "--no-e2e turns off"),
        (words(&["node", "lab", "--exit", "--routes", "10.0.0.0/33"]), 64, "is not a range"),
        (words(&["exit", "lab"]), 64, "--listen ADDR:PORT"),
        (words(&["exit", "lab", "--listen", "0.0.0.0:1080"]), 64, "a loopback address alone"),
        (words(&["exit", "--listen", "1080"]), 64, "missing NAME"),
        (words(&["proxy", "--exit", "lab", "--relay-host", "r.example", "h.example", "22"]), 64, "relay's place"),
        (words(&["proxy", "--client-key", "k", "h.example", "22"]), 64, "--exit NAME or node://NAME"),
        (words(&["ssh", "--exit", "lab", "node://lab"]), 64, "--exit NAME starts the road"),
        (words(&["ssh", "--exit", "lab", "--direct", "u@h.example"]), 64, "--exit NAME starts the road"),
        (words(&["ssh", "--exit", "lab", "-4", "u@h.example"]), 64, "-4 and -6"),
        (words(&["pipe", "--exit", "lab", "stdio", "tcp:h.example:22"]), 64, "name one of them"),
        // The exit over a carrier (T-596) takes no relay's and no pair's flag.
        (words(&["exit", "lab", "--listen", "1080", "--carrier", "exec:cat", "--pair-file", "x"]), 64, "--carrier has"),
        (words(&["exit", "lab", "--listen", "1080", "--carrier", "tcp:127.0.0.1:1"]), 64, "--carrier tcp:"),
        // ssh, proxy and pipe take it too (T-614), with no stdio, which is
        // their own, and no flag of another road.
        (words(&["ssh", "--exit", "lab", "--carrier", "stdio", "u@h.example"]), 64, "--carrier stdio"),
        (words(&["ssh", "--exit", "lab", "--carrier", "exec:cat", "--pair-file", "x", "u@h.example"]), 64, "carrier:"),
        (words(&["ssh", "--exit", "lab", "--carrier", "exec:cat", "node://lab"]), 64, "--exit NAME starts the road"),
        (words(&["proxy", "--exit", "lab", "--carrier", "stdio", "h.example", "22"]), 64, "--carrier stdio"),
        (words(&["proxy", "--exit", "lab", "--carrier", "exec:cat", "--ca-file", "x", "h", "22"]), 64, "has neither"),
        (words(&["proxy", "--exit", "lab", "--carrier", "exec:cat", "--pair-file", "x", "h", "22"]), 64, "node://"),
        (words(&["pipe", "--exit", "lab", "--carrier", "stdio", "-", "relay:h.example:22"]), 64, "--carrier stdio"),
        (words(&["pipe", "--exit", "lab", "--carrier", "exec:cat", "node:box", "relay:h.example:22"]), 64, "not both"),
    ] {
        let (rc, out, err) = ran(&mut command_in(home, &args));
        assert!(rc == code && err.contains(says) && out.is_empty(), "{args:?}: {rc} {err}");
    }
    let listen = words(&["exit", "lab", "--listen", "1080"]);
    let (rc, _, err) = ran(command_in(home, &listen).env("PODSSH_LISTEN", "no"));
    assert!(rc == 78 && err.contains("PODSSH_LISTEN=no"), "{rc} {err}");
}

#[test]
fn an_exit_carries_what_its_net_lets_out_and_dials_no_address_unchecked() {
    let session = Session::start("exit-ends");
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
    let dir = session.home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let ((gw_key, gw), (lab_key, lab)) = (key_file(&dir, "gw.key", 0x21), key_file(&dir, "lab.key", 0x22));
    let ((a_key, a), (b_key, b)) = (key_file(&dir, "a.key", 0x31), key_file(&dir, "b.key", 0x41));
    let owner = owner_key(&dir).display().to_string();
    let owner_doc = dir.join("owner.doc");
    let owner_says = |args: &[&str]| {
        let mut args = args.to_vec();
        args.extend(["--owner-key", owner.as_str()]);
        let (rc, _, err) = net(&session.home, &owner_doc, &args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home"]);
    owner_says(&["net", "add", "gw", &gw, "--roles", "node,exit"]);
    owner_says(&["net", "add", "lab", &lab]);
    owner_says(&["net", "add", "a", &a]);
    owner_says(&["net", "add", "b", &b]);
    // a goes out and reaches the range; b goes out to public addresses alone.
    let policy = dir.join("policy.json");
    let a_rule = r#"{"from": ["a"], "to": ["exit:gw", "127.0.0.1/32"]}"#;
    let rules = format!(r#"{{"rules": [{a_rule}, {{"from": ["b"], "to": ["exit:gw"]}}]}}"#);
    std::fs::write(&policy, rules).unwrap();
    owner_says(&["net", "policy", "set", &policy.display().to_string()]);
    // Each end takes the owner's document, as a user hands it on.
    let given = dir.join("serial-6");
    std::fs::copy(&owner_doc, &given).unwrap();
    let doc = dir.join("net.doc");
    let (rc, _, err) = net(&session.home, &doc, &["net", "take", &given.display().to_string()]);
    assert!(rc == 0 && err.contains("serial 6"), "{err}");
    // Each end: the pins after the verb, the stand-in's CA, the net's document.
    let end = |args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]).env("PODSSH_NET", &doc);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    for name in ["gw", "lab"] {
        let (rc, _, err) = ran(&mut end(&words(&["relay", "pair", name, "--relay-host", &relay])));
        assert_eq!(rc, 0, "podssh relay pair {name}: {err}");
    }
    // A node whose net gives it no role exit does not start.
    let (rc, _, err) = ran(&mut end(&words(&["node", "lab", "--exit", "--key", &lab_key])));
    assert!(rc == 78 && err.contains("gives lab no role exit"), "{rc} {err}");
    // The exit, with no target of its own.
    let node_args = words(&["node", "gw", "--exit", "--routes", "127.0.0.1/32", "--key", &gw_key]);
    let mut node = end(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let exit = wait_for(&lines, "an exit of the net home as gw").expect("the node says its exit");
    assert!(exit.contains("127.0.0.1/32") && exit.contains("the members that the 2 rules"), "{exit}");
    wait_for(&lines, "online").expect("the node is online");
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    let (word, dials) = service("web\n");
    let proxy = |key: &str, host: &str, port: u16| {
        ran(&mut end(&words(&["proxy", "--exit", "gw", "--client-key", key, host, &port.to_string()])))
    };
    // a: the loopback of the exit's host, in its range.
    let (rc, out, err) = proxy(&a_key, "127.0.0.1", word);
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{err}\nthe node:\n{}", said());
    // b: the policy names no range for it, so the loopback is refused, and
    // never dialled: a private target is never taken for a public one.
    let before = dials.load(Ordering::SeqCst);
    let (rc, out, err) = proxy(&b_key, "127.0.0.1", word);
    assert!(rc != 0 && out.is_empty(), "a private target was reached: {rc} {out} {err}");
    assert!(err.contains("lets b reach 127.0.0.1"), "{err}\nthe node:\n{}", said());
    assert_eq!(dials.load(Ordering::SeqCst), before, "the exit dialled a private target that it refused");
    // a: an address of no range of --routes is refused, before any dial.
    let (rc, out, err) = proxy(&a_key, "10.255.255.1", 9);
    assert!(rc != 0 && out.is_empty() && err.contains("not a public address"), "{rc} {err}\nthe node:\n{}", said());
    // SSH through the exit to the test's server, its host key under its name.
    let mut ssh = vec!["ssh".to_string()];
    ssh.extend(session.common());
    ssh.extend(words(&["--exit", "gw", "--client-key", &a_key, "-p", &session.port.to_string(), "tester@127.0.0.1"]));
    ssh.push("greet".into());
    let (rc, out, err) = ran(&mut end(&ssh));
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}\nthe node:\n{}", said());
    let known = std::fs::read_to_string(session.home.join("known_hosts")).unwrap_or_default();
    assert!(known.contains("127.0.0.1") && !known.contains("node://"), "the host's key under its name: {known}");
    // The local proxy, for a, then for b.
    let site = page();
    for (key, member) in [(&a_key, "a"), (&b_key, "b")] {
        let args = words(&["exit", "gw", "--listen", "127.0.0.1:0", "--client-key", key.as_str()]);
        let mut listener = end(&args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let heard = lines_of(&mut listener);
        session.keep(listener);
        let first = wait_for(&heard, "proxy on 127.0.0.1:").expect("the proxy says where it listens");
        let port = first.split("proxy on 127.0.0.1:").nth(1).and_then(|r| r.split(',').next()).unwrap();
        let port: u16 = port.parse().unwrap();
        let (code, tunnel) = socks5(port, "127.0.0.1", site);
        let (status, stream) = connect(port, &format!("127.0.0.1:{site}"));
        if member == "a" {
            assert_eq!(code, 0, "SOCKS5 for a");
            assert!(fetch(tunnel.unwrap()).ends_with("ok\n"), "a's page by SOCKS5");
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
            assert!(fetch(stream).ends_with("ok\n"), "a's page by CONNECT");
            curl_through(port, site);
        } else {
            assert_eq!(code, 2, "SOCKS5 refuses b by the rules");
            assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        }
    }
}

/// A child that is ended when the test ends, pass or fail.
struct Ended(std::process::Child);

impl Drop for Ended {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The port of the proxy that the line `line` names.
fn port_of(line: &str) -> u16 {
    let port = line.split("proxy on 127.0.0.1:").nth(1).and_then(|r| r.split(',').next()).unwrap();
    port.parse().unwrap()
}

/// The exit over a carrier (T-596, GitHub #124), with no relay and no pair:
/// the node gw, of the role exit, starts `podssh exit gw --listen
/// 127.0.0.1:0 --carrier stdio` as its `exec:` program, as the end with
/// egress starts `ssh -T sandbox podssh exit ...` in the issue; the proxy's
/// SOCKS5 and CONNECT, and curl where this host has it, reach a page of the
/// test through the node. A member with no rule is refused by each protocol,
/// and its target is never dialled. When the node goes, its stream's end
/// ends the proxy, which had one life.
#[test]
fn an_exit_over_a_carrier_lends_its_egress() {
    let scratch = Scratch(throughput_harness::scratch("exit-carrier"));
    let home = scratch.0.as_path();
    let dir = home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let ((gw_key, gw), (a_key, a), (c_key, c)) =
        (key_file(&dir, "gw.key", 0x51), key_file(&dir, "a.key", 0x61), key_file(&dir, "c.key", 0x71));
    let owner = owner_key(&dir).display().to_string();
    let owner_doc = dir.join("owner.doc");
    let owner_says = |args: &[&str]| {
        let mut args = args.to_vec();
        args.extend(["--owner-key", owner.as_str()]);
        let (rc, _, err) = net(home, &owner_doc, &args);
        assert_eq!(rc, 0, "{args:?}: {err}");
    };
    owner_says(&["net", "init", "home"]);
    owner_says(&["net", "add", "gw", &gw, "--roles", "node,exit"]);
    owner_says(&["net", "add", "a", &a]);
    owner_says(&["net", "add", "c", &c]);
    // a goes out and reaches the loopback's range; c, a member, has no rule.
    let policy = dir.join("policy.json");
    std::fs::write(&policy, r#"{"rules": [{"from": ["a"], "to": ["exit:gw", "127.0.0.1/32"]}]}"#).unwrap();
    owner_says(&["net", "policy", "set", &policy.display().to_string()]);
    let (given, doc) = (dir.join("given.doc"), dir.join("net.doc"));
    std::fs::copy(&owner_doc, &given).unwrap();
    let (rc, _, err) = net(home, &doc, &["net", "take", &given.display().to_string()]);
    assert_eq!(rc, 0, "net take: {err}");
    let bin = env!("CARGO_BIN_EXE_podssh");
    // The node, whose program is the proxy of `key`'s member on its stdio:
    // both inherit HOME, the net's document and stderr.
    let node = |key: &str| {
        assert!(![bin, key].iter().any(|w| w.contains('\'')), "a path that the words cannot carry");
        let program = format!("exec:'{bin}' exit gw --listen 127.0.0.1:0 --carrier stdio --client-key '{key}'");
        let words = ["node", "gw", "--exit", "--routes", "127.0.0.1/32", "--key", gw_key.as_str(), "--carrier"];
        let words: Vec<String> = words.iter().map(|w| w.to_string()).chain([program]).collect();
        let mut cmd = without_proxy(command_in(home, &words));
        cmd.env("PODSSH_NET", &doc).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let lines = lines_of(&mut child);
        (Ended(child), lines)
    };
    let site = page();
    let (mut a_node, lines) = node(&a_key);
    let said = |lines: &std::sync::mpsc::Receiver<String>| lines.try_iter().collect::<Vec<_>>().join("\n");
    wait_for(&lines, "an exit of the net home as gw").expect("the node says its exit");
    let first = wait_for(&lines, "proxy on 127.0.0.1:").expect("the proxy says where it listens");
    assert!(first.contains("over the carrier stdio"), "{first}");
    let port = port_of(&first);
    let (code, tunnel) = socks5(port, "127.0.0.1", site);
    assert_eq!(code, 0, "SOCKS5 for a: {}", said(&lines));
    assert!(fetch(tunnel.unwrap()).ends_with("ok\n"), "a's page by SOCKS5");
    let (status, stream) = connect(port, &format!("127.0.0.1:{site}"));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}: {}", said(&lines));
    assert!(fetch(stream).ends_with("ok\n"), "a's page by CONNECT");
    curl_through(port, site);
    // The node goes: the stream of stdio had one life, so the proxy ends.
    let _ = a_node.0.kill();
    wait_for(&lines, "the carrier's stream ended").expect("the proxy ends with its stream");
    // c: a member that the policy names in no rule.
    let (word, dials) = service("web\n");
    let (_c_node, lines) = node(&c_key);
    let port = port_of(&wait_for(&lines, "proxy on 127.0.0.1:").expect("the proxy says where it listens"));
    let (code, _) = socks5(port, "127.0.0.1", word);
    assert_eq!(code, 2, "SOCKS5 refuses c by the rules: {}", said(&lines));
    let (status, _) = connect(port, &format!("127.0.0.1:{word}"));
    assert!(status.starts_with("HTTP/1.1 403"), "{status}: {}", said(&lines));
    wait_for(&lines, "lets c reach").expect("the refusal names the rules");
    assert_eq!(dials.load(Ordering::SeqCst), 0, "the exit dialled a target for a member with no rule");
}

/// The page through the proxy on `proxy`, with curl as its client, by
/// SOCKS5 with the name sent, and by HTTP CONNECT; when this host has curl.
fn curl_through(proxy: u16, site: u16) {
    if !found("curl", &["--version"]) {
        eprintln!("did not run: no curl here");
        return;
    }
    let url = format!("http://127.0.0.1:{site}/");
    // curl takes each option's value as the next word: it reads no `--opt=value`.
    let socks = vec!["--proxy".to_string(), format!("socks5h://127.0.0.1:{proxy}")];
    let tunnel = vec!["--proxytunnel".to_string(), "--proxy".to_string(), format!("http://127.0.0.1:{proxy}")];
    for via in [socks, tunnel] {
        // No proxy of the machine's, and no .curlrc (-q).
        let mut cmd = without_proxy(Command::new("curl"));
        for name in PROXY_VARS.iter().chain(&["http_proxy", "HTTP_PROXY"]) {
            cmd.env_remove(name);
        }
        cmd.args(["-q", "-sS", "--max-time", "60"]).args(&via).arg(&url);
        let (rc, out, err) = ran(&mut cmd);
        assert_eq!((rc, out.as_str()), (0, "ok\n"), "curl {via:?}: {err}");
    }
}

#[path = "exit/clients.rs"]
mod clients;
