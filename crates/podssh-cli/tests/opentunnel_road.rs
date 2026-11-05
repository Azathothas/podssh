//! The OpenTunnel road of the command line from end to end (T-531), on this
//! machine's loopback: podssh-relay's stand-in OpenTunnel server
//! (`tests/opentunnel_stand_in`), its API behind TLS of its own CA and its
//! visitors' port raw, as the service's; a stand-in proxy of the node's and
//! the client's that takes a CONNECT to the service's names alone and refuses
//! each other one, as a cage whose proxy passes TLS by name and no upgrade to
//! the relay; an SSH server for the node's TARGET; `podssh node lab TARGET
//! --opentunnel --allow FILE`, and `podssh ssh node://tester@lab
//! --opentunnel-name NAME greet` with the pair's road down: the race goes to
//! OpenTunnel. A later run with no name falls back on the one kept, and
//! PODSSH_OPENTUNNEL=no turns that off. A node with no door is refused (64);
//! one with no pair and the DERP road off serves the road unasked (Q76).
//! Planted (`scripts/plants/t531-no-door.patch`): the road starts with no
//! `--allow`, and the test of its refusal fails. A session goes on across
//! the node's upgrade in place, as the node attaches its kept tunnel again
//! (T-679, `upgrade_support`).

mod cleanup;
#[path = "../../podssh-relay/tests/opentunnel_stand_in/mod.rs"]
mod opentunnel_stand_in;
mod ssh_harness;
mod upgrade_support;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use opentunnel_stand_in::{StandIn, DOMAIN};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-opentunnel-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// service and the stand-in proxy, and none of the settings of the machine
/// that runs the test.
fn command(home: &Path, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_DERP", "PODSSH_DERP_SERVER", "PODSSH_RELAY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    for name in ["SSL_CERT_FILE", "SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "http_proxy"] {
        cmd.env_remove(name);
    }
    let proxy = format!("http://127.0.0.1:{proxy}");
    cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
    cmd.env("PODSSH_OPENTUNNEL", format!("https://{DOMAIN}"));
    // The roads of the test alone: no transit relay, no Piping Server, no
    // record at n0's server of pkarr.
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
fn run(cmd: &mut Command) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// Kills the node when the test ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The lines of the node's stderr up to the first that holds `needle`.
fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => panic!("no line with {needle:?} from the node within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
}

/// The stand-in proxy: a CONNECT to the service's name goes to its API, one
/// to a name under it to its visitors' port, and each other is refused.
async fn proxy(api: u16, visitors: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let to = match (request.method.as_str(), target) {
                    ("CONNECT", Ok((host, 443))) if host == DOMAIN => api,
                    ("CONNECT", Ok((host, 443))) if host.ends_with(&format!(".{DOMAIN}")) => visitors,
                    _ => {
                        let words = "this proxy passes the names of the service alone";
                        let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                        return;
                    }
                };
                let Ok(mut far) = TcpStream::connect((Ipv4Addr::LOCALHOST, to)).await else { return };
                let _ = tcp.write_all(&podssh_ws::http::request::established()).await;
                if !rest.is_empty() && far.write_all(&rest).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut far).await;
            });
        }
    });
    port
}

/// The place of one test: its runtime, which serves the stand-in, the proxy
/// and the SSH server; the node's home and the client's.
struct Lab {
    runtime: tokio::runtime::Runtime,
    stand_in: Arc<StandIn>,
    proxy: u16,
    ca: String,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: PathBuf,
    client_key: String,
    known: String,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let stand_in = StandIn::new();
        let ca = home.join("ca.pem");
        std::fs::write(&ca, &stand_in.ca.pem).unwrap();
        let (cert, key) = stand_in.ca.pair(DOMAIN);
        let acceptor =
            podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[podssh_ws::tls_server::HTTP1])
                .expect("the API's TLS");
        let proxy_port = runtime.block_on(async {
            let api = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let visitors = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let (api_port, visitors_port) = (api.local_addr().unwrap().port(), visitors.local_addr().unwrap().port());
            let serving = stand_in.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = api.accept().await {
                    let (acceptor, serving) = (acceptor.clone(), serving.clone());
                    tokio::spawn(async move {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serving.serve_api(tls).await;
                        }
                    });
                }
            });
            let serving = stand_in.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = visitors.accept().await {
                    tokio::spawn(serving.clone().serve_visitor(tcp));
                }
            });
            proxy(api_port, visitors_port).await
        });
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text];
        let (rc, _, err) = run(&mut command(&home, proxy_port, &keygen));
        assert_eq!(rc, 0, "{err}");
        let port = runtime.block_on(ssh_harness::start(&host_key));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
        }
        let allow = node_home.join("allow");
        std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
        Lab {
            runtime,
            stand_in,
            proxy: proxy_port,
            ca: ca.to_string_lossy().into_owned(),
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// `podssh node lab TARGET` with `extra`, its lines, and its name once
    /// its bridge attached.
    fn node(&self, extra: &[&str], env: &[(&str, &str)]) -> (Node, mpsc::Receiver<String>, String) {
        let (key, allow) = (self.node_home.join("node.key"), self.allow.to_string_lossy().into_owned());
        let key = key.to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", self.target.as_str(), "--allow", allow.as_str(), "--key", key.as_str()];
        args.extend_from_slice(&["--ca-file", self.ca.as_str()]);
        args.extend_from_slice(extra);
        let mut cmd = command(&self.node_home, self.proxy, &args);
        cmd.envs(env.iter().copied());
        let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let node = Node(child);
        let seen = wait_for(&lines, "attached to OpenTunnel");
        let line = seen.iter().find(|l| l.contains(": name ")).unwrap_or_else(|| panic!("no name: {seen:#?}"));
        let name = line.split(": name ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        (node, lines, name)
    }

    /// `podssh ssh` from the client's home, with its key and known hosts.
    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--ca-file", &self.ca, "--client-key", &self.client_key]);
        args.extend_from_slice(words);
        command(&self.client_home, self.proxy, &args)
    }

    /// Let the client's key in, as the node's operator does.
    fn let_in(&self) {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", key.identity.public().fingerprint()).unwrap();
    }

    /// A pair of the client's under `lab` whose relay is a port of the
    /// loopback where nothing listens, so the pair's road fails at once.
    fn pair_down(&self) {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: closed };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        // The repository's fixture form of a token, which names no credential.
        let token = |kind: &str| format!("testonly{kind}{}", "0".repeat(56 - kind.len()));
        let body = serde_json::json!({
            "name": "p-0123456789abcdef0123456789abcdef",
            "node_token": token("node"),
            "connect_token": token("connect"),
            "stop_token": token("stop"),
            "expires": now + 72 * 3600 * 1000,
        });
        let pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), now).expect("a test pair");
        let cache = self.client_home.join("cache").join("podssh");
        podssh_relay::pair::store_in_first(&[cache], "lab", &pair).expect("the pair stored");
    }
}

#[test]
fn with_the_pair_s_road_down_the_race_gives_the_session_to_opentunnel_and_a_kept_name_falls_back() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, _lines, name) = lab.node(&["--opentunnel"], &[]);
    assert!(name.ends_with(&format!(".{DOMAIN}")) && name.split('.').count() == 4, "{name}");
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--opentunnel-name", &name, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the OpenTunnel road answered first"), "{err}");
    assert!(err.contains("the OpenTunnel name is kept in"), "{err}");
    assert!(lab.stand_in.opens.load(Ordering::SeqCst) >= 1, "a visitor came over the bridge");

    // No name now: the kept one, once each road before it failed (Q76).
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("when each road before it failed (a kept name, Q76)"), "{err}");

    // PODSSH_OPENTUNNEL=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_OPENTUNNEL", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("OpenTunnel"), "no OpenTunnel road with PODSSH_OPENTUNNEL=no: {err}");
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1, "one tunnel for the node");
    drop(lab.runtime);
}

/// A session over the OpenTunnel road goes on across the node's upgrade in
/// place (T-679): with the pair's road down, SIGUSR2 at a quarter of 16 MiB
/// down, and the node, the same process, becomes its binary again (the
/// test's own) with the session; it attaches its kept tunnel again, under
/// the same name, and the client resumes there, its bytes whole. The
/// service made one tunnel.
#[cfg(unix)]
#[test]
fn a_session_over_the_opentunnel_road_goes_on_across_the_node_s_upgrade() {
    const DOWN: u64 = 16 << 20;
    let lab = Lab::new("upgrade");
    lab.let_in();
    lab.pair_down();
    let (node, lines, name) = lab.node(&["--opentunnel"], &[]);
    let pid = node.0.id();
    let source = format!("source {DOWN}");
    let mut client = lab
        .ssh(&["--opentunnel-name", &name, "node://tester@lab", &source])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let came = upgrade_support::across(&mut client, DOWN, Duration::from_secs(180), || {
        upgrade_support::ask(pid);
        let went = wait_for(&lines, "sessions go to");
        assert!(went.last().unwrap().contains("1 of 1 sessions go to"), "{went:#?}");
        let took = wait_for(&lines, "sessions over from");
        assert!(took.last().unwrap().contains("took 1 of 1 sessions over"), "{took:#?}");
        let again = wait_for(&lines, "attached to OpenTunnel");
        assert!(again.iter().any(|l| l.contains(&format!("name {name}"))), "the same name: {again:#?}");
    });
    assert_eq!(came.code, Some(0), "{}", came.err);
    assert_eq!(came.total, DOWN, "{}", came.err);
    assert!(upgrade_support::runs(pid), "the node runs on in its own process");
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1, "one tunnel for the node, across its upgrade");
    drop(node);
    drop(lab.runtime);
}

#[test]
fn a_node_of_the_road_with_no_door_is_refused_before_it_makes_a_tunnel() {
    let lab = Lab::new("door");
    let mut cmd = command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--opentunnel"]);
    let (rc, out, err) = run(&mut cmd);
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("--opentunnel needs --allow FILE"), "{err}");
    assert!(err.contains("anyone may connect to a tunnel's name"), "{err}");
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 0, "no tunnel made");
    assert!(out.is_empty());
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_and_the_derp_road_off_serves_the_road_unasked_and_keeps_its_tunnel() {
    let lab = Lab::new("unasked");
    let (node, lines, name) = lab.node(&[], &[("PODSSH_DERP", "no")]);
    drop(lines);
    drop(node);
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1);
    // Started again: the same name, and no new CSR.
    let mut again = command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target]);
    let allow = lab.allow.to_string_lossy().into_owned();
    let key = lab.node_home.join("node.key").to_string_lossy().into_owned();
    again.args(["--allow", &allow, "--key", &key, "--ca-file", &lab.ca]).env("PODSSH_DERP", "no");
    let mut child = again.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let stderr = BufReader::new(child.stderr.take().unwrap());
    let _node = Node(child);
    let mut seen = Vec::new();
    for line in stderr.lines().map_while(Result::ok) {
        let done = line.contains("attached to OpenTunnel");
        seen.push(line);
        if done {
            break;
        }
    }
    let said = seen.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{seen:#?}"));
    assert!(said.contains("Q76") && said.contains("PODSSH_OPENTUNNEL=no"), "{said}");
    assert!(seen.iter().any(|l| l.contains(&format!("name {name}"))), "the same name: {seen:#?}");
    assert!(seen.iter().any(|l| l.contains("the tunnel kept in")), "{seen:#?}");
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1, "no second tunnel");
    assert_eq!(lab.stand_in.new_csrs.load(Ordering::SeqCst), 1, "no new CSR");
    drop(lab.runtime);
}
