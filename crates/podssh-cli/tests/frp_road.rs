//! The frp road of the command line from end to end (T-498), on this
//! machine's loopback: a stand-in of frps written in the test
//! (`frp_support`), behind TLS of the test's own CA on frp's TCP with TLS; a
//! stand-in proxy of the node's and the client's that takes a CONNECT to
//! frps's name alone; an SSH server for the node's TARGET; `podssh node lab
//! TARGET --frp FILE --allow FILE`, and `podssh ssh node://tester@lab greet`
//! with PODSSH_FRP and the pair's road down: the race goes to frps. A
//! client with another secret is refused in frps's words; a node with
//! another token ends with frps's words (69); a node of the road that would
//! open its door, or whose file does not read, is refused before it
//! connects, and no line says a secret. frps and frpc of frp's own release
//! run in `scripts/interop-frp.sh`.

mod cleanup;
mod frp_support;
#[allow(dead_code)]
#[path = "../../podssh-relay/tests/opentunnel_stand_in/keys.rs"]
mod keys;
mod ssh_harness;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use frp_support::{Frps, SECRET, TOKEN};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);
/// frps's name, which the stand-in proxy alone resolves.
const FRPS: &str = "frps.test";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-frp-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME under `home`, the stand-in proxy, and none of
/// the settings of the machine that runs the test.
fn command(home: &Path, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_DERP", "PODSSH_DERP_SERVER", "PODSSH_RELAY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    for name in ["SSL_CERT_FILE", "SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "PODSSH_FRP"] {
        cmd.env_remove(name);
    }
    let proxy = format!("http://127.0.0.1:{proxy}");
    cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
    // The roads of the test alone.
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_DERP", "no");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

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

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

/// The stand-in proxy: a CONNECT to frps's name goes to the stand-in, and
/// each other one is refused.
async fn proxy(frps: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                if !matches!((request.method.as_str(), target), ("CONNECT", Ok((host, 7000))) if host == FRPS) {
                    let words = "this proxy passes frps alone";
                    let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                    return;
                }
                let Ok(mut far) = TcpStream::connect((Ipv4Addr::LOCALHOST, frps)).await else { return };
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

/// Write a private file of the road.
fn road_file(path: &Path, token: &str, secret: &str) -> String {
    let text = format!("# the test's frps\nserver frp://{FRPS}\ntoken {token}\nsecret {secret}\n");
    private(path, &text);
    path.to_string_lossy().into_owned()
}

fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct Lab {
    runtime: tokio::runtime::Runtime,
    frps: Arc<Frps>,
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
        let ca = keys::Ca::new();
        let ca_path = home.join("ca.pem");
        std::fs::write(&ca_path, &ca.pem).unwrap();
        let (cert, key) = ca.pair(FRPS);
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[]).expect("frps's TLS");
        let frps = Arc::new(Frps::default());
        let proxy_port = runtime.block_on(async {
            let port = frps.listen(acceptor).await;
            proxy(port).await
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
            frps,
            proxy: proxy_port,
            ca: ca_path.to_string_lossy().into_owned(),
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    fn node_args(&self, road: &str) -> Vec<String> {
        let key = self.node_home.join("node.key").to_string_lossy().into_owned();
        let allow = self.allow.to_string_lossy().into_owned();
        ["node", "lab", &self.target, "--frp", road, "--allow", &allow, "--key", &key, "--ca-file", &self.ca]
            .map(String::from)
            .to_vec()
    }

    /// `podssh node lab TARGET --frp FILE`, once frps took its service.
    fn node(&self) -> (Node, mpsc::Receiver<String>) {
        let road = road_file(&self.node_home.join("frp"), TOKEN, SECRET);
        let args = self.node_args(&road);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cmd = command(&self.node_home, self.proxy, &args);
        let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let node = Node(child);
        let seen = wait_for(&lines, "waiting for visitors at");
        for line in &seen {
            assert!(!line.contains(TOKEN) && !line.contains(SECRET), "a line says a secret: {line}");
        }
        (node, lines)
    }

    /// `podssh ssh` from the client's home, with PODSSH_FRP naming `road`.
    fn ssh(&self, road: &str, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--ca-file", &self.ca, "--client-key", &self.client_key]);
        args.extend_from_slice(words);
        let mut cmd = command(&self.client_home, self.proxy, &args);
        cmd.env("PODSSH_FRP", road);
        cmd
    }

    fn let_in(&self) {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", key.identity.public().fingerprint()).unwrap();
    }

    /// A pair of the client's under `lab` whose relay is a closed port of
    /// the loopback, so the pair's road fails at once.
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
fn with_the_pair_s_road_down_the_race_gives_the_session_to_frps_and_another_secret_is_refused() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, _lines) = lab.node();
    let road = road_file(&lab.client_home.join("frp"), TOKEN, SECRET);
    let (rc, out, err) = run(&mut lab.ssh(&road, &["-v", "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the frp road answered first"), "{err}");
    assert!(err.contains("the frp road when each road before it failed (the user's frps, T-498)"), "{err}");
    assert!(lab.frps.visits.load(Ordering::SeqCst) >= 1, "a visitor came through frps");
    assert!(!err.contains(TOKEN) && !err.contains(SECRET), "{err}");

    // Another secret: frps refuses the visit, in its words.
    let wrong = road_file(&lab.client_home.join("frp-wrong"), TOKEN, "another-secret-of-the-test");
    let (rc, out, err) = run(&mut lab.ssh(&wrong, &["-v", "node://tester@lab", "greet"]));
    assert_ne!(rc, 0, "stdout {out:?}, stderr {err}");
    assert!(err.contains("frps refused the visit: \"visitor connection of [lab] auth failed\""), "{err}");
    assert!(!err.contains("another-secret-of-the-test"), "{err}");
    drop(lab.runtime);
}

#[test]
fn a_node_with_another_token_ends_in_frps_s_words() {
    let lab = Lab::new("token");
    let road = road_file(&lab.node_home.join("frp"), "another-token-of-the-test", SECRET);
    let args = lab.node_args(&road);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &args));
    assert_eq!(rc, 69, "stdout {out:?}, stderr {err}");
    assert!(err.contains("token in login doesn't match token from configuration"), "{err}");
    assert!(!err.contains("another-token-of-the-test"), "{err}");
    assert!(out.is_empty());
    drop(lab.runtime);
}

#[test]
fn a_node_of_the_road_that_would_open_its_door_or_whose_file_does_not_read_is_refused_first() {
    let lab = Lab::new("refused");
    let road = road_file(&lab.node_home.join("frp"), TOKEN, SECRET);
    let mut args = lab.node_args(&road);
    args.push("--no-e2e".into());
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &words));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--no-e2e cannot go with --frp"), "{err}");

    let bad = lab.node_home.join("frp-bad");
    private(&bad, &format!("server frp://{FRPS}\npassword {SECRET}\n"));
    let args = lab.node_args(&bad.to_string_lossy());
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &words));
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("line 2"), "{err}");
    assert!(!err.contains(SECRET), "the line's text is never said: {err}");
    assert_eq!(lab.frps.logins.load(Ordering::SeqCst), 0, "nothing logged in");
    drop(lab.runtime);
}
