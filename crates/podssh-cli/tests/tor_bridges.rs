//! `podssh ssh tor://` through a bridge of a Tor network of C tor (T-385),
//! software that podssh did not write: chutney's network with a bridge
//! whose transports are Tor's own meek-server 0.38.0 and WebTunnel server
//! 0.0.7, run by the bridge's tor (`scripts/tor-net-bridges.sh` starts it,
//! and writes the file of the bridge lines that `PODSSH_TEST_TOR_BRIDGES`
//! names, beside the network's `arti.toml`). For each transport, a login
//! with that bridge alone in `PODSSH_TOR_BRIDGES`: Arti bootstraps through
//! it, an exit reaches the test's SSH server, and the stand-in proxy of
//! `HTTPS_PROXY` is asked for the transport's server alone, never a relay,
//! as the bridge is the only first hop. `podssh doctor --full` names the
//! transport. With no network the test says so and passes.
#![cfg(feature = "tor")]

mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const BRIDGES_ENV: &str = "PODSSH_TEST_TOR_BRIDGES";
const LIMIT: Duration = Duration::from_secs(240);

/// A proxy of HTTP CONNECT on the loopback that keeps the target of each
/// CONNECT, and carries each one, or only those whose target is `only`
/// (403 for the others).
async fn proxy(only: Option<String>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let (seen, only) = (seen.clone(), only.clone());
            tokio::spawn(async move {
                let mut client = BufReader::new(client);
                let mut line = String::new();
                if client.read_line(&mut line).await.is_err() {
                    return;
                }
                let target = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                loop {
                    let mut header = String::new();
                    match client.read_line(&mut header).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) if header == "\r\n" => break,
                        Ok(_) => {}
                    }
                }
                seen.lock().unwrap().push(target.clone());
                if only.as_ref().is_some_and(|only| target != *only) {
                    let _ = client.get_mut().write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                    return;
                }
                let Ok(mut far) = TcpStream::connect(&target).await else {
                    let _ = client.get_mut().write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let mut client = client.into_inner();
                if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut far).await;
                }
            });
        }
    });
    (port, asked)
}

/// Run `cmd` to its end within the limit: its code, stdout and stderr.
fn ran(mut cmd: Command) -> (Option<i32>, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code(), text(&out.stdout), text(&out.stderr))
}

/// The bridge line of `transport` in the file of the network, the file of
/// that line alone in `home`, the network's `arti.toml`, and the address
/// and port of the transport's server (its `url=`).
fn bridge(file: &Path, transport: &str, home: &Path) -> (PathBuf, PathBuf, String) {
    let lines = std::fs::read_to_string(file).unwrap();
    let line = lines
        .lines()
        .find(|l| l.split_whitespace().next() == Some(transport))
        .unwrap_or_else(|| panic!("no {transport} line in {}", file.display()));
    let server = line
        .split_whitespace()
        .find_map(|w| w.strip_prefix("url=http://"))
        .and_then(|rest| rest.split('/').next())
        .expect("the line's url= is http://ADDRESS:PORT/...")
        .to_string();
    let one = home.join("bridges");
    std::fs::write(&one, format!("# the {transport} bridge of the test's network\nBridge {line}\n")).unwrap();
    (one, file.with_file_name("arti.toml"), server)
}

fn podssh(home: &Path, bridges: &Path, network: &Path, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .env("HOME", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("PODSSH_TOR_NETWORK", network)
        .env("PODSSH_TOR_BRIDGES", bridges)
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"));
    for name in ["https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSH_AUTH_SOCK", "SSH_ASKPASS"] {
        cmd.env_remove(name);
    }
    cmd
}

/// A login through the bridge of `transport` alone: the command's output
/// comes back, and the proxy was asked for the transport's server alone
/// (nothing, where the network is on the loopback, which podssh sends
/// through no proxy).
fn login_through(transport: &str) {
    let Some(file) = std::env::var_os(BRIDGES_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{BRIDGES_ENV} is not set: no Tor network with a bridge to test (scripts/tor-net-bridges.sh)");
        return;
    };
    let home = std::env::temp_dir().join(format!("podssh-tor-bridges-{}-{transport}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let (bridges, network, server) = bridge(Path::new(&file), transport, &home);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (proxy_port, asked) = runtime.block_on(proxy(None));
    let key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let ssh_port = runtime.block_on(ssh_harness::start(&key));
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let destination = format!("tor://u@127.0.0.1:{ssh_port}");
    let args = ["ssh", "-o", &known, "-o", "StrictHostKeyChecking=accept-new", &destination, "greet"];
    let (code, out, err) = ran(podssh(&home, &bridges, &network, proxy_port, &args));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains(&format!("1 bridge over {transport}")), "the bridge is not said: {err}");
    let asked = asked.lock().unwrap().clone();
    if server.starts_with("127.") {
        assert!(asked.is_empty(), "a loopback server went through the proxy: {asked:?}");
    } else {
        assert!(!asked.is_empty(), "the transport's server was not asked of the proxy: {err}");
        assert!(asked.iter().all(|t| *t == server), "a first hop other than the bridge's transport: {asked:?}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_login_through_a_meek_lite_bridge() {
    login_through("meek_lite");
}

#[test]
fn a_login_through_a_webtunnel_bridge() {
    login_through("webtunnel");
}

/// `podssh doctor --full` bootstraps through the meek_lite bridge, and its
/// line tor names the transport; the stand-in proxy carries the transport's
/// server alone, and the relay and the DERP servers are closed ports of the
/// loopback.
#[test]
fn doctor_full_names_the_bridge_s_transport() {
    let Some(file) = std::env::var_os(BRIDGES_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{BRIDGES_ENV} is not set: no Tor network with a bridge to test (scripts/tor-net-bridges.sh)");
        return;
    };
    let home = std::env::temp_dir().join(format!("podssh-tor-bridges-doctor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let (bridges, network, server) = bridge(Path::new(&file), "meek_lite", &home);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (proxy_port, _) = runtime.block_on(proxy(Some(server)));
    let args = ["doctor", "--full", "--relay-host", "127.0.0.1:9"];
    let mut cmd = podssh(&home, &bridges, &network, proxy_port, &args);
    cmd.env("PODSSH_DERP_SERVER", "127.0.0.1:9");
    let (_, out, err) = ran(cmd);
    let line =
        out.lines().find(|l| l.contains("Arti bootstrapped in")).unwrap_or_else(|| panic!("no line tor: {out}{err}"));
    eprintln!("{line}");
    assert!(line.contains(" ok ") && line.contains("1 bridge over meek_lite, named in"), "{line}");
    let _ = std::fs::remove_dir_all(&home);
}
