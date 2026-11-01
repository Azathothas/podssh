//! `podssh ssh tor://` against a Tor network of C tor on the loopback
//! (T-353), software that podssh did not write: chutney's network `basic`,
//! whose arti-client configuration `PODSSH_TEST_TOR_NETWORK` names
//! (`scripts/tor-net.sh` starts it), given to podssh as
//! `PODSSH_TOR_NETWORK`. An exit reaches the test's SSH server, and the
//! login runs a command there. Each first hop goes through a stand-in proxy
//! of `HTTPS_PROXY`, but where the relays listen on the loopback, which
//! podssh never sends through a proxy. With no network the test says so
//! and passes.
#![cfg(feature = "tor")]

mod ssh_harness;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const NETWORK_ENV: &str = "PODSSH_TEST_TOR_NETWORK";
const LIMIT: Duration = Duration::from_secs(180);

/// A proxy of HTTP CONNECT on the loopback that keeps the target of each
/// CONNECT, and carries each one, or only those whose target starts with
/// `only` (403 for the others).
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
                if only.as_ref().is_some_and(|only| !target.starts_with(only.as_str())) {
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

fn podssh(home: &Path, network: &std::ffi::OsStr, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args)
        .env("HOME", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("PODSSH_TOR_NETWORK", network)
        // chutney's relays listen on ports from 5000 up.
        .env("PODSSH_TOR_PORTS", "any")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"));
    for name in ["https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSH_AUTH_SOCK", "SSH_ASKPASS"] {
        cmd.env_remove(name);
    }
    cmd
}

/// A login through the private network: the command's output comes back,
/// each first hop went through the proxy by its address (none where the
/// relays are on the loopback), and the server was reached through an
/// exit, never through the proxy.
#[test]
fn a_login_through_a_private_tor_network() {
    let Some(network) = std::env::var_os(NETWORK_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{NETWORK_ENV} is not set: no private Tor network, nothing to test (scripts/tor-net.sh)");
        return;
    };
    let home = std::env::temp_dir().join(format!("podssh-tor-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
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
    let (code, out, err) = ran(podssh(&home, &network, proxy_port, &args));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains("in the network of"), "the network's file is not said: {err}");
    let asked = asked.lock().unwrap().clone();
    // chutney names each relay by the one address that the network listens on.
    let on_loopback = std::fs::read_to_string(&network).unwrap().contains("\"127.0.0.1:");
    if on_loopback {
        assert!(asked.is_empty(), "a loopback relay went through the proxy: {asked:?}");
    } else {
        assert!(!asked.is_empty(), "no first hop went through the proxy: {err}");
        let literal = |t: &String| t.parse::<std::net::SocketAddr>().is_ok();
        assert!(asked.iter().all(literal), "a relay asked by a name: {asked:?}");
    }
    let server = format!("127.0.0.1:{ssh_port}");
    assert!(!asked.contains(&server), "the server was reached through the proxy, not Tor: {asked:?}");
    let known_hosts = std::fs::read_to_string(home.join("known_hosts")).unwrap();
    assert!(known_hosts.contains("tor://127.0.0.1"), "the host key is not kept under tor://: {known_hosts}");
    let _ = std::fs::remove_dir_all(&home);
}

/// `podssh doctor --full`: its line `tor` says that Arti bootstrapped, and
/// in how long. The stand-in proxy carries the private network's relays
/// alone, the relay and the DERP servers are ports of the loopback where
/// nothing listens: nothing else of doctor's leaves this host.
#[test]
fn doctor_full_says_that_tor_bootstraps() {
    let Some(network) = std::env::var_os(NETWORK_ENV).filter(|v| !v.is_empty()) else {
        eprintln!("{NETWORK_ENV} is not set: no private Tor network, nothing to test (scripts/tor-net.sh)");
        return;
    };
    let text = std::fs::read_to_string(&network).unwrap();
    // chutney names each relay by the one address that the network listens on.
    let address = text
        .split('"')
        .find_map(|word| word.parse::<std::net::SocketAddr>().ok())
        .map(|at| format!("{}:", at.ip()))
        .expect("no relay's address in the network's configuration");
    let home = std::env::temp_dir().join(format!("podssh-tor-doctor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (proxy_port, asked) = runtime.block_on(proxy(Some(address.clone())));
    let mut cmd = podssh(&home, &network, proxy_port, &["doctor", "--full", "--relay-host", "127.0.0.1:9"]);
    cmd.env("PODSSH_DERP_SERVER", "127.0.0.1:9");
    let (_, out, err) = ran(cmd);
    let line =
        out.lines().find(|l| l.contains("Arti bootstrapped in")).unwrap_or_else(|| panic!("no line tor: {out}{err}"));
    eprintln!("{line}");
    assert!(line.contains(" ok "), "{line}");
    let network_shown = network.to_string_lossy().into_owned();
    assert!(line.contains("in the network of") && line.contains(&network_shown), "{line}");
    let asked = asked.lock().unwrap().clone();
    let through = asked.iter().any(|t| t.starts_with(&address));
    // podssh asks a proxy for no loopback address.
    assert_eq!(through, !address.starts_with("127."), "the first hops and the proxy: {asked:?}");
    let _ = std::fs::remove_dir_all(&home);
}
