//! The direct road after the relay hosts (T-363), on this machine's
//! loopback. The built-in relay host and each host of its seed pool are
//! pinned to 127.0.0.1, whose port 443 takes no connection here, so each
//! relay host fails at once, as a relay that refuses; the test's SSH server
//! listens on another port. With no
//! `--direct`, `podssh ssh` logs in over the direct road and says that it
//! fell back; with `--direct` and the server's port closed, it fails and
//! does not fall back; with `--relay-host`, or with `PODSSH_DIRECT=no`, a
//! failing relay ends the run; when both fail, the lines name both roads and
//! their times. Through a proxy of the test that takes the CONNECT and sends
//! nothing, the fallback ends with the proxy named.

mod cleanup;
mod ssh_harness;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ssh_harness::GREETING;

const LIMIT: Duration = Duration::from_secs(60);
const FELL_BACK: &str = "podssh tries";

/// The built-in relay host and each of its seed pool, which a fresh cache
/// tries after it, pinned to the loopback, as `PODSSH_RELAY_ADDR` takes them.
fn pins() -> String {
    let seed = podssh_relay::pool::SEED.iter().copied();
    let hosts = std::iter::once(podssh_relay::relay::DEFAULT_RELAY_HOST).chain(seed);
    hosts.map(|host| format!("{host}=127.0.0.1")).collect::<Vec<_>>().join(",")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-direct-fallback-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// Whether the relay's pin reaches nothing: a host where something takes
/// 127.0.0.1:443 cannot run these tests, and says so.
fn port_443_is_closed() -> bool {
    let open = TcpStream::connect_timeout(&"127.0.0.1:443".parse().unwrap(), Duration::from_secs(1)).is_ok();
    if open {
        eprintln!("did not run: something takes 127.0.0.1:443 here, where the relay's pin must find nothing");
    }
    !open
}

/// A port of the loopback where nothing listens.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// `podssh ssh ARGS` with HOME and the cache under `home`, the relay pinned,
/// and none of the settings of the machine that runs the test: its code,
/// stdout, stderr, and how long it took.
fn ssh(home: &Path, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String, Duration) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    cmd.args(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known]);
    cmd.args(args);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("PODSSH_RELAY_ADDR", pins());
    // The direct road alone (T-363): the public forwarders that follow it
    // (T-370) are other products' live services, which no test asks.
    cmd.env("PODSSH_FORWARDER_FALLBACK", "no");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_RELAY",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_DIRECT",
        "PODSSH_MPTCP",
        "SSL_CERT_FILE",
        "SSH_AUTH_SOCK",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd.envs(set.iter().copied());
    let started = Instant::now();
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh ssh {args:?} still ran after {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr), took)
}

/// The test's SSH server, in a runtime that the caller keeps.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let host_key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let port = runtime.block_on(ssh_harness::start(&host_key));
    (runtime, port)
}

#[test]
fn with_no_road_named_a_failing_relay_falls_back_to_the_direct_road() {
    if !port_443_is_closed() {
        return;
    }
    let home = scratch("falls-back");
    let (runtime, port) = server(&home);
    let port = port.to_string();
    let (rc, out, err, _) = ssh(&home, &["-v", "-p", &port, "tester@127.0.0.1", "greet"], &[]);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the direct road");
    let said = err.lines().find(|l| l.contains(FELL_BACK)).unwrap_or_else(|| panic!("no fallback line: {err}"));
    assert!(said.contains(&format!("podssh tries 127.0.0.1:{port} directly")), "{said}");
    assert!(err.contains("the direct road carried the session"), "-v names the road: {err}");
    drop(runtime);
}

#[test]
fn direct_alone_does_not_fall_back_and_a_named_relay_or_podssh_direct_no_ends_the_run() {
    if !port_443_is_closed() {
        return;
    }
    let home = scratch("alone");
    let (runtime, port) = server(&home);
    let (closed, port) = (closed_port().to_string(), port.to_string());
    // --direct with the server's port closed: the direct road alone.
    let (rc, _, err, _) = ssh(&home, &["--direct", "-p", &closed, "tester@127.0.0.1", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(!err.contains(FELL_BACK), "--direct fell back: {err}");
    // A relay that the user names is the relay alone, though the server is up.
    let named = format!("127.0.0.1:{}", closed_port());
    let (rc, _, err, _) = ssh(&home, &["--relay-host", &named, "-p", &port, "tester@127.0.0.1", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(!err.contains(FELL_BACK), "a named relay fell back: {err}");
    // PODSSH_DIRECT=no, the built-in relay: no fallback either.
    let (rc, _, err, _) = ssh(&home, &["-p", &port, "tester@127.0.0.1", "true"], &[("PODSSH_DIRECT", "no")]);
    assert_eq!(rc, 255, "{err}");
    assert!(!err.contains(FELL_BACK), "PODSSH_DIRECT=no fell back: {err}");
    // A word that is no yes or no is a configuration error, before anything.
    let (rc, _, err, _) = ssh(&home, &["-p", &port, "tester@127.0.0.1", "true"], &[("PODSSH_DIRECT", "maybe")]);
    assert_eq!(rc, 78, "{err}");
    drop(runtime);
}

#[test]
fn when_both_roads_fail_the_lines_name_both_and_their_times() {
    if !port_443_is_closed() {
        return;
    }
    let home = scratch("both");
    let closed = closed_port().to_string();
    let (rc, _, err, _) = ssh(&home, &["-p", &closed, "tester@127.0.0.1", "true"], &[]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains(FELL_BACK), "{err}");
    let both = err.lines().find(|l| l.contains("the relay road failed after")).unwrap_or_else(|| panic!("{err}"));
    assert!(both.contains(&format!("the direct road to 127.0.0.1:{closed} after")), "{both}");
    assert!(both.matches(" s").count() >= 2, "each road's time: {both}");
}

/// A proxy on the loopback that answers each CONNECT with 200, then sends
/// nothing for 30 s, as a proxy that expects TLS. Its port.
fn silent_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = std::io::Write::write_all(&mut conn, b"HTTP/1.1 200 Connection Established\r\n\r\n");
                std::thread::sleep(Duration::from_secs(30));
            });
        }
    });
    port
}

#[test]
fn through_a_proxy_that_carries_no_ssh_the_fallback_names_the_proxy() {
    if !port_443_is_closed() {
        return;
    }
    let home = scratch("proxy");
    let proxy = format!("http://127.0.0.1:{}", silent_proxy());
    // The relay host, pinned to the loopback, goes with no proxy; the name of
    // the target goes through it.
    let (rc, _, err, took) = ssh(&home, &["tester@ssh.example", "true"], &[("https_proxy", &proxy)]);
    assert_eq!(rc, 255, "{err}");
    let said = err.lines().find(|l| l.contains(FELL_BACK)).unwrap_or_else(|| panic!("{err}"));
    assert!(said.contains("through the proxy 127.0.0.1:"), "{said}");
    let both = err.lines().find(|l| l.contains("the relay road failed after")).unwrap_or_else(|| panic!("{err}"));
    assert!(both.contains("took the CONNECT") && both.contains("nothing came in 10 s"), "{both}");
    assert!(took < Duration::from_secs(40), "{took:?}");
}
