//! `podssh doctor --hop` (T-371): a first hop of `-J` as `--direct` reaches
//! it. Against the harness's SSH server (russh's, not podssh's): the banner,
//! the host key and the methods that it offers to a key made for the check,
//! with no proxy; through a stand-in proxy that takes the CONNECT and then
//! sends nothing, as one that waits for TLS does: the line names it, and
//! the road that would carry such a hop. A hop that does not read is 64.

mod ssh_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The variables that would steer the dial away from the test's servers.
const STEERING: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "PODSSH_OFFLINE",
    "SSH_AUTH_SOCK",
];

/// A scratch directory, removed when the test ends, as it passes or fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-doctor-hop-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `podssh doctor ARGS` in `home`, with `set` and no steering variable.
fn doctor(home: &Scratch, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("doctor").args(args).env("HOME", &home.0).env("XDG_CONFIG_HOME", home.0.join("config"));
    cmd.env("XDG_CACHE_HOME", home.0.join("cache"));
    for name in STEERING {
        cmd.env_remove(name);
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// The line of `name` in a report: its status, then the name and the
/// column's padding, so that `hop` is not `hop key`.
fn line<'a>(out: &'a str, name: &str) -> &'a str {
    let named = |l: &&str| {
        let after_status = l.trim_start().split_once(char::is_whitespace).map(|(_, rest)| rest.trim_start());
        after_status.is_some_and(|rest| rest.strip_prefix(name).is_some_and(|tail| tail.starts_with("  ")))
    };
    out.lines().find(named).unwrap_or_else(|| panic!("no {name}: {out}"))
}

/// The harness's SSH server on the loopback, kept up by `runtime`.
fn server(home: &Scratch) -> (tokio::runtime::Runtime, u16) {
    let key = home.0.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, _) = runtime.block_on(ssh_harness::start_counting(&key));
    (runtime, port)
}

#[test]
fn a_hop_with_no_proxy_gives_its_banner_its_key_and_its_methods() {
    let home = Scratch::new("direct");
    let (_runtime, port) = server(&home);
    let hop = format!("tester@127.0.0.1:{port}");
    let (code, out, err) = doctor(&home, &["--hop", &hop], &[]);
    assert_eq!(code, 0, "{out}{err}");
    let reached = line(&out, "hop");
    assert!(reached.contains("ok") && reached.contains("with no proxy"), "{reached}");
    assert!(reached.contains("an SSH server answered with its banner"), "{reached}");
    assert!(reached.contains("loss 0 of 9"), "sampled as the other probes: {reached}");
    assert!(line(&out, "hop key").contains("presents the host key SHA256:"), "{out}");
    let login = line(&out, "hop login");
    assert!(login.contains("as tester: the server refused a key made for this check"), "{login}");
    assert!(!out.contains("relay"), "--hop asks about the hop alone: {out}");
}

/// A proxy that answers each CONNECT with 200 and then sends nothing, for
/// as long as the client stays: one that waits for a ClientHello.
fn silent_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                let _ = stream.read(&mut [0u8; 1024]);
            });
        }
    });
    port
}

#[test]
fn a_proxy_that_waits_for_tls_is_named_and_no_login_is_tried() {
    let home = Scratch::new("tls");
    let proxy = format!("http://127.0.0.1:{}", silent_proxy());
    let (code, out, err) = doctor(&home, &["--hop", "git@hop.example:443"], &[("HTTPS_PROXY", &proxy)]);
    assert_eq!(code, 1, "a hop that carries no SSH fails the run: {out}{err}");
    let reached = line(&out, "hop");
    assert!(reached.contains("FAIL") && reached.contains("hop.example:443 through 127.0.0.1:"), "{reached}");
    assert!(reached.contains("nothing came in 5 s: no SSH server answered"), "{reached}");
    assert!(reached.contains("waits for TLS"), "{reached}");
    assert!(!out.contains("hop key") && !out.contains("hop login"), "{out}");
}

#[test]
fn a_hop_that_does_not_read_is_a_usage_error_and_offline_asks_nothing() {
    let home = Scratch::new("usage");
    let (code, out, err) = doctor(&home, &["--hop", "user@"], &[]);
    assert_eq!(code, 64, "{out}{err}");
    assert!(err.contains("--hop") && out.is_empty(), "{err}");
    let (code, out, err) = doctor(&home, &["--hop", "git@github.com"], &[("PODSSH_OFFLINE", "1")]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(line(&out, "hop").contains("not attempted: PODSSH_OFFLINE is set"), "{out}");
}
