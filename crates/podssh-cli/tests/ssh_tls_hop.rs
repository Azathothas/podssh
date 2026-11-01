//! `ssh+tls://` (T-372) against stunnel, software that podssh did not
//! write, in front of the test's SSH server: as the destination, as the hop
//! of `-J` before a plain server, and as a hop after a plain one, inside its
//! channel. podssh reaches stunnel with `--direct` through a stand-in HTTP
//! CONNECT proxy, which maps each name to the loopback, so that the names of
//! the certificate (`tls-hop.test`, `localhost`) are what podssh checks. A
//! certificate for another name is refused at the TLS step; a proxy that
//! waits for TLS and closes each other stream passes the hop of TLS and
//! fails a plain one. stunnel comes from `PODSSH_TEST_STUNNEL` (the gate
//! names it, so that a missing one fails), else `stunnel` on the path; with
//! neither, or no `openssl` for the certificates, the test says that it did
//! not run.
#![cfg(unix)]

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(60);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-tls-hop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// stunnel, as the gate names it or as the path finds it.
fn stunnel() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os("PODSSH_TEST_STUNNEL") {
        let path = PathBuf::from(named);
        assert!(path.is_file(), "PODSSH_TEST_STUNNEL names no file: {}", path.display());
        return Some(path);
    }
    ["stunnel", "stunnel4"].iter().find_map(|name| {
        let found = Command::new("sh").args(["-c", &format!("command -v {name}")]).output().ok()?;
        let path = String::from_utf8_lossy(&found.stdout).trim().to_string();
        (found.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
    })
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A CA, and a leaf of it for `tls-hop.test` and `localhost`: `ca.pem`,
/// `leaf.pem` and `leaf.key` in `dir`.
fn certificates(dir: &Path) -> bool {
    std::fs::write(dir.join("ext.cnf"), "subjectAltName=DNS:tls-hop.test,DNS:localhost\n").unwrap();
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
    let mut ca = vec!["req", "-x509"];
    ca.extend(ec);
    ca.extend(["-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=podssh test CA"]);
    let mut csr = vec!["req"];
    csr.extend(ec);
    csr.extend(["-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=tls-hop.test"]);
    let sign = [
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "leaf.pem",
        "-days",
        "2",
        "-extfile",
        "ext.cnf",
    ];
    openssl(dir, &ca) && openssl(dir, &csr) && openssl(dir, &sign)
}

/// A process that ends with the test.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// stunnel on `port`, TLS with the leaf, to the SSH server on `ssh`.
fn start_stunnel(program: &Path, dir: &Path, port: u16, ssh: u16) -> Running {
    let conf = dir.join("stunnel.conf");
    let text = format!(
        "foreground = yes\npid =\n[ssh]\naccept = 127.0.0.1:{port}\nconnect = 127.0.0.1:{ssh}\ncert = {}\nkey = {}\n",
        dir.join("leaf.pem").display(),
        dir.join("leaf.key").display()
    );
    std::fs::write(&conf, text).unwrap();
    let mut child = Command::new(program);
    child.arg(&conf).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let running = Running(child.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "stunnel did not listen on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    running
}

/// A CONNECT proxy on the loopback that maps each name to 127.0.0.1 and
/// keeps the names asked; with `tls_only`, a stream whose first byte is not
/// TLS's handshake is closed, as a proxy that waits for TLS on port 443 does.
async fn proxy(tls_only: bool) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let target = text.split_whitespace().nth(1).unwrap_or("").to_string();
                seen.lock().unwrap().push(target.clone());
                let port: u16 = target.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let Ok(mut upstream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else { return };
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                if tls_only {
                    let mut first = [0u8; 1];
                    if client.read_exact(&mut first).await.is_err() || first[0] != 0x16 {
                        // Closed, with the client's bytes unread.
                        return;
                    }
                    if upstream.write_all(&first).await.is_err() {
                        return;
                    }
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, asked)
}

struct Setup {
    dir: PathBuf,
    ssh: u16,
    stunnel_port: u16,
    _stunnel: Running,
    runtime: tokio::runtime::Runtime,
}

fn setup(name: &str) -> Option<Setup> {
    let Some(program) = stunnel() else {
        eprintln!("did not run: no stunnel on this host");
        return None;
    };
    let dir = scratch(name);
    if !certificates(&dir) {
        eprintln!("did not run: no openssl for the certificates");
        return None;
    }
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let ssh = runtime.block_on(ssh_harness::start(&key));
    let stunnel_port = free_port();
    let stunnel = start_stunnel(&program, &dir, stunnel_port, ssh);
    Some(Setup { dir, ssh, stunnel_port, _stunnel: stunnel, runtime })
}

impl Setup {
    /// `podssh ssh --direct` through the proxy on `proxy`, trusting the
    /// test's CA, with `args`, then `greet`.
    fn ssh(&self, proxy: u16, args: &[&str]) -> Output {
        let known = format!("UserKnownHostsFile={}", self.dir.join("known_hosts").display());
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["ssh", "--direct", "--ca-file"])
            .arg(self.dir.join("ca.pem"))
            .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known])
            .args(args)
            .arg("greet")
            .env("HOME", &self.dir)
            .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"))
            .env("PODSSH_SSH_CONFIG", "none")
            .env("PODSSH_CACHE_DIR", self.dir.join("cache"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in ["https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSH_AUTH_SOCK", "SSL_CERT_FILE"]
        {
            cmd.env_remove(name);
        }
        let mut child = cmd.spawn().unwrap();
        let deadline = Instant::now() + LIMIT;
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "podssh ssh did not end within {LIMIT:?}");
            std::thread::sleep(Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The destination, and a `-J` hop before a plain server, each inside TLS
/// that stunnel ends; the proxy saw only the names of the TLS.
#[test]
fn ssh_inside_tls_as_the_destination_and_as_the_first_hop() {
    let Some(s) = setup("first") else { return };
    let (proxy, asked) = s.runtime.block_on(proxy(false));
    let dest = format!("ssh+tls://podtest@tls-hop.test:{}", s.stunnel_port);
    let out = s.ssh(proxy, &[&dest]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    let hop = format!("ssh+tls://podtest@tls-hop.test:{}", s.stunnel_port);
    let plain = format!("podtest@127.0.0.1:{}", s.ssh);
    let out = s.ssh(proxy, &["-J", &hop, &plain]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked, vec![format!("tls-hop.test:{}", s.stunnel_port); 2], "{asked:?}");
}

/// A hop of TLS after a plain one: its TLS runs inside the channel of the
/// hop before it, which the server opens to stunnel.
#[test]
fn a_hop_of_tls_after_a_plain_one_runs_inside_its_channel() {
    let Some(s) = setup("second") else { return };
    let (proxy, asked) = s.runtime.block_on(proxy(false));
    let first = format!("podtest@plain.test:{}", s.ssh);
    let dest = format!("ssh+tls://podtest@localhost:{}", s.stunnel_port);
    let out = s.ssh(proxy, &["-J", &first, &dest]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    assert_eq!(asked.lock().unwrap().clone(), vec![format!("plain.test:{}", s.ssh)]);
}

/// A certificate for another name is refused at the TLS step, before SSH.
#[test]
fn a_certificate_for_another_name_is_refused_at_the_tls_step() {
    let Some(s) = setup("name") else { return };
    let (proxy, _) = s.runtime.block_on(proxy(false));
    let dest = format!("ssh+tls://podtest@other.test:{}", s.stunnel_port);
    let out = s.ssh(proxy, &[&dest]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("TLS") && err.contains("other.test"), "{err}");
    assert!(out.stdout.is_empty());
}

/// Through a proxy that waits for TLS and closes each other stream, the
/// hop of TLS passes and a plain one fails.
#[test]
fn a_proxy_that_waits_for_tls_passes_the_hop_of_tls_alone() {
    let Some(s) = setup("strict") else { return };
    let (proxy, _) = s.runtime.block_on(proxy(true));
    let dest = format!("ssh+tls://podtest@tls-hop.test:{}", s.stunnel_port);
    let out = s.ssh(proxy, &[&dest]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    let plain = format!("podtest@plain.test:{}", s.ssh);
    let out = s.ssh(proxy, &[&plain]);
    assert_eq!(out.status.code(), Some(255), "a plain hop passed a proxy that waits for TLS: {}", text(&out.stderr));
}

/// `doctor --hop ssh+tls://...`: its probes inside TLS, the banner, the
/// host key and a login, as for a plain hop.
#[test]
fn doctor_probes_a_hop_of_tls_inside_tls() {
    let Some(s) = setup("doctor") else { return };
    let (proxy, _) = s.runtime.block_on(proxy(true));
    let hop = format!("ssh+tls://podtest@tls-hop.test:{}", s.stunnel_port);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["doctor", "--hop", &hop, "--ca-file"])
        .arg(s.dir.join("ca.pem"))
        .env("HOME", &s.dir)
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}"))
        .env("PODSSH_CACHE_DIR", s.dir.join("cache"))
        .stdin(Stdio::null());
    for name in ["https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let report = text(&out.stdout);
    let line =
        |name: &str| report.lines().find(|l| l.split_whitespace().nth(1) == Some(name)).unwrap_or("").to_string();
    assert!(line("hop").starts_with("  ok") && line("hop").contains("an SSH server answered"), "{report}");
    assert!(report.contains("ssh+tls://tls-hop.test:"), "{report}");
    assert!(report.lines().any(|l| l.contains("hop key") && l.trim_start().starts_with("ok")), "{report}");
}
