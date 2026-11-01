//! The world of `tests/shadowsocks_cli.rs` (T-373): `ssserver` and `sslocal`
//! of shadowsocks-rust as the gate or the path names them, the test's SSH
//! server, a stand-in subscription behind the proxy of `cloud_support`, a
//! CONNECT proxy that maps each name to the loopback (or takes each byte
//! and carries none), and the run of `podssh` with its stdin, within a
//! limit.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::shadowsocks::{self, Decoder, Encoder, Method};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cloud_support::{self, scratch, Handler, Proxy, Scratch, Stream};

pub const MIB: usize = 1 << 20;
/// A run waits up to 10 s for a silent server, and a list's fetch more.
const LIMIT: Duration = Duration::from_secs(120);

/// The program of `var`, else `name` on the path; `None`, said, with
/// neither.
pub fn program(var: &str, name: &str) -> Option<PathBuf> {
    if let Some(named) = std::env::var_os(var) {
        let path = PathBuf::from(named);
        assert!(path.is_file(), "{var} names no file: {}", path.display());
        return Some(path);
    }
    let found = Command::new("sh").args(["-c", &format!("command -v {name}")]).output().ok();
    let path = found.filter(|f| f.status.success()).map(|f| String::from_utf8_lossy(&f.stdout).trim().to_string());
    match path.filter(|p| !p.is_empty()) {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!("did not run: no {name} of shadowsocks-rust on this host, and {var} names none");
            None
        }
    }
}

/// A process that ends with the test.
pub struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// `ssserver` on the loopback with `method` and `password`, from a file of
/// its configuration: the process and its port.
pub fn start_server(program: &Path, dir: &Path, method: &str, password: &str) -> (Running, u16) {
    let port = free_port();
    let conf = dir.join(format!("ssserver-{port}.json"));
    let text = serde_json::json!({"server": "127.0.0.1", "server_port": port, "password": password, "method": method});
    std::fs::write(&conf, text.to_string()).unwrap();
    let mut child = Command::new(program);
    child.arg("-c").arg(&conf).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let running = Running(child.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ssserver did not listen on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    (running, port)
}

/// What the stand-in subscription serves, and what it was asked.
#[derive(Debug, Clone, Default)]
pub struct Served {
    pub body: Vec<u8>,
    pub asked: usize,
    pub paths: Vec<String>,
}

/// The test's SSH server, the proxy with the stand-in subscription behind
/// it, and the runtime that they run on, dropped last.
pub struct World {
    pub dir: Scratch,
    pub sshd: u16,
    pub proxy: Proxy,
    served: Arc<Mutex<Served>>,
    pub runtime: tokio::runtime::Runtime,
}

impl World {
    pub fn new(name: &str) -> World {
        let dir = scratch(&format!("shadowsocks-{name}"));
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        let key = dir.join("host_key");
        let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(made.success());
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let sshd = runtime.block_on(crate::ssh_harness::start(&key));
        let served = Arc::new(Mutex::new(Served::default()));
        let proxy = runtime.block_on(Proxy::start(&dir, handler(served.clone())));
        World { dir, sshd, proxy, served, runtime }
    }

    /// What the subscription serves from now on.
    pub fn serve(&self, body: Vec<u8>) {
        self.served.lock().unwrap().body = body;
    }

    pub fn served(&self) -> Served {
        self.served.lock().unwrap().clone()
    }

    /// `podssh ssh` to the test's server with `road`, running `remote`,
    /// through the world's proxy, with no other road of the environment, no
    /// settings file and a cache of its own.
    pub fn ssh(&self, road: &[&str], remote: &str) -> Command {
        let known = format!("UserKnownHostsFile={}", self.dir.join("known_hosts").display());
        let (ca, port) = (self.proxy.ca_file.display().to_string(), self.sshd.to_string());
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"];
        args.extend(["-o", known.as_str(), "--ca-file", ca.as_str(), "-p", port.as_str()]);
        args.extend_from_slice(road);
        args.extend(["u@127.0.0.1", remote]);
        let mut cmd = cloud_support::command(&self.dir, &args, Some(&self.proxy), &[]);
        let roads = ["PODSSH_FORWARDER", "PODSSH_FORWARDER_FALLBACK", "PODSSH_RELAY", "PODSSH_SESSION_LOG"];
        for name in roads.into_iter().chain(["SSH_AUTH_SOCK", "PODSSH_RELAY_FAILOVER", "PODSSH_RELAY_ADDR"]) {
            cmd.env_remove(name);
        }
        cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_CACHE_DIR", self.dir.join("cache"));
        cmd.env("TMPDIR", self.dir.join("tmp"));
        cmd
    }
}

/// The stand-in subscription: each request gets the body of the moment.
fn handler(served: Arc<Mutex<Served>>) -> Handler {
    Arc::new(move |_host: String, stream: Stream| {
        let served = served.clone();
        Box::pin(async move { serve_list(served, stream).await })
    })
}

async fn serve_list(served: Arc<Mutex<Served>>, mut stream: Stream) {
    let Ok(head) = cloud_support::read_head(&mut stream).await else { return };
    let path = head.split_whitespace().nth(1).unwrap_or_default().to_string();
    let body = {
        let mut served = served.lock().unwrap();
        served.asked += 1;
        served.paths.push(path);
        served.body.clone()
    };
    let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.shutdown().await;
}

/// A CONNECT proxy on the loopback that maps each name to 127.0.0.1 and
/// keeps each target asked; with `hold`, it takes each byte after its 200
/// and carries none, as a proxy that waits for TLS does.
pub async fn mapping_proxy(hold: bool) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(head) = cloud_support::read_head(&mut client).await else { return };
                let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
                seen.lock().unwrap().push(target.clone());
                let port: u16 = target.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                if hold {
                    let mut sink = [0u8; 4096];
                    while client.read(&mut sink).await.unwrap_or(0) > 0 {}
                    return;
                }
                let Ok(mut upstream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, asked)
}

/// What a stand-in server heard from `sslocal`, and what its client heard
/// back.
pub struct Heard {
    pub target: (String, u16),
    pub first: Vec<u8>,
    pub answer: Vec<u8>,
}

/// `sslocal` with `method` in front of a server of podssh's codec: a SOCKS5
/// client asks it for `target.test:2222` and says hello; the server opens
/// what `sslocal` sent, and answers with podssh's encoder.
pub async fn through_sslocal(program: &Path, dir: &Path, method: &str) -> Heard {
    let password = format!("sslocal-{method}");
    let parsed = Method::parse(method).unwrap();
    let master = shadowsocks::master_key(password.as_bytes(), parsed.key_len());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let local = free_port();
    let conf = dir.join(format!("sslocal-{local}.json"));
    let text = serde_json::json!({"server": "127.0.0.1", "server_port": server_port, "password": password,
        "method": method, "local_address": "127.0.0.1", "local_port": local});
    std::fs::write(&conf, text.to_string()).unwrap();
    let mut child = Command::new(program);
    child.arg("-c").arg(&conf).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let _sslocal = Running(child.spawn().unwrap());
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut decoder = Decoder::new(parsed, &master);
        let (mut plain, mut buf) = (Vec::new(), vec![0u8; 65536]);
        let (host, port, used) = loop {
            if let Some((host, port, used)) = shadowsocks::parse_address(&plain) {
                if plain.len() >= used + 18 {
                    break (host, port, used);
                }
            }
            let n = tcp.read(&mut buf).await.unwrap();
            assert!(n > 0, "sslocal closed before its first bytes came whole");
            decoder.feed(&buf[..n]);
            while let Some(chunk) = decoder.chunk().expect("sslocal's chunks open") {
                plain.extend_from_slice(&chunk);
            }
        };
        let mut out = Vec::new();
        Encoder::new(parsed, &master).unwrap().seal(b"hello back", &mut out).unwrap();
        tcp.write_all(&out).await.unwrap();
        // Open until the client heard it.
        let _ = tcp.read(&mut buf).await;
        ((host, port), plain[used..].to_vec())
    });
    let client = async {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut socks = loop {
            match tokio::net::TcpStream::connect(("127.0.0.1", local)).await {
                Ok(socks) => break socks,
                Err(e) => assert!(Instant::now() < deadline, "sslocal did not listen on {local}: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        socks.write_all(&[5, 1, 0]).await.unwrap();
        let mut chosen = [0u8; 2];
        socks.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, 0], "no authentication");
        let mut connect = vec![5, 1, 0, 3, 11];
        connect.extend_from_slice(b"target.test");
        connect.extend_from_slice(&2222u16.to_be_bytes());
        socks.write_all(&connect).await.unwrap();
        let mut reply = [0u8; 4];
        socks.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "sslocal took the CONNECT");
        let skip = match reply[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            _ => usize::from(socks.read_u8().await.unwrap()) + 2,
        };
        let mut bound = vec![0u8; skip];
        socks.read_exact(&mut bound).await.unwrap();
        socks.write_all(b"hello from sslocal").await.unwrap();
        let mut answer = vec![0u8; 10];
        socks.read_exact(&mut answer).await.unwrap();
        answer
    };
    let answer = tokio::time::timeout(Duration::from_secs(30), client).await.expect("sslocal's round within 30 s");
    let ended = tokio::time::timeout(Duration::from_secs(10), server).await.expect("the server's end");
    let (target, first) = ended.unwrap();
    Heard { target, first, answer }
}

/// Run `cmd` with `input` on its stdin, within the limit: its exit code,
/// its stdout and its stderr.
pub fn run(mut cmd: Command, input: Vec<u8>) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut all = Vec::new();
        let _ = stdout.read_to_end(&mut all);
        all
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = stderr.read_to_string(&mut all);
        all
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podssh still ran after {LIMIT:?}: {}", err.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    (code, out.join().unwrap(), err.join().unwrap())
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn mebibyte() -> Vec<u8> {
    (0..MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}
