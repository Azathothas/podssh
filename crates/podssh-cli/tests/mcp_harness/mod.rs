//! `podssh mcp` as an MCP client runs it (T-055, T-488): the server on its
//! stdin and stdout, each line that it writes read as one JSON-RPC answer,
//! a scratch home, and the test's SSH server with a configuration that
//! reaches it as 127.0.0.1. `tests/mcp.rs` and `tests/mcp_tools.rs` share it.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const WAIT: Duration = Duration::from_secs(60);

pub struct Mcp {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub lines: Receiver<String>,
    pub next: u64,
}

/// podssh with a clean environment, its home and its cache in `dir`.
pub fn podssh(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    cmd.env("PODSSH_CACHE_DIR", dir.join("cache"));
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd
}

impl Mcp {
    pub fn start(dir: &Path, args: &[&str]) -> Mcp {
        let mut child = podssh(dir)
            .arg("mcp")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Mcp { stdin: child.stdin.take(), child, lines, next: 100 }
    }

    pub fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next answer, read as JSON-RPC 2.0: an id, and a result or an
    /// error.
    pub fn answer(&self, within: Duration) -> Option<Value> {
        let line = self.lines.recv_timeout(within).ok()?;
        let value: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON-RPC ({e}): {line}"));
        assert_eq!(value["jsonrpc"], "2.0", "{line}");
        assert!(value.get("id").is_some(), "no id: {line}");
        assert!(value.get("result").is_some() != value.get("error").is_some(), "{line}");
        Some(value)
    }

    /// A request, and its answer.
    pub fn ask(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let answer = self.answer(WAIT).unwrap_or_else(|| panic!("no answer to {method}"));
        assert_eq!(answer["id"], id, "{answer}");
        answer
    }

    /// `tools/call` of `name` in the handshake's revision.
    pub fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.ask("tools/call", json!({ "name": name, "arguments": arguments }))["result"].clone()
    }

    pub fn initialize(&mut self) {
        let r = self.ask(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": { "name": "test", "version": "1" } }),
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18", "{r}");
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    /// The names of `tools/list`, in its order.
    pub fn tool_names(&mut self) -> Vec<String> {
        let tools = self.ask("tools/list", json!({}));
        tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// Close stdin: the exit code, and how long the server took.
    pub fn close(mut self) -> (Option<i32>, Duration) {
        drop(self.stdin.take());
        let started = Instant::now();
        while started.elapsed() < WAIT {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status.code(), started.elapsed());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        panic!("podssh mcp did not end at the end of its input");
    }
}

pub fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-mcp-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::cleanup::at_test_end(&dir);
    dir
}

/// A host key in `dir`, made by podssh, for the test's server.
pub fn host_key(dir: &Path) -> PathBuf {
    let key = dir.join("host_key");
    let made = podssh(dir).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
    assert!(made.success());
    key
}

/// A configuration that reaches the server at `port` as 127.0.0.1, with no
/// key of the user's and the known_hosts of `dir`.
pub fn config(dir: &Path, port: u16) -> PathBuf {
    let config = dir.join("config");
    let known = dir.join("known_hosts");
    let text = format!(
        "Host 127.0.0.1\n  Port {port}\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {}\n",
        known.display()
    );
    std::fs::write(&config, text).unwrap();
    config
}

/// The known_hosts of `dir` holds the server's key `key`, so that a tool
/// with no fingerprint of its own reaches it with StrictHostKeyChecking=yes.
pub fn trust(dir: &Path, port: u16, key: &Path) {
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let mut words = public.split_whitespace();
    let (kind, body) = (words.next().unwrap(), words.next().unwrap());
    std::fs::write(dir.join("known_hosts"), format!("[127.0.0.1]:{port} {kind} {body}\n")).unwrap();
}

/// The test's server, and a configuration that reaches it as 127.0.0.1:
/// the runtime that serves it, the configuration, and the SHA-256
/// fingerprint of its key.
pub fn server(dir: &Path) -> (tokio::runtime::Runtime, PathBuf, String) {
    let key = host_key(dir);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(crate::ssh_harness::start(&key));
    let config = config(dir, port);
    let public = std::fs::read_to_string(dir.join("host_key.pub")).unwrap();
    let public = russh::keys::ssh_key::PublicKey::from_openssh(public.trim()).unwrap();
    (runtime, config, public.fingerprint(russh::keys::HashAlg::Sha256).to_string())
}
