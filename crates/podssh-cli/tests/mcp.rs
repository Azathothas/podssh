//! `podssh mcp` (T-055) over its stdin and stdout, as an MCP client runs it:
//! the handshake of the earlier revisions and the requests of 2026-07-28,
//! the errors of JSON-RPC, a host outside `--allow-host` refused with no
//! connection, and `ssh_exec` against the test's SSH server. Each line that
//! the server writes on stdout is read as one JSON-RPC answer: one that is
//! not fails the test.

mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const WAIT: Duration = Duration::from_secs(60);

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next: u64,
}

fn podssh(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd
}

impl Mcp {
    fn start(dir: &Path, args: &[&str]) -> Mcp {
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

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next answer, read as JSON-RPC 2.0: an id, and a result or an
    /// error.
    fn answer(&self, within: Duration) -> Option<Value> {
        let line = self.lines.recv_timeout(within).ok()?;
        let value: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON-RPC ({e}): {line}"));
        assert_eq!(value["jsonrpc"], "2.0", "{line}");
        assert!(value.get("id").is_some(), "no id: {line}");
        assert!(value.get("result").is_some() != value.get("error").is_some(), "{line}");
        Some(value)
    }

    /// A request, and its answer.
    fn ask(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let answer = self.answer(WAIT).unwrap_or_else(|| panic!("no answer to {method}"));
        assert_eq!(answer["id"], id, "{answer}");
        answer
    }

    /// `tools/call` of `name` in the handshake's revision.
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.ask("tools/call", json!({ "name": name, "arguments": arguments }))["result"].clone()
    }

    fn initialize(&mut self) {
        let r = self.ask(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": { "name": "test", "version": "1" } }),
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18", "{r}");
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    /// Close stdin: the exit code, and how long the server took.
    fn close(mut self) -> (Option<i32>, Duration) {
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

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-mcp-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

#[test]
fn the_handshake_the_list_and_the_errors_of_json_rpc() {
    let dir = scratch("protocol");
    let mut mcp = Mcp::start(&dir, &["--allow-host", "127.0.0.1"]);
    mcp.send(&json!("not a request"));
    assert_eq!(mcp.answer(WAIT).unwrap()["error"]["code"], -32600);
    writeln!(mcp.stdin.as_mut().unwrap(), "not json").unwrap();
    assert_eq!(mcp.answer(WAIT).unwrap()["error"]["code"], -32700);
    mcp.initialize();
    let tools = mcp.ask("tools/list", json!({}));
    let names: Vec<&str> =
        tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["ssh_exec", "status", "doctor", "man"]);
    assert_eq!(mcp.ask("ping", json!({}))["result"], json!({}));
    assert_eq!(mcp.ask("prompts/list", json!({}))["error"]["code"], -32601);
    assert_eq!(mcp.ask("tools/call", json!({ "name": "rm" }))["error"]["code"], -32602);
    // The revision 2026-07-28: each request names its version.
    let meta = json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {} } });
    let discover = mcp.ask("server/discover", meta.clone());
    assert_eq!(discover["result"]["resultType"], "complete", "{discover}");
    assert_eq!(discover["result"]["supportedVersions"][0], "2026-07-28");
    // man's JSON is the tool's structured result.
    let mut params = meta.clone();
    params["name"] = json!("man");
    params["arguments"] = json!({ "section": "mcp" });
    let man = mcp.ask("tools/call", params)["result"].clone();
    assert_eq!((man["isError"].clone(), man["resultType"].clone()), (json!(false), json!("complete")), "{man}");
    assert!(man["structuredContent"].to_string().contains("allow-host"), "{man}");
    let (code, _) = mcp.close();
    assert_eq!(code, Some(0));
}

#[test]
fn a_host_outside_the_list_is_refused_and_not_reached() {
    let dir = scratch("refused");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = dir.join("config");
    std::fs::write(&config, format!("Host other\n  HostName 127.0.0.1\n  Port {port}\n")).unwrap();
    let mut mcp = Mcp::start(&dir, &["--allow-host", "web*", "-F", config.to_str().unwrap(), "--direct"]);
    mcp.initialize();
    for destination in ["other", "u@other", "-oProxyCommand=x", "other:22"] {
        let r = mcp.call("ssh_exec", json!({ "destination": destination, "command": "true" }));
        assert_eq!(r["isError"], true, "{destination}: {r}");
        assert!(r.get("structuredContent").is_none(), "{r}");
    }
    let r = mcp.call("ssh_exec", json!({ "destination": "other", "command": "true" }));
    assert!(r["content"][0]["text"].as_str().unwrap().contains("allows web* (--allow-host)"), "{r}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(listener.accept().is_err(), "a refused call reached the host");
    // With no --allow-host, ssh_exec is not offered.
    mcp.close();
    let mut mcp = Mcp::start(&dir, &[]);
    mcp.initialize();
    assert_eq!(mcp.ask("tools/call", json!({ "name": "ssh_exec", "arguments": {} }))["error"]["code"], -32602);
    mcp.close();
}

#[test]
fn a_bad_command_line_is_refused() {
    let dir = scratch("usage");
    for (args, code) in [
        (&["--allow-host", ""][..], 64),
        (&["--allow-host", "a b"][..], 64),
        (&["--allow-host", "u@"][..], 64),
        (&["stray"][..], 64),
        (&["-F", "no-such-file"][..], 78),
    ] {
        let out = podssh(&dir).arg("mcp").args(args).stdin(Stdio::null()).output().unwrap();
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

/// The test's server, and a configuration that reaches it as 127.0.0.1.
fn server(dir: &Path) -> (tokio::runtime::Runtime, PathBuf, String) {
    let key = dir.join("host_key");
    let made = podssh(dir).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let config = dir.join("config");
    let known = dir.join("known_hosts");
    let text = format!(
        "Host 127.0.0.1\n  Port {port}\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {}\n",
        known.display()
    );
    std::fs::write(&config, text).unwrap();
    let public = std::fs::read_to_string(dir.join("host_key.pub")).unwrap();
    let public = russh::keys::ssh_key::PublicKey::from_openssh(public.trim()).unwrap();
    (runtime, config, public.fingerprint(russh::keys::HashAlg::Sha256).to_string())
}

#[test]
fn ssh_exec_gives_the_status_and_the_streams_of_a_command() {
    let dir = scratch("exec");
    let (_runtime, config, fingerprint) = server(&dir);
    let mut mcp = Mcp::start(&dir, &["--allow-host", "127.0.0.1", "-F", config.to_str().unwrap(), "--direct"]);
    mcp.initialize();
    // An unknown host key, and no fingerprint: refused.
    let r = mcp.call("ssh_exec", json!({ "destination": "u@127.0.0.1", "command": "exit 3" }));
    assert_eq!(
        (r["isError"].clone(), r["structuredContent"]["failure"].clone()),
        (json!(true), json!("host-key")),
        "{r}"
    );
    let exec = |mcp: &mut Mcp, extra: Value| {
        let mut arguments = json!({ "destination": "u@127.0.0.1", "host_key_fingerprint": fingerprint });
        arguments.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        mcp.call("ssh_exec", arguments)
    };
    let r = exec(&mut mcp, json!({ "command": "exit 3" }));
    let s = &r["structuredContent"];
    assert_eq!(r["isError"], false, "a status is the command's: {r}");
    assert_eq!(
        (s["exit"].clone(), s["status"].clone(), s["end"].clone()),
        (json!(3), json!(3), json!("status")),
        "{r}"
    );
    assert_eq!((s["stdout"].clone(), s["stdout_encoding"].clone()), (json!("out\n"), json!("utf-8")));
    assert!(s["stderr"].as_str().unwrap().contains("err!\n"), "{r}");
    assert_eq!(serde_json::from_str::<Value>(r["content"][0]["text"].as_str().unwrap()).unwrap(), *s);
    let r = exec(&mut mcp, json!({ "command": "cat", "stdin": "hello\n" }));
    assert_eq!(
        (r["structuredContent"]["stdout"].clone(), r["structuredContent"]["status"].clone()),
        (json!("hello\n"), json!(0)),
        "{r}"
    );
    // Past 1 MiB, the output is cut, and says so.
    let r = exec(&mut mcp, json!({ "command": "head -c 1500000 /dev/zero" }));
    let s = &r["structuredContent"];
    assert_eq!(
        (s["truncated"].clone(), s["stdout"].as_str().unwrap().len()),
        (json!(true), 1 << 20),
        "{}",
        s["stderr"]
    );
    // Past its limit, the call ends with its session.
    let started = Instant::now();
    let ran = dir.join("ran").display().to_string();
    let r = exec(&mut mcp, json!({ "command": format!("append {ran} 0 30"), "timeout_seconds": 1 }));
    assert_eq!((r["isError"].clone(), r["structuredContent"]["timed_out"].clone()), (json!(true), json!(true)), "{r}");
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    // A cancelled call gets no answer, and the server goes on.
    mcp.send(&json!({ "jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": { "name": "ssh_exec",
        "arguments": { "destination": "u@127.0.0.1", "host_key_fingerprint": fingerprint,
            "command": format!("append {ran} 0 30") } } }));
    std::thread::sleep(Duration::from_millis(500));
    mcp.send(&json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": "slow" } }));
    assert_eq!(mcp.ask("ping", json!({}))["result"], json!({}));
    assert!(mcp.answer(Duration::from_secs(3)).is_none(), "a cancelled call was answered");
    // The end of input ends the server, and a call in flight with it.
    mcp.send(&json!({ "jsonrpc": "2.0", "id": "last", "method": "tools/call", "params": { "name": "ssh_exec",
        "arguments": { "destination": "u@127.0.0.1", "host_key_fingerprint": fingerprint,
            "command": format!("append {ran} 0 30") } } }));
    std::thread::sleep(Duration::from_millis(500));
    let (code, took) = mcp.close();
    assert_eq!(code, Some(0));
    assert!(took < Duration::from_secs(15), "{took:?}");
}
