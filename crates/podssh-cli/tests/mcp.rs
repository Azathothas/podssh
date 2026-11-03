//! `podssh mcp` (T-055) over its stdin and stdout, as an MCP client runs it:
//! the handshake of the earlier revisions and the requests of 2026-07-28,
//! the errors of JSON-RPC, a host outside `--allow-host` refused with no
//! connection, and `ssh_exec` against the test's SSH server; the tools of
//! T-488 behind their gates, and a local path outside `--allow-dir` refused
//! before any child runs. Each line that the server writes on stdout is read
//! as one JSON-RPC answer: one that is not fails the test.

mod cleanup;
mod mcp_harness;
mod ssh_harness;

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use mcp_harness::{podssh, scratch, server, Mcp, WAIT};
use serde_json::{json, Value};

#[test]
fn the_handshake_the_list_and_the_errors_of_json_rpc() {
    let dir = scratch("protocol");
    let mut mcp = Mcp::start(&dir, &["--allow-host", "127.0.0.1"]);
    mcp.send(&json!("not a request"));
    assert_eq!(mcp.answer(WAIT).unwrap()["error"]["code"], -32600);
    writeln!(mcp.stdin.as_mut().unwrap(), "not json").unwrap();
    assert_eq!(mcp.answer(WAIT).unwrap()["error"]["code"], -32700);
    mcp.initialize();
    let names = mcp.tool_names();
    let hosts = ["ssh_exec", "health", "job_start", "job_list", "job_log", "job_wait", "job_stop"];
    assert_eq!(names, [&hosts[..], &["status", "doctor", "man"][..]].concat());
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
        (&["--allow-dir", "no-such-dir"][..], 78),
    ] {
        let out = podssh(&dir).arg("mcp").args(args).stdin(Stdio::null()).output().unwrap();
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    // A directory that holds the home's .ssh, the home itself here, is
    // refused, and names why (T-488).
    let out = podssh(&dir).arg("mcp").arg("--allow-dir").arg(&dir).stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(64), "{err}");
    assert!(err.contains(".ssh is inside it"), "{err}");
}

/// The copies only with `--allow-dir`, the sessions only with
/// `--allow-session`, and neither with no host allowed (T-488).
#[test]
fn each_tool_of_t488_is_offered_behind_its_gate() {
    let dir = scratch("gates");
    let allowed = dir.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let allowed = allowed.to_str().unwrap();
    let names = |args: &[&str]| {
        let mut mcp = Mcp::start(&dir, args);
        mcp.initialize();
        let names = mcp.tool_names();
        mcp.close();
        names
    };
    let copies = ["cp_put", "cp_get"];
    let sessions = ["session_start", "session_send", "session_wait", "session_capture", "session_stop"];
    let has = |names: &[String], wanted: &[&str]| wanted.iter().all(|w| names.iter().any(|n| n == w));
    let all = names(&["--allow-host", "web*", "--allow-dir", allowed, "--allow-session"]);
    assert!(has(&all, &copies) && has(&all, &sessions) && has(&all, &["health", "job_wait"]), "{all:?}");
    let host = names(&["--allow-host", "web*"]);
    assert!(!host.iter().any(|n| n.starts_with("cp_") || n.starts_with("session_")), "{host:?}");
    let no_host = names(&["--allow-dir", allowed, "--allow-session"]);
    assert_eq!(no_host, ["status", "doctor", "man"], "no tool reaches a host with none allowed");
}

/// A local path outside `--allow-dir`, and a link that leads out of it, are
/// refused before any child runs: the host's port sees no connection; so is
/// a host outside `--allow-host`, by each tool that reaches one (T-488).
#[test]
fn a_path_outside_the_directory_and_a_host_outside_the_list_reach_nothing() {
    let dir = scratch("outside");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = mcp_harness::config(&dir, listener.local_addr().unwrap().port());
    let (allowed, other) = (dir.join("allowed"), dir.join("other"));
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("secret"), b"not for the agent").unwrap();
    std::fs::write(allowed.join("ok.txt"), b"ok").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(other.join("secret"), allowed.join("to-secret")).unwrap();
    let (allowed_text, config_text) = (allowed.to_str().unwrap(), config.to_str().unwrap());
    let args = ["--allow-host", "127.0.0.1", "--allow-dir", allowed_text, "-F", config_text, "--direct"];
    let mut mcp = Mcp::start(&dir, &args);
    mcp.initialize();
    let secret = other.join("secret").display().to_string();
    let mut outside = vec![secret.clone(), "../other/secret".to_string()];
    if cfg!(unix) {
        outside.push("to-secret".into());
    }
    for local in &outside {
        let r = mcp.call("cp_put", json!({ "destination": "127.0.0.1", "path": "p", "local_path": local }));
        assert_eq!(r["isError"], true, "{local}: {r}");
        assert!(r["content"][0]["text"].as_str().unwrap().contains("outside the directories"), "{local}: {r}");
    }
    let r = mcp.call("cp_get", json!({ "destination": "127.0.0.1", "path": "p", "local_path": secret }));
    assert_eq!(r["isError"], true, "{r}");
    let other_host = json!({ "destination": "db1", "path": "p", "local_path": "ok.txt", "command": "true",
        "id": "0123abcd" });
    for (tool, keys) in [
        ("cp_put", &["destination", "path", "local_path"][..]),
        ("health", &["destination"][..]),
        ("job_start", &["destination", "command"][..]),
        ("job_stop", &["destination", "id"][..]),
    ] {
        let arguments: serde_json::Map<String, Value> =
            keys.iter().map(|k| (k.to_string(), other_host[*k].clone())).collect();
        let r = mcp.call(tool, Value::Object(arguments));
        assert!(r["content"][0]["text"].as_str().unwrap().contains("not allowed"), "{tool}: {r}");
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(listener.accept().is_err(), "a refused call reached the host");
    mcp.close();
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
