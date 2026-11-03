//! The tools of `podssh mcp` that T-488 adds, through the server as an MCP
//! client runs it, against the test's SSH server: `cp_put` of a file of
//! `--allow-dir` and of `content`, and `cp_get` back, each with its bytes;
//! `job_start`, then `job_wait` with the job's status, its log and its stop
//! (with tmux on this host); and `session_start`, `send`, `wait` and
//! `capture` on a pty, a session of another's refused, and each session
//! that the server started stopped at its end. The copies and the jobs need
//! a far host of sh (`job_harness`), so they run on Unix.

mod cleanup;
#[cfg(unix)]
mod job_harness;
mod mcp_harness;
mod ssh_harness;

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use mcp_harness::{config, host_key, podssh, scratch, trust, Mcp};
use serde_json::json;

/// The server for a far host at `port`, its key `key`, with `extra` flags;
/// the known_hosts of `home` holds the key, so that no tool needs a
/// fingerprint.
fn serve(home: &Path, port: u16, key: &Path, extra: &[&str]) -> Mcp {
    let config = config(home, port);
    trust(home, port, key);
    let config = config.display().to_string();
    let mut args = vec!["--allow-host", "127.0.0.1", "-F", config.as_str(), "--direct"];
    args.extend_from_slice(extra);
    let mut mcp = Mcp::start(home, &args);
    mcp.initialize();
    mcp
}

/// A copy up, of a file of the directory and of content, and down again,
/// each file with its bytes, as cp checked its digest.
#[cfg(unix)]
#[test]
fn cp_put_and_cp_get_carry_a_file_with_its_digest() {
    use base64::Engine as _;
    let far = job_harness::Far::new("mcp-cp", std::env::var("PATH").unwrap_or_default(), None);
    let key = far.home.parent().unwrap().join("host_key");
    let allowed = far.local.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(allowed.join("up.bin"), &bytes).unwrap();
    let mut mcp = serve(&far.local, far.port, &key, &["--allow-dir", allowed.to_str().unwrap()]);
    let r = mcp.call("cp_put", json!({ "destination": "a@127.0.0.1", "path": "up.bin", "local_path": "up.bin" }));
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["exit"], 0, "{r}");
    assert!(std::fs::read(far.home.join("up.bin")).unwrap() == bytes, "the far file differs");
    let content = base64::engine::general_purpose::STANDARD.encode(b"hello\n");
    let r = mcp.call("cp_put", json!({ "destination": "a@127.0.0.1", "path": "note.txt", "content": content }));
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(std::fs::read(far.home.join("note.txt")).unwrap(), b"hello\n");
    let r = mcp.call("cp_get", json!({ "destination": "a@127.0.0.1", "path": "up.bin", "local_path": "down.bin" }));
    assert_eq!(r["isError"], false, "{r}");
    assert!(std::fs::read(allowed.join("down.bin")).unwrap() == bytes, "the copy down differs");
    let (code, _) = mcp.close();
    assert_eq!(code, Some(0));
}

/// A job starts, and job_wait gives its status once it ended; its log and
/// its list, then its stop.
#[cfg(unix)]
#[test]
fn job_start_then_job_wait_gives_the_job_s_status() {
    let Some(far) = job_harness::Far::with_tmux("mcp-job") else { return };
    let key = far.home.parent().unwrap().join("host_key");
    let mut mcp = serve(&far.local, far.port, &key, &[]);
    let host = "a@127.0.0.1";
    let r = mcp.call("job_start", json!({ "destination": host, "command": "printf 'J\\n'; exit 5" }));
    assert_eq!(r["isError"], false, "{r}");
    let id = r["structuredContent"]["id"].as_str().unwrap_or_else(|| panic!("no id: {r}")).to_string();
    let r = mcp.call("job_wait", json!({ "destination": host, "id": id, "wait_seconds": 30 }));
    let s = &r["structuredContent"];
    assert_eq!((r["isError"].clone(), s["ended"].clone(), s["exit"].clone()), (json!(false), json!(true), json!(5)), "{r}");
    let r = mcp.call("job_log", json!({ "destination": host, "id": id }));
    assert_eq!(r["structuredContent"]["stdout"], "J\n", "{r}");
    let r = mcp.call("job_list", json!({ "destination": host }));
    assert!(r["structuredContent"].to_string().contains(&id), "{r}");
    let r = mcp.call("job_stop", json!({ "destination": host, "id": id }));
    assert_eq!(r["isError"], false, "{r}");
    mcp.close();
}

/// A session that the test stops when it fails, as the server would not.
struct Stopped<'a>(&'a Path, &'a str);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        let mut cmd = podssh(self.0);
        cmd.args(["session", "stop", self.1]);
        let _ = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// A session on a pty, driven by the calls; another's is refused; the
/// server's end stops it, and its socket goes.
#[test]
fn the_server_s_end_stops_each_session_that_it_started() {
    let dir = scratch("sessions");
    let key = host_key(&dir);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let mut mcp = serve(&dir, port, &key, &["--allow-session"]);
    let _stopped = Stopped(&dir, "w");
    let r = mcp.call("session_start", json!({ "name": "w", "destination": "pty-u@127.0.0.1", "command": "cat" }));
    assert_eq!(r["isError"], false, "{r}");
    let socket = std::path::PathBuf::from(r["structuredContent"]["socket"].as_str().unwrap_or_default());
    assert!(socket.exists(), "{r}");
    assert_eq!(mcp.call("session_send", json!({ "name": "w", "text": "echo hi" }))["isError"], false);
    let r = mcp.call("session_wait", json!({ "name": "w", "idle_seconds": 1, "wait_seconds": 20 }));
    assert_eq!(r["structuredContent"]["ended_by"], "idle", "{r}");
    let r = mcp.call("session_capture", json!({ "name": "w" }));
    assert!(r["structuredContent"]["stdout"].as_str().unwrap_or_default().contains("echo hi"), "{r}");
    let r = mcp.call("session_send", json!({ "name": "theirs", "text": "x" }));
    assert_eq!(r["isError"], true, "{r}");
    assert!(r["content"][0]["text"].as_str().unwrap().contains("not one that this server started"), "{r}");
    let (code, _) = mcp.close();
    assert_eq!(code, Some(0));
    let deadline = Instant::now() + Duration::from_secs(15);
    while socket.exists() {
        assert!(Instant::now() < deadline, "the session outlived the server: {}", socket.display());
        std::thread::sleep(Duration::from_millis(100));
    }
}
