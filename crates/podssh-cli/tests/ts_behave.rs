//! `ts` behaviour tests (Tailscale): dispatch maps every failure to
//! a non-zero exit with empty stdout, and the VERB_OWNER row is gone.
//!
//! The plant for this suite is deleting the `Parsed::Ts` arm in
//! `dispatch.rs`: every test below must fail, because the arm — not the
//! removed owner row — does the work. `run` uses `Tty::none` (a pipe), so
//! every case carries `--timeout` past the `--timeout` gate except the gate test.
//!
//! Shapes that would attempt a live start (valid key + state) are absent
//! here: they would dial the control plane from a unit test. The live proof
//! is the ignored M5 test at the bottom, naming its blocker.
//!
//! Only built with the `ts` feature; `ts_not_built.rs` covers the default
//! build, where `ts` parses and refuses.
#![cfg(feature = "ts")]

use podssh_cli::dispatch::{run, Streams};
use podssh_cli::tree::parse;

fn run_case(argv: &[&str]) -> (i32, String, String) {
    let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let p = parse(owned);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// A scratch key file with test-only bytes. Removed by the caller.
fn scratch_key(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("podssh-ts-behave-{name}-{}", std::process::id()));
    std::fs::write(&path, b"tskey-auth-test-not-a-secret").unwrap();
    path
}

#[test]
fn ts_without_a_key_file_is_77_naming_the_flag() {
    for argv in [vec!["ts", "--timeout", "30s"], vec!["ts", "-W", "peer:22", "--timeout", "30s"]] {
        let (rc, out, err) = run_case(&argv);
        assert_eq!(rc, 77, "{argv:?}");
        assert!(out.is_empty(), "{argv:?}");
        assert!(err.contains("--ts-auth-key-file"), "{argv:?}: {err}");
    }
}

#[test]
fn ts_with_an_unreadable_key_file_is_64_naming_the_path() {
    let missing = std::env::temp_dir().join("podssh-ts-behave-no-such-dir-9f3/missing.key");
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        missing.to_string_lossy().into_owned(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let owned: Vec<String> = argv;
    let p = parse(owned);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("missing.key"), "{text}");
}

#[test]
fn ts_with_an_empty_key_file_is_77() {
    let path = std::env::temp_dir().join(format!("podssh-ts-behave-empty-{}", std::process::id()));
    std::fs::write(&path, b"\n").unwrap();
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        path.to_string_lossy().into_owned(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let p = parse(argv);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    std::fs::remove_file(&path).ok();
    assert_eq!(rc, 77);
    assert!(out.is_empty());
}

#[test]
fn ts_host_form_refuses_with_empty_stdout() {
    let (rc, out, err) = run_case(&["ts", "peer", "--timeout", "30s"]);
    assert_eq!(rc, 70);
    assert!(out.is_empty());
    assert!(err.contains("not implemented yet"), "{err}");
}

#[test]
fn ts_without_a_state_file_is_64_naming_the_flag() {
    let key = scratch_key("state");
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        key.to_string_lossy().into_owned(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let p = parse(argv);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    std::fs::remove_file(&key).ok();
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("--ts-state"), "{text}");
}

#[test]
fn ts_with_a_state_parent_that_does_not_exist_is_64() {
    let key = scratch_key("parent");
    let missing = std::env::temp_dir().join("podssh-ts-behave-no-dir-9f3/state.json");
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        key.to_string_lossy().into_owned(),
        "--ts-state".to_string(),
        missing.to_string_lossy().into_owned(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let p = parse(argv);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    std::fs::remove_file(&key).ok();
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("does not exist"), "{text}");
}

#[test]
fn ts_with_a_bad_proxy_is_64() {
    let key = scratch_key("proxy");
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        key.to_string_lossy().into_owned(),
        "--ts-state".to_string(),
        "s.json".to_string(),
        "--ts-proxy".to_string(),
        "socks5://proxy.example:1080".to_string(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let p = parse(argv);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    std::fs::remove_file(&key).ok();
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("--ts-proxy"), "{text}");
}

#[test]
fn ts_with_a_bad_wait_is_64_naming_the_ts_flag() {
    let key = scratch_key("wait");
    let argv = vec![
        "ts".to_string(),
        "--ts-auth-key-file".to_string(),
        key.to_string_lossy().into_owned(),
        "--ts-state".to_string(),
        "s.json".to_string(),
        "--ts-wait-allowlist".to_string(),
        "30x".to_string(),
        "--timeout".to_string(),
        "30s".to_string(),
    ];
    let p = parse(argv);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
    std::fs::remove_file(&key).ok();
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    let text = String::from_utf8(err).unwrap();
    assert!(text.contains("--ts-wait-allowlist"), "{text}");
}

#[test]
fn ts_tun_and_socks_modes_are_78_capability() {
    for mode in ["tun", "socks"] {
        let (rc, out, err) = run_case(&["ts", "--ts-mode", mode, "--timeout", "30s"]);
        assert_eq!(rc, 78, "{mode}");
        assert!(out.is_empty(), "{mode}");
        assert!(err.contains(mode), "{mode}: {err}");
    }
}

#[test]
fn ts_without_timeout_in_a_pipe_is_usage_64() {
    let (rc, out, err) = run_case(&["ts", "-W", "peer:22"]);
    assert_eq!(rc, 64);
    assert!(out.is_empty());
    assert!(err.contains("--timeout"), "{err}");
}

/// M5 live acceptance: a real node prints its one status line.
///
/// Ignored: needs a live tailnet (auth key at `.env/TS_KEY.txt` plus the
/// relay allowlist sync — operator action with the Tailscale admin token and
/// the wrangler credential, neither present here). Un-ignoring without both
/// proves nothing: an unlisted key reads `1008 "not authorized"`, which is
/// the relay working, not the node.
#[test]
#[ignore = "M5: needs live tailnet admission (auth key + allowlist sync)"]
fn ts_live_status_prints_the_node_line() {
    let key = std::path::PathBuf::from(".env/TS_KEY.txt");
    let state = std::env::temp_dir().join("podssh-ts-m5-state.json");
    let argv = vec![
        "ts".to_string(),
        "--ts-mode".to_string(),
        "relay".to_string(),
        "--ts-auth-key-file".to_string(),
        key.to_string_lossy().into_owned(),
        "--ts-state".to_string(),
        state.to_string_lossy().into_owned(),
        "--timeout".to_string(),
        "120s".to_string(),
    ];
    let (rc, out, err) = run_case(&argv.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    std::fs::remove_file(&state).ok();
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("node "), "{out}");
}

/// `PODSSH_TIMEOUT` passes the gate of `ts` (GitHub #12): with it, `ts` stops
/// at the missing key file (77); without it, the gate refuses (64); a bad
/// value is 78. The binary runs, so the variable reaches only its process.
#[test]
fn podssh_timeout_passes_the_gate() {
    let run = |value: Option<&str>| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.arg("ts").env("PODSSH_OFFLINE", "1").env_remove("PODSSH_TIMEOUT");
        if let Some(v) = value {
            cmd.env("PODSSH_TIMEOUT", v);
        }
        cmd.stdin(std::process::Stdio::null()).output().expect("podssh runs").status.code()
    };
    assert_eq!(run(Some("30s")), Some(77), "the variable passes the gate");
    assert_eq!(run(None), Some(64), "no flag and no variable, with no terminal");
    assert_eq!(run(Some("30x")), Some(78), "a bad variable");
}
