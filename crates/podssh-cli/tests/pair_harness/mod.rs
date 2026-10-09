//! The harness of the offline tests of the pairs' commands (T-083, T-084):
//! a scratch HOME and cache, test pairs in the store, the binary run offline,
//! and the check that no output holds a token.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::pair;
use podssh_relay::relay::Relay;

pub const NAME: &str = "p-0123456789abcdef0123456789abcdef";
pub const NODE: &str = "testonlynode0000000000000000000000000000000000000000000000000000";
pub const CONNECT: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
pub const STOP: &str = "testonlystop0000000000000000000000000000000000000000000000000000";
// The repository's fixture form: a MAC with no digit is not a credential.
pub const FORWARD: &str = "ephm1.9999999999999.forward.TESTONLYNOTACREDENTIALNODE";

pub fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-node-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The cache directory that podssh uses under `home`.
pub fn cache_dir(home: &Path) -> PathBuf {
    home.join("cache").join("podssh")
}

/// A pair named NAME with the test tokens, made `made_ms_ago`, for 72 hours.
pub fn test_pair(made_ms_ago: i64) -> pair::Pair {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let made = now - made_ms_ago;
    let body = format!(
        r#"{{"name":"{NAME}","node_token":"{NODE}","connect_token":"{CONNECT}","stop_token":"{STOP}","expires":{}}}"#,
        made + 72 * 3600 * 1000
    );
    let relay = Relay { host: "relay.example.org".into(), port: 443 };
    pair::parse(&relay, body.as_bytes(), made).expect("a test pair")
}

/// Keep a test pair under `label` in the cache of `home`.
pub fn store(home: &Path, label: &str, made_ms_ago: i64) -> PathBuf {
    pair::store_in_first(&[cache_dir(home)], label, &test_pair(made_ms_ago)).expect("stored")
}

pub const EXPIRED: i64 = 80 * 3600 * 1000;

/// Run `podssh ARGS` offline, with HOME and the cache under `home`: the code,
/// stdout and stderr, within 30 s.
pub fn podssh(home: &Path, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    for name in [
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_TOKEN",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home).env("PODSSH_OFFLINE", "1");
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd.envs(set.iter().copied());
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh {args:?} did not end within 30 s");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// No token of the pair, nor the token in the environment, in `text`.
pub fn no_token(text: &str) {
    for token in [NODE, CONNECT, STOP, FORWARD] {
        assert!(!text.contains(token), "a token is in {text:?}");
    }
}
