//! `podssh status` as a process, with a scratch HOME and cache: one line of
//! JSON; the relay hosts and where they came from; a cached token and a
//! token in the environment that never appear; whether a host key is known;
//! and a cache directory that the run does not change.

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

// The repository's fixture form: a MAC with no digit is not a credential.
const SECRET_CACHED: &str = "ephm1.9999999999999.forward.TESTONLYNOTACREDENTIALCACHED";
const SECRET_CACHED_MAC: &str = "TESTONLYNOTACREDENTIALCACHED";
const SECRET_ENV: &str = "podssh-status-test-token-0123456789abcdef";

/// A scratch directory, made for one test.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-status-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The cache directory that podssh uses under `home`, as `cache` finds it.
fn cache_dir(home: &Path) -> PathBuf {
    home.join("cache").join("podssh")
}

/// Run `podssh status ARGS` with HOME and the cache under `home`, offline,
/// and nothing else steering it but `set`. The code and stdout, within 30 s.
fn status(home: &Path, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String) {
    ran(command(home, "status", args, set))
}

/// `podssh VERB ARGS` with HOME and the cache under `home`, offline, and
/// nothing else steering it but `set`.
fn command(home: &Path, verb: &str, args: &[&str], set: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg(verb).args(args);
    for name in [
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_CACHE_DIR",
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
    cmd
}

/// The code, stdout and stderr of `cmd`, within 30 s.
fn ran(mut cmd: Command) -> (i32, String, String) {
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh did not end within 30 s");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn one_line(out: &str) -> Value {
    assert_eq!(out.lines().count(), 1, "one line: {out}");
    serde_json::from_str(out).expect("the line is JSON")
}

#[test]
fn the_line_names_the_relays_and_where_they_came_from() {
    let home = scratch("relays");
    let (rc, out, err) = status(&home, &[], &[]);
    assert_eq!(rc, 0, "{err}");
    let doc = one_line(&out);
    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["relays_from"], "default and pool");
    assert_eq!(doc["relays"][0]["host"], podssh_relay::DEFAULT_RELAY_HOST);
    assert_eq!(doc["offline"], true);
    assert_eq!(doc["attachment"], "pipe");
    assert!(doc["host"].is_null());
    let (_, out, _) = status(&home, &["--relay-host", "a.example,b.example:8443"], &[]);
    let doc = one_line(&out);
    assert_eq!(doc["relays_from"], "--relay-host");
    assert_eq!(
        doc["relays"],
        serde_json::json!([{ "host": "a.example", "port": 443 }, { "host": "b.example", "port": 8443 }])
    );
    let (_, out, _) = status(&home, &[], &[("PODSSH_RELAY", "c.example")]);
    assert_eq!(one_line(&out)["relays_from"], "PODSSH_RELAY");
    let (rc, out, err) = status(&home, &["bad host!"], &[]);
    assert_eq!(rc, 64, "{out}{err}");
    assert!(out.is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

/// A cached token and a token in the environment are said to be there, and
/// never shown; the run leaves the cache as it was.
#[test]
fn no_token_appears_and_the_cache_is_unchanged() {
    let home = scratch("secret");
    let dir = cache_dir(&home);
    let key = podssh_relay::DEFAULT_RELAY_HOST;
    let far = 9_999_999_999_999;
    podssh_relay::cache::store_in_first(std::slice::from_ref(&dir), key, SECRET_CACHED, far, key)
        .expect("a cache entry");
    let listing = |d: &Path| -> Vec<(String, u64, std::time::SystemTime)> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| {
                let m = e.metadata().unwrap();
                (e.file_name().to_string_lossy().into_owned(), m.len(), m.modified().unwrap())
            })
            .collect();
        v.sort();
        v
    };
    let before = listing(&dir);
    let (rc, out, err) = status(&home, &[], &[]);
    assert_eq!(rc, 0, "{err}");
    assert!(!out.contains(SECRET_CACHED) && !err.contains(SECRET_CACHED), "{out}{err}");
    assert!(!out.contains(SECRET_CACHED_MAC) && !err.contains(SECRET_CACHED_MAC), "{out}{err}");
    let doc = one_line(&out);
    assert_eq!(doc["token"]["source"], "cache");
    assert_eq!(doc["token"]["for"], key);
    assert_eq!(doc["token"]["expires_ms"], far);
    assert_eq!(listing(&dir), before, "the run changed the cache");
    let (_, out, err) = status(&home, &[], &[("PODSSH_RELAY_TOKEN", SECRET_ENV)]);
    assert!(!out.contains(SECRET_ENV) && !err.contains(SECRET_ENV), "{out}{err}");
    assert_eq!(one_line(&out)["token"]["source"], "PODSSH_RELAY_TOKEN");
    let _ = std::fs::remove_dir_all(&home);
}

/// A destination's host key is known when the user's `known_hosts` has it.
#[test]
fn a_known_host_key_is_found_and_an_unknown_one_is_not() {
    let home = scratch("hosts");
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    std::fs::write(ssh.join("known_hosts"), format!("fixture.example ssh-ed25519 {key}\n")).unwrap();
    let (rc, out, err) = status(&home, &["user@fixture.example"], &[]);
    assert_eq!(rc, 0, "{err}");
    let doc = one_line(&out);
    assert_eq!(doc["host"]["name"], "fixture.example");
    assert_eq!(doc["host"]["known"], true);
    assert_eq!(doc["host"]["key_types"], serde_json::json!(["ssh-ed25519"]));
    let (_, out, _) = status(&home, &["unknown.example:2222"], &[]);
    let doc = one_line(&out);
    assert_eq!(doc["host"]["name"], "[unknown.example]:2222");
    assert_eq!(doc["host"]["known"], false);
    let _ = std::fs::remove_dir_all(&home);
}

/// The cache's directories, and what chose them (T-243): the directory of
/// PODSSH_CACHE_DIR first, none for no directory, else the usual places.
#[test]
fn the_cache_shows_its_directories_and_what_chose_them() {
    let home = scratch("cache-dir");
    let chosen = home.join("chosen");
    let (code, out, err) = status(&home, &[], &[("PODSSH_CACHE_DIR", chosen.to_str().unwrap())]);
    assert_eq!(code, 0, "{err}");
    let doc = one_line(&out);
    assert_eq!(doc["cache"]["from"], "PODSSH_CACHE_DIR");
    assert_eq!(doc["cache"]["dirs"][0], chosen.display().to_string());
    assert_eq!(doc["cache"]["dirs"][1], cache_dir(&home).display().to_string());
    let (code, out, err) = status(&home, &[], &[("PODSSH_CACHE_DIR", "none")]);
    assert_eq!(code, 0, "{err}");
    let doc = one_line(&out);
    assert_eq!(doc["cache"]["from"], "none");
    assert_eq!(doc["cache"]["dirs"], serde_json::json!([]));
    let (_, out, _) = status(&home, &[], &[]);
    assert_eq!(one_line(&out)["cache"]["from"], "default");
}

/// The proxy: its variable, HOST:PORT and its kind, never its user or its
/// password (T-070); a setting that cannot be used gives its error.
#[test]
fn the_proxy_is_named_with_its_kind_and_no_credentials() {
    let home = scratch("proxy");
    for (url, shown, kind) in [
        ("http://alice:s3cret@proxy.example:3128", "proxy.example:3128", "http"),
        ("socks5h://alice:s3cret@proxy.example:1080", "proxy.example:1080", "socks5"),
        ("socks5://alice:s3cret@proxy.example", "proxy.example:1080", "socks5"),
    ] {
        let (rc, out, err) = status(&home, &[], &[("ALL_PROXY", url)]);
        assert_eq!(rc, 0, "{err}");
        let doc = one_line(&out);
        // Windows reads variable names without regard to case.
        assert_eq!(doc["proxy"]["variable"].as_str().map(str::to_ascii_lowercase).as_deref(), Some("all_proxy"));
        assert_eq!((doc["proxy"]["proxy"].as_str(), doc["proxy"]["kind"].as_str()), (Some(shown), Some(kind)), "{out}");
        assert!(!out.contains("s3cret") && !out.contains("alice"), "{out}");
    }
    let (rc, out, err) = status(&home, &[], &[("ALL_PROXY", "socks4://alice:s3cret@proxy.example:1080")]);
    assert_eq!(rc, 0, "{err}");
    let doc = one_line(&out);
    assert!(doc["proxy"]["error"].as_str().is_some_and(|why| why.contains("SOCKS4")), "{out}");
    assert_eq!((doc["proxy"]["proxy"].clone(), doc["proxy"]["kind"].clone()), (Value::Null, Value::Null), "{out}");
    assert!(!out.contains("s3cret") && !out.contains("alice"), "{out}");
}

/// The limit of open files (T-564): a soft limit of 64 under a hard one
/// above it is raised to the hard one; a hard limit of 64 keeps it, and `-v`
/// says so once.
#[cfg(unix)]
mod open_files {
    use std::os::unix::process::CommandExt;

    use super::*;

    /// The hard limit of this test process.
    #[allow(clippy::unnecessary_cast)]
    fn hard_here() -> u64 {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: a read of this process's limit into a struct of its own.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
        limit.rlim_max as u64
    }

    /// `cmd`, its child started with these soft and hard limits of open files.
    #[allow(clippy::unnecessary_cast)]
    fn limited(mut cmd: Command, soft: u64, hard: u64) -> Command {
        let limit = libc::rlimit { rlim_cur: soft as libc::rlim_t, rlim_max: hard as libc::rlim_t };
        // SAFETY: setrlimit is async-signal-safe, and changes the child alone.
        unsafe {
            cmd.pre_exec(move || match libc::setrlimit(libc::RLIMIT_NOFILE, &limit) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            });
        }
        cmd
    }

    #[test]
    fn a_soft_limit_below_the_hard_one_is_raised_to_it() {
        let hard = hard_here().min(4096);
        if hard <= 64 {
            eprintln!("skipped: this host's hard limit of open files is {hard}, with no room above 64");
            return;
        }
        let home = scratch("nofile-raised");
        let (rc, out, err) = ran(limited(command(&home, "status", &[], &[]), 64, hard));
        assert_eq!(rc, 0, "{err}");
        let doc = one_line(&out);
        let files = &doc["open_files"];
        assert_eq!(files["at_start"], 64, "{out}");
        assert_eq!(files["soft"], hard, "raised to the hard limit: {out}");
        assert_eq!(files["hard"], hard, "{out}");
        assert_eq!(files["raised"], true, "{out}");
        assert!(files["refused"].is_null(), "{out}");
    }

    #[test]
    fn a_hard_limit_at_the_soft_one_keeps_it_and_v_says_so() {
        let home = scratch("nofile-kept");
        let (rc, out, err) = ran(limited(command(&home, "status", &[], &[]), 64, 64));
        assert_eq!(rc, 0, "{err}");
        let files = &one_line(&out)["open_files"];
        let shown = (files["soft"].as_u64(), files["at_start"].as_u64(), files["raised"].as_bool());
        assert_eq!(shown, (Some(64), Some(64), Some(false)), "{out}");
        // Offline, the run ends before a session; -v says the limit once,
        // before its first line.
        let args = ["-v", "-o", "BatchMode=yes", "tester@unreachable.example", "true"];
        let (rc, _, err) = ran(limited(command(&home, "ssh", &args, &[]), 64, 64));
        assert_ne!(rc, 0, "offline, no session: {err}");
        let said: Vec<&str> = err.lines().filter(|line| line.contains("open file limit")).collect();
        assert_eq!(said, ["podssh: open file limit: 64, the hard limit of this host"], "{err}");
        assert!(err.lines().next().is_some_and(|line| line.contains("open file limit")), "said first: {err}");
    }
}
