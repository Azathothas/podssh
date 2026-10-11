//! podssh's settings file (T-048), through the binary and through the
//! resolution of `podssh ssh`: `PODSSH_SETTINGS`, the file below the flag
//! and the variable, a bad file refused (78) with its line, and on Unix a
//! file that others can change, or a symbolic link, refused. Nothing
//! connects.

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::resolve::{resolve, Env, Transport};
use podssh_cli::tree::{parse, Parsed};
use serde_json::Value;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-settings-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Private, as the user's own directories are: the file is checked.
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` offline, with HOME in `home` and the variables of `set`:
/// its exit code, stdout and stderr.
fn podssh(home: &Path, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    for name in [
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_FAILOVER",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_SETTINGS",
        "PODSSH_CACHE_DIR",
        "SSL_CERT_FILE",
        "XDG_CONFIG_HOME",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home).env("APPDATA", home.join("appdata")).env("PODSSH_OFFLINE", "1");
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd.envs(set.iter().copied());
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

fn status(home: &Path, args: &[&str], set: &[(&str, &str)]) -> Value {
    let mut all = vec!["status"];
    all.extend_from_slice(args);
    let (code, out, err) = podssh(home, &all, set);
    assert_eq!(code, 0, "{err}");
    serde_json::from_str(&out).expect("one line of JSON")
}

fn hosts(doc: &Value) -> Vec<String> {
    doc["relays"].as_array().unwrap().iter().map(|r| format!("{}:{}", r["host"].as_str().unwrap(), r["port"])).collect()
}

#[test]
fn status_takes_the_files_relay_hosts_below_the_flag_and_the_variable() {
    let home = scratch("status");
    let file = home.join("settings");
    std::fs::write(&file, "# podssh's own settings\nRelayHost file.example,file2.example:8443\n").unwrap();
    let path = file.display().to_string();
    let with = [("PODSSH_SETTINGS", path.as_str())];
    let doc = status(&home, &[], &with);
    assert_eq!(hosts(&doc), ["file.example:443", "file2.example:8443"]);
    assert_eq!(
        (doc["relays_from"].as_str(), doc["settings"].as_str()),
        (Some("the settings file"), Some(path.as_str()))
    );
    let doc = status(&home, &[], &[("PODSSH_SETTINGS", path.as_str()), ("PODSSH_RELAY", "env.example")]);
    assert_eq!((hosts(&doc), doc["relays_from"].as_str()), (vec!["env.example:443".to_string()], Some("PODSSH_RELAY")));
    let doc = status(
        &home,
        &["--relay-host", "flag.example"],
        &[("PODSSH_SETTINGS", path.as_str()), ("PODSSH_RELAY", "env.example")],
    );
    assert_eq!(
        (hosts(&doc), doc["relays_from"].as_str()),
        (vec!["flag.example:443".to_string()], Some("--relay-host"))
    );
    let doc = status(&home, &[], &[("PODSSH_SETTINGS", "none")]);
    assert_eq!((doc["relays_from"].as_str(), doc["settings"].is_null()), (Some("default and pool"), true));
    // The usual place: the configuration directory, here APPDATA or
    // XDG_CONFIG_HOME under the scratch home.
    let config = if cfg!(windows) { home.join("appdata") } else { home.join("xdg") };
    std::fs::create_dir_all(config.join("podssh")).unwrap();
    std::fs::write(config.join("podssh").join("settings"), "RelayHost usual.example\n").unwrap();
    let xdg = home.join("xdg").display().to_string();
    let doc = status(&home, &[], &[("XDG_CONFIG_HOME", xdg.as_str())]);
    assert_eq!(hosts(&doc), ["usual.example:443"]);
}

#[test]
fn a_bad_file_is_refused_with_its_line_and_78() {
    let home = scratch("bad");
    for (text, says) in [
        ("RelayHost a.example\nRelayHosts b.example\n", ":2: RelayHosts is not a setting of podssh"),
        ("RelayAddr not-a-pin\n", ":1: RelayAddr not-a-pin: "),
        ("RelayHost bad host!\n", ":1: RelayHost bad host!: "),
        ("RelayFailover sideways\n", ":1: RelayFailover \"sideways\" is not a mode"),
    ] {
        let file = home.join("settings");
        std::fs::write(&file, text).unwrap();
        let path = file.display().to_string();
        let (code, out, err) = podssh(&home, &["status"], &[("PODSSH_SETTINGS", path.as_str())]);
        assert_eq!(code, 78, "{text:?}: {out}{err}");
        assert!(err.contains(&format!("{path}{says}")), "{text:?}: {err}");
    }
    let (code, _, err) = podssh(&home, &["status"], &[("PODSSH_SETTINGS", "settings")]);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("give an absolute path; the working directory is never read"), "{err}");
}

#[test]
fn doctor_names_the_file() {
    let home = scratch("doctor");
    let file = home.join("settings");
    std::fs::write(&file, "RelayHost doctor.example\n").unwrap();
    let path = file.display().to_string();
    let (_, out, err) = podssh(&home, &["doctor"], &[("PODSSH_SETTINGS", path.as_str())]);
    assert!(out.contains(&format!("podssh's settings are read from {path}")), "{out}{err}");
    let (_, out, _) = podssh(&home, &["doctor"], &[("PODSSH_SETTINGS", "none")]);
    assert!(out.contains("no settings file"), "{out}");
}

/// The resolution of `podssh ssh` takes the file's relay hosts and CA file,
/// below its flags and variables.
#[test]
fn ssh_takes_the_files_relay_hosts_and_ca_file() {
    let file = podssh_cli::settings::parse("RelayHost file.example\nCaFile /file/ca.pem\n", "f", None).unwrap();
    let words = |w: &[&str]| -> SshArgs {
        let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(w.iter().copied()).map(Into::into).collect();
        match parse(argv) {
            Parsed::Command { ssh: Some(args), .. } => *args,
            other => panic!("{other:?}"),
        }
    };
    let env = Env {
        home: Some("/home/u".into()),
        user: Some("u".into()),
        ssh_config: Some("none".into()),
        settings: file.clone(),
        ..Env::default()
    };
    let relays = |args: SshArgs, env: &Env| match resolve(&args, env).unwrap().transport {
        Transport::Relay { relays, trust, .. } => (relays.hosts[0].host.clone(), format!("{trust:?}")),
        other => panic!("{other:?}"),
    };
    let (host, trust) = relays(words(&["h"]), &env);
    assert_eq!(host, "file.example");
    assert!(trust.contains("/file/ca.pem"), "{trust}");
    let env_var = Env { relay: Some("env.example".into()), ssl_cert_file: Some("/env.pem".into()), ..env.clone() };
    let (host, trust) = relays(words(&["h"]), &env_var);
    assert_eq!(host, "env.example");
    assert!(trust.contains("/env.pem"), "{trust}");
    let (host, _) = relays(words(&["--relay-host", "flag.example", "h"]), &env_var);
    assert_eq!(host, "flag.example");
}

#[cfg(unix)]
#[test]
fn on_unix_a_file_that_others_can_change_or_a_link_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let home = scratch("unix");
    let file = home.join("settings");
    std::fs::write(&file, "RelayHost unix.example\n").unwrap();
    let path = file.display().to_string();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
    let (code, _, err) = podssh(&home, &["status"], &[("PODSSH_SETTINGS", path.as_str())]);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("bad owner or permissions") && err.contains("chmod go-w"), "{err}");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = home.join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let link = link.display().to_string();
    let (code, _, err) = podssh(&home, &["status"], &[("PODSSH_SETTINGS", link.as_str())]);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("is a symbolic link, which podssh does not follow for its settings"), "{err}");
    let (code, out, err) = podssh(&home, &["status"], &[("PODSSH_SETTINGS", path.as_str())]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("unix.example"), "{out}");
}
