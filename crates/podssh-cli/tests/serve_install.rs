//! `podssh node NAME TARGET --install` and `--uninstall` (T-121) as
//! processes, in a scratch HOME. On Unix, fake `systemctl` and `crontab`
//! programs on PATH, made of shell builtins, record their words and keep the
//! table: the user unit and the line of the crontab hold the binary's
//! absolute path and NAME, and no token of the pair or of the environment;
//! `--uninstall` leaves each file of the home as it was. On each system,
//! with neither program, the command to run at login and 69. The variables
//! of `--env-file` reach the node before anything else.

mod pair_harness;

use std::path::{Path, PathBuf};

use pair_harness::{no_token, podssh, scratch, store};

/// A relay token in the environment, which no service may keep.
const ENV_TOKEN: &str = "ephm1.9999999999999.forward.TESTONLYNOTACREDENTIALENV";

/// Each file under `dir`, with its bytes, in order: what the runs left.
fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(next) = dirs.pop() {
        for entry in std::fs::read_dir(&next).unwrap().map(Result::unwrap) {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    found.sort();
    found
}

/// A proxy URL with a password, made here so that no scanner reads one.
fn proxy_with_password() -> String {
    format!("http://{}:{}@proxy.example:3128", "alice", "s3cr3t-pass")
}

/// The variables of each run: PATH, the place of user units, a proxy with
/// a password and a relay token.
fn vars(home: &Path, bin: &Path, side: &Path) -> Vec<(String, String)> {
    [
        ("PATH", bin.display().to_string()),
        ("XDG_CONFIG_HOME", home.join("config").display().to_string()),
        ("https_proxy", proxy_with_password()),
        ("PODSSH_RELAY_TOKEN", ENV_TOKEN.to_string()),
        ("FAKE_LOG", side.join("log").display().to_string()),
        ("FAKE_TABLE", side.join("table").display().to_string()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v))
    .collect()
}

fn run(home: &Path, args: &[&str], vars: &[(String, String)]) -> (i32, String, String) {
    let set: Vec<(&str, &str)> = vars.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    podssh(home, args, &set)
}

/// The binary as the service names it: `current_exe`, which resolves links.
fn exe() -> String {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_podssh")).unwrap().display().to_string()
}

/// What a text that a service reads must not hold: a token, the password.
fn clean(text: &str) {
    no_token(text);
    assert!(!text.contains(ENV_TOKEN) && !text.contains("s3cr3t"), "{text}");
}

#[cfg(unix)]
mod fakes {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// A program on PATH that logs its words, then runs `body`.
    pub fn fake(bin: &Path, name: &str, body: &str) {
        let path = bin.join(name);
        let script = format!("#!/bin/sh\nprintf '%s\\n' \"{name} $*\" >> \"$FAKE_LOG\"\n{body}\n");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    pub const SYSTEMCTL: &str = "[ \"$2\" = show-environment ] && echo HOME=/home/tester\nexit 0";

    /// `crontab -l` prints the table, or says that there is none;
    /// `crontab FILE` makes FILE the table.
    pub const CRONTAB: &str = r#"if [ "$1" = -l ]; then
  [ -f "$FAKE_TABLE" ] || { echo "no crontab for tester" >&2; exit 1; }
  while IFS= read -r line; do printf '%s\n' "$line"; done < "$FAKE_TABLE"
  exit 0
fi
while IFS= read -r line; do printf '%s\n' "$line"; done < "$1" > "$FAKE_TABLE""#;
}

/// A scratch HOME with the pair `lab`, its PATH directory, and a directory
/// beside it for what the fakes keep.
fn home(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = scratch(tag);
    let side = scratch(&format!("{tag}-side"));
    let bin = side.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    store(&home, "lab", 0);
    (home, bin, side)
}

#[cfg(unix)]
#[test]
fn a_user_unit_holds_the_path_and_the_name_and_no_token() {
    let (home, bin, side) = home("install-unit");
    fakes::fake(&bin, "systemctl", fakes::SYSTEMCTL);
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let (code, out, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--install"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("a user unit of systemd") && err.contains("enabled and started"), "{err}");
    clean(&err);
    let unit = std::fs::read_to_string(home.join("config/systemd/user/podssh-node-lab.service")).unwrap();
    let env_file = pair_harness::cache_dir(&home).join("node-lab.env");
    let exec = format!("ExecStart={} node lab 127.0.0.1:22 --env-file {}\n", exe(), env_file.display());
    assert!(unit.contains(&exec), "{unit}");
    clean(&unit);
    // The variables are in a private file: the proxy, with its password, and
    // no token.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&env_file).unwrap().permissions().mode() & 0o777, 0o600);
    let env = std::fs::read_to_string(&env_file).unwrap();
    assert!(env.contains(&format!("\nhttps_proxy={}\n", proxy_with_password())), "{env}");
    no_token(&env);
    assert!(!env.contains(ENV_TOKEN) && err.contains("PODSSH_RELAY_TOKEN is set and is not carried"), "{env}{err}");
    let log = std::fs::read_to_string(side.join("log")).unwrap();
    for step in ["--user show-environment", "--user daemon-reload", "--user enable podssh-node-lab.service"] {
        assert!(log.contains(&format!("systemctl {step}\n")), "{step}: {log}");
    }
    assert!(log.contains("systemctl --user restart podssh-node-lab.service\n"), "{log}");
    let (code, _, err) = run(&home, &["node", "lab", "--uninstall"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed the user unit") && err.contains("stopped and disabled"), "{err}");
    assert!(std::fs::read_to_string(side.join("log"))
        .unwrap()
        .contains("--user disable --now podssh-node-lab.service"));
    assert_eq!(files(&home), before, "--uninstall left something: {err}");
}

#[cfg(unix)]
#[test]
fn with_no_systemd_a_line_of_the_crontab_and_the_user_s_lines_kept() {
    let (home, bin, side) = home("install-cron");
    fakes::fake(&bin, "crontab", fakes::CRONTAB);
    std::fs::write(side.join("table"), "MAILTO=tester\n0 3 * * * backup\n").unwrap();
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let (code, _, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--plain", "--install"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("no systemctl on PATH") || err.contains("an @reboot line of the crontab"), "{err}");
    assert!(err.contains("to start the node now:"), "{err}");
    let table = std::fs::read_to_string(side.join("table")).unwrap();
    let env_file = pair_harness::cache_dir(&home).join("node-lab.env");
    let line = format!("@reboot {} node lab 127.0.0.1:22 --plain --env-file {}\n", exe(), env_file.display());
    assert!(table.starts_with("MAILTO=tester\n0 3 * * * backup\n# podssh node lab --install"), "{table}");
    assert!(table.ends_with(&line), "{table}");
    clean(&table);
    // Again: one line, never two.
    let (code, _, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--plain", "--install"], &vars);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(side.join("table")).unwrap().matches("@reboot").count(), 1);
    let (code, _, err) = run(&home, &["node", "lab", "--uninstall"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed its line of the crontab"), "{err}");
    assert_eq!(std::fs::read_to_string(side.join("table")).unwrap(), "MAILTO=tester\n0 3 * * * backup\n");
    assert_eq!(files(&home), before, "--uninstall left something: {err}");
}

/// With no way, the command to run at login on stdout, and 69; the file of
/// variables that it names stays until `--uninstall`.
#[test]
fn with_no_way_the_command_to_run_at_login_and_69() {
    let (home, bin, side) = home("install-none");
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let (code, out, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--install"], &vars);
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("no service of this user can be made here"), "{err}");
    assert!(out.contains(" node lab 127.0.0.1:22 --env-file ") && out.contains("node-lab.env"), "{out}");
    clean(&out);
    let (code, _, err) = run(&home, &["node", "lab", "--uninstall"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed the file of its variables"), "{err}");
    assert_eq!(files(&home), before);
}

#[test]
fn what_cannot_be_a_service_is_refused_and_nothing_is_written() {
    let (home, bin, side) = home("install-refused");
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let cases: [(&[&str], i32, &str); 5] = [
        (&["node", "lab", "--install", "--ephemeral-key"], 64, "a new key"),
        (&["node", "lab", "--install", "--uninstall"], 64, "give one"),
        (&["node", "lab", "--install", "--env-file", "x"], 64, "--env-file is the file"),
        (&["node", "--install"], 64, "NAME"),
        (&["node", "nopair", "127.0.0.1:22", "--install"], 78, "no pair is stored"),
    ];
    for (args, want, says) in cases {
        let (code, _, err) = run(&home, args, &vars);
        assert_eq!(code, want, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    assert_eq!(files(&home), before);
}

/// `--env-file` is read before the node: `PODSSH_CACHE_DIR=none` there hides
/// the stored pair, which the node then cannot find (78, where it would be
/// offline, 69).
#[test]
fn the_variables_of_env_file_reach_the_node_first() {
    let (home, bin, side) = home("env-file");
    let vars = vars(&home, &bin, &side);
    let (code, _, err) = run(&home, &["node", "lab", "127.0.0.1:22"], &vars);
    assert_eq!(code, 69, "the control: the pair is found, and the node is offline: {err}");
    let file = side.join("vars.env");
    std::fs::write(&file, "# test\nPODSSH_CACHE_DIR=none\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, _, err) =
            run(&home, &["node", "lab", "127.0.0.1:22", "--env-file", &file.display().to_string()], &vars);
        assert_eq!(code, 78, "a file that others can read: {err}");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (code, _, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--env-file", &file.display().to_string()], &vars);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("no pair is stored under \"lab\""), "{err}");
    std::fs::write(&file, "PODSSH_RELAY_TOKEN=x\n").unwrap();
    let (code, _, err) = run(&home, &["node", "lab", "--env-file", &file.display().to_string()], &vars);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("line 1: PODSSH_RELAY_TOKEN is a token"), "{err}");
}
