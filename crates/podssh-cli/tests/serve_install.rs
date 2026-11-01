//! `podssh node NAME TARGET --install` and `--uninstall` (T-121), and
//! `podssh ssh --install NAME -N -R ... --persist` (T-393), as processes, in
//! a scratch HOME. On Unix, fake `systemctl`, `launchctl` and `crontab`
//! programs on PATH, made of shell builtins, record their words and keep the
//! table: the user unit, the LaunchAgent and the lines of the crontab hold
//! the binary's absolute path and NAME, and no token of the pair or of the
//! environment; `--uninstall` leaves each file of the home as it was. On
//! each system, with none of them, the command to run at login and 69. The
//! variables of `--env-file` reach the node before anything else, and a
//! second run of a service ends at once while the first holds its lock.

mod pair_harness;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
/// The units and the crontab that name it are of Unix.
#[cfg(unix)]
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

    /// `launchctl print gui/UID` answers, as in a login session at the
    /// screen, and each other step passes.
    pub const LAUNCHCTL: &str = "exit 0";

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
    assert!(err.contains("two lines of the crontab: one at boot, and one each 5 minutes"), "{err}");
    assert!(err.contains("to start it now:"), "{err}");
    let table = std::fs::read_to_string(side.join("table")).unwrap();
    let env_file = pair_harness::cache_dir(&home).join("node-lab.env");
    let command = format!("{} node lab 127.0.0.1:22 --plain --env-file {}", exe(), env_file.display());
    assert!(table.starts_with("MAILTO=tester\n0 3 * * * backup\n# podssh node lab --install"), "{table}");
    // T-393: the watchdog beside the line at boot.
    assert!(table.ends_with(&format!("@reboot {command}\n*/5 * * * * {command}\n")), "{table}");
    clean(&table);
    // Again: two lines, never four.
    let (code, _, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--plain", "--install"], &vars);
    assert_eq!(code, 0, "{err}");
    let table = std::fs::read_to_string(side.join("table")).unwrap();
    assert!(table.matches("@reboot").count() == 1 && table.matches("*/5 * * * *").count() == 1, "{table}");
    let (code, _, err) = run(&home, &["node", "lab", "--uninstall"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed its lines of the crontab"), "{err}");
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

/// T-393: where launchctl has this user's login session, a LaunchAgent that
/// keeps the node alive, loaded in it; `--uninstall` boots it out and
/// leaves the home as it was.
#[cfg(unix)]
#[test]
fn a_launch_agent_where_launchctl_has_a_login_session() {
    let (home, bin, side) = home("install-launchd");
    fakes::fake(&bin, "launchctl", fakes::LAUNCHCTL);
    fakes::fake(&bin, "crontab", fakes::CRONTAB);
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let (code, out, err) = run(&home, &["node", "lab", "127.0.0.1:22", "--install"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("a LaunchAgent") && err.contains("loaded in gui/"), "{err}");
    clean(&err);
    let path = home.join("Library/LaunchAgents/dev.podssh.node.lab.plist");
    let agent = std::fs::read_to_string(&path).unwrap();
    let (exe, env_file) = (exe(), pair_harness::cache_dir(&home).join("node-lab.env").display().to_string());
    for word in [exe.as_str(), "node", "lab", "127.0.0.1:22", "--env-file", env_file.as_str()] {
        assert!(agent.contains(&format!("    <string>{word}</string>\n")), "{word}: {agent}");
    }
    assert!(agent.contains("<key>KeepAlive</key>\n  <true/>") && agent.contains("<key>RunAtLoad</key>"), "{agent}");
    clean(&agent);
    let log = std::fs::read_to_string(side.join("log")).unwrap();
    assert!(log.lines().any(|l| l.starts_with("launchctl print gui/")), "{log}");
    let plist = path.display().to_string();
    assert!(log.lines().any(|l| l.starts_with("launchctl bootstrap gui/") && l.ends_with(&plist)), "{log}");
    // The crontab is another way, which the agent leaves alone.
    assert!(!side.join("table").exists());
    let bootouts = |log: &str| {
        log.lines().filter(|l| l.starts_with("launchctl bootout gui/") && l.ends_with("/dev.podssh.node.lab")).count()
    };
    assert_eq!(bootouts(&log), 1, "an older load, before the bootstrap: {log}");
    let (code, _, err) = run(&home, &["node", "lab", "--uninstall"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed the LaunchAgent") && err.contains("(stopped)"), "{err}");
    assert_eq!(bootouts(&std::fs::read_to_string(side.join("log")).unwrap()), 2);
    assert_eq!(files(&home), before, "--uninstall left something: {err}");
}

/// T-393: a reverse tunnel of `podssh ssh -N -R --persist` as a user unit:
/// the words as typed but `--install NAME`, after the options of a service
/// and its file of variables, in the directory where they were typed.
#[cfg(unix)]
#[test]
fn a_tunnel_of_ssh_becomes_a_user_unit_of_its_typed_words() {
    let (home, bin, side) = home("install-ssh");
    fakes::fake(&bin, "systemctl", fakes::SYSTEMCTL);
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let words = ["ssh", "--install", "bastion", "-N", "-R", "2222:127.0.0.1:22", "--persist", "me@example.org"];
    let (code, out, err) = run(&home, &words, &vars);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("podssh ssh: bastion: a user unit of systemd") && err.contains("BatchMode=yes"), "{err}");
    clean(&err);
    let unit = std::fs::read_to_string(home.join("config/systemd/user/podssh-ssh-bastion.service")).unwrap();
    let env_file = pair_harness::cache_dir(&home).join("ssh-bastion.env");
    let exec = format!(
        "ExecStart={} ssh -o BatchMode=yes -o ForkAfterAuthentication=no -o ControlPath=none -o \
         ExitOnForwardFailure=yes --env-file {} --persist-forever -N -R 2222:127.0.0.1:22 --persist \
         me@example.org\n",
        exe(),
        env_file.display()
    );
    assert!(unit.contains(&exec), "{unit}");
    let dir = std::env::current_dir().unwrap();
    assert!(unit.contains(&format!("\nWorkingDirectory=-{}\n", dir.display())), "{unit}");
    assert!(unit.contains("\nRestart=always\n"), "{unit}");
    clean(&unit);
    let log = std::fs::read_to_string(side.join("log")).unwrap();
    assert!(log.contains("systemctl --user restart podssh-ssh-bastion.service\n"), "{log}");
    let (code, _, err) = run(&home, &["ssh", "--uninstall", "bastion"], &vars);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("removed the user unit") && err.contains("removed the file of its variables"), "{err}");
    assert_eq!(files(&home), before, "--uninstall left something: {err}");
}

#[test]
fn what_cannot_be_a_tunnel_s_service_is_refused_and_nothing_is_written() {
    let (home, bin, side) = home("install-ssh-refused");
    let vars = vars(&home, &bin, &side);
    let before = files(&home);
    let r = "2222:127.0.0.1:22";
    let cases: [(&[&str], &str); 8] = [
        (&["ssh", "--install", "b", "--persist", "-R", r, "me@example.org"], "give -N"),
        (&["ssh", "--install", "b", "-N", "-R", r, "me@example.org"], "needs --persist"),
        (&["ssh", "--install", "b", "-N", "-f", "--persist", "-R", r, "me@example.org"], "--install with -f"),
        (&["ssh", "--install", "b", "--uninstall", "b"], "give one"),
        (&["ssh", "--install", "b", "--env-file", "x", "-N"], "--env-file is the file"),
        (&["ssh", "--install", ".b", "-N", "--persist", "-R", r, "me@example.org"], "a name of letters"),
        (&["ssh", "--install", "b", "-N", "--persist", "-R", r], "missing destination"),
        (&["ssh", "--install", "b", "-N", "--persist", "me@example.org"], "give -R, -L or -D"),
    ];
    for (args, says) in cases {
        let (code, _, err) = run(&home, args, &vars);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    assert_eq!(files(&home), before);
}

/// T-393: a run of a service whose lock another run holds (here the test)
/// ends at once with 0, and says nothing to a pipe, where a second node
/// would meet the first at the relay; with the lock free, the same run goes
/// on, to the offline node's 69.
#[test]
fn a_second_start_of_a_service_ends_at_once_while_its_lock_is_held() {
    let (home, bin, side) = home("install-lock");
    let vars = vars(&home, &bin, &side);
    let file = side.join("vars.env");
    std::fs::write(&file, "# a service's variables\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let shown = file.display().to_string();
    let node = ["node", "lab", "127.0.0.1:22", "--env-file", shown.as_str()];
    let (code, _, err) = run(&home, &node, &vars);
    assert_eq!(code, 69, "the control: the lock is free, and the node is offline: {err}");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(side.join("vars.env.lock"))
        .unwrap();
    lock.try_lock().expect("the test holds the lock");
    let started = Instant::now();
    let (code, out, err) = run(&home, &node, &vars);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty() && err.is_empty(), "a pipe hears nothing: {out}{err}");
    let ssh = ["ssh", "--env-file", shown.as_str(), "-N", "-R", "2222:127.0.0.1:22", "me@example.org"];
    let (code, out, err) = run(&home, &ssh, &vars);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty() && err.is_empty(), "{out}{err}");
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    drop(lock);
}
