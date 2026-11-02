//! The login name with no variable (T-500), a module of `tests/ssh_args.rs`,
//! whose own file is near 500 lines. Resolved: the user database's entry is
//! the login and `-v` says so; a host with none refuses with what was read.
//! Against the binary: `podssh ssh -G` with `PODSSH_USER`, `USER`, `LOGNAME`
//! and `USERNAME` removed prints the effective uid's entry as its `user`
//! line, and `PODSSH_USER` beats `USER`. The plant of the entry, the entry
//! never read, fails the test of the binary with a refusal.

use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env, UserFrom};

#[test]
fn the_user_database_entry_is_the_login_and_v_says_where_it_came_from() {
    let entry = Env { user: Some("agent".into()), user_from: UserFrom::Entry { uid: 1000 }, ..super::env() };
    let r = resolve(&super::ssh(&["host"]), &entry).unwrap();
    assert_eq!(r.options.user, "agent");
    assert!(r.notes.iter().any(|n| n.contains("agent is uid 1000's entry")), "{:?}", r.notes);
    // A variable needs no line.
    let r = resolve(&super::ssh(&["host"]), &super::env()).unwrap();
    assert!(!r.notes.iter().any(|n| n.contains("local user name")), "{:?}", r.notes);

    let missing = Env { user: None, user_from: UserFrom::Missing { uid: Some(1000) }, ..super::env() };
    let refusal = resolve_or_refuse(&super::ssh(&["host"]), &missing).unwrap_err();
    assert_eq!(refusal.code, 64, "{}", refusal.message);
    for said in ["uid 1000 has no entry", "-l USER", "PODSSH_USER", "set PODSSH_USER or USER"] {
        assert!(refusal.message.contains(said), "{said}: {}", refusal.message);
    }
    // A jump host with no user is refused as the destination is.
    let refusal = resolve_or_refuse(&super::ssh(&["-J", "hop.example", "u@host"]), &missing).unwrap_err();
    assert_eq!(refusal.code, 64, "{}", refusal.message);
    assert!(refusal.message.starts_with("no user name for the jump host hop.example: "), "{}", refusal.message);
    // A name given on the command line needs none.
    assert_eq!(resolve(&super::ssh(&["-l", "given", "host"]), &missing).unwrap().options.user, "given");
}

#[cfg(unix)]
mod binary {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    /// The run to its end within 30 s: a run that waits must fail the test,
    /// not hold it.
    fn within(cmd: &mut Command) -> Output {
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("no end within 30 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().unwrap()
    }

    /// The entries of `/etc/passwd`, read apart from podssh: `(uid, name)`.
    fn entries() -> Vec<(u32, String)> {
        let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let fields = |line: &str| line.split(':').map(str::to_string).collect::<Vec<_>>();
        text.lines()
            .filter(|line| !line.starts_with(['#', '+', '-']))
            .map(fields)
            .filter(|f| f.len() >= 7 && !f[0].is_empty() && !f[0].contains(char::is_whitespace))
            .filter_map(|f| Some((f[2].parse::<u32>().ok()?, f[0].clone())))
            .collect()
    }

    /// The name of `uid`'s entry: the first line of `/etc/passwd` for it; on
    /// macOS, whose users are in the system's directory, what `id` says.
    fn entry_name(uid: u32) -> Option<String> {
        if cfg!(target_os = "macos") {
            let out = within(Command::new("id").args(["-un", &uid.to_string()]));
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return (out.status.success() && !name.is_empty()).then_some(name);
        }
        entries().into_iter().find(|(u, _)| *u == uid).map(|(_, name)| name)
    }

    /// The uid that the run takes, and its entry's name. As root, another
    /// uid with an entry: uid 0's name and podssh's fallback for uid 0 are
    /// both root, which would hide an entry that was never read.
    fn subject() -> (u32, Option<String>) {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if me != 0 {
            return (me, entry_name(me));
        }
        match entries().into_iter().find(|(uid, _)| *uid != 0) {
            Some((uid, name)) => (uid, Some(name)),
            None => (0, entry_name(0)),
        }
    }

    /// `podssh ssh -G` of a host as `uid`, with each user variable removed
    /// and `set` given; no ssh_config and no settings file of the machine.
    fn print_config(uid: u32, set: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["ssh", "-G", "-F", "none", "host.example"]);
        for name in ["PODSSH_USER", "USER", "LOGNAME", "USERNAME"] {
            cmd.env_remove(name);
        }
        cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("PODSSH_OFFLINE", "1");
        // A home that the uid of the run may read.
        cmd.env("HOME", std::env::temp_dir()).envs(set.iter().copied());
        // SAFETY: geteuid has no preconditions and cannot fail.
        if uid != unsafe { libc::geteuid() } {
            cmd.uid(uid);
        }
        within(&mut cmd)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn with_no_variable_the_login_name_is_the_user_database_entry_of_the_uid() {
        let (uid, name) = subject();
        let out = print_config(uid, &[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        match name.or_else(|| (uid == 0).then(|| "root".to_string())) {
            Some(name) => {
                assert_eq!(out.status.code(), Some(0), "uid {uid}, whose entry is {name}: {stderr}");
                assert!(stdout.lines().any(|l| l == format!("user {name}")), "uid {uid} is {name}: {stdout}");
            }
            None => {
                assert_eq!(out.status.code(), Some(64), "uid {uid} has no entry: {stdout}{stderr}");
                assert!(stderr.contains(&format!("uid {uid} has no entry")), "{stderr}");
                assert!(stderr.contains("PODSSH_USER") && stderr.contains("-l USER"), "{stderr}");
            }
        }
    }

    #[test]
    fn podssh_user_names_the_login_before_user_and_the_user_database() {
        let (uid, _) = subject();
        let out = print_config(uid, &[("PODSSH_USER", "named-by-podssh"), ("USER", "named-by-user")]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(stdout.lines().any(|l| l == "user named-by-podssh"), "{stdout}");
        let out = print_config(uid, &[("USER", "named-by-user")]);
        assert!(text(&out.stdout).lines().any(|l| l == "user named-by-user"), "{}", text(&out.stderr));
    }
}
