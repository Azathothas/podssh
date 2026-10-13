//! `podssh containers` (T-190) through the binary: the refusals of the
//! command line (64) before anything connects, offline; and against the
//! test's SSH server on the loopback, whose `containers-...` users answer
//! the list's script as a host with docker and kubectl answers it
//! (`ssh_harness/containers.rs`): a line for each container with the
//! command that enters it, a tool that fails beside one that lists, a name
//! that a shell would read, a host with no tool, and `--exec` on the same
//! connection, with the command that it sends. Against OpenSSH and Dropbear,
//! with stand-ins of docker and kubectl, it runs in the gate
//! (`scripts/interop-containers.sh`).

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-containers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh containers` with `args`, its home in `home`, with no settings
/// file and no ssh_config: (exit code, stdout, stderr).
fn containers(home: &Path, args: &[&str], offline: bool) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("containers")
        .args(args)
        .current_dir(home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    if offline {
        cmd.env("PODSSH_OFFLINE", "1");
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

#[test]
fn a_bad_command_line_is_64_before_anything_connects() {
    let home = scratch("refused");
    for (args, says) in [
        (&[][..], "give the host"),
        (&["--exec", "a;b", "h"][..], "--exec \"a;b\""),
        (&["--exec", "pod/", "h"][..], "--exec \"pod/\""),
        (&["--exec", "web", "--shell", "sh -x", "h"][..], "--shell \"sh -x\""),
        (&["--shell", "bash", "h"][..], "give --exec NAME too"),
        (&["-t", "h"][..], "give --exec NAME too"),
        (&["--tool", "lxc", "h"][..], "--tool lxc"),
        (&["h", "ls"][..], "'ls'"),
        (&["node://lab"][..], "node://"),
        (&["--no-such-flag", "h"][..], "--no-such-flag"),
    ] {
        let (code, out, err) = containers(&home, args, true);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}

#[test]
fn offline_the_host_is_not_reached_and_the_exit_is_255() {
    let home = scratch("offline");
    let (code, out, err) = containers(&home, &["--direct", "u@web.example.org"], true);
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty() && err.contains("PODSSH_OFFLINE"), "{out}{err}");
}

/// The test's server on a runtime of its own: the runtime, its port, and
/// the count of the connections that it took.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, connections) = runtime.block_on(ssh_harness::start_counting(&key));
    (runtime, port, connections)
}

/// `podssh containers` on the loopback, as `user`, with `flags` before the
/// destination.
fn on(home: &Path, port: u16, user: &str, flags: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts").display().to_string();
    let destination = format!("{user}@127.0.0.1:{port}");
    let mut args = vec!["--direct", "-o", "StrictHostKeyChecking=accept-new", "-o"];
    let known = format!("UserKnownHostsFile={known}");
    args.push(&known);
    args.extend_from_slice(flags);
    args.push(&destination);
    containers(home, &args, false)
}

/// The words of a line, split as a POSIX shell splits words in single
/// quotes and none else, as `list::word` writes them.
fn words(line: &str) -> Vec<String> {
    let (mut out, mut word, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in line.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                any = true;
            }
            ' ' if !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                }
                any = false;
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(word);
    }
    out
}

#[test]
fn each_container_has_a_line_with_the_command_that_enters_it() {
    let home = scratch("list");
    let (_runtime, port, _) = server(&home);
    let (code, out, err) = on(&home, port, "containers-a", &[]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 5, "{out}");
    assert!(!out.contains("Welcome"), "the login's own line is no container: {out}");
    for (line, tool, name) in [
        (lines[0], "docker", "web"),
        (lines[3], "kubectl", "pod/api-7d9f8c6b5-x2x9k"),
        (lines[4], "kubectl", "pod/worker-0"),
    ] {
        let words = words(line);
        assert_eq!((words[0].as_str(), words[1].as_str()), (tool, name), "{line}");
        // The command parses as podssh ssh, with the destination and the
        // exec of that container.
        assert_eq!(&words[2..5], ["podssh", "ssh", "-t"], "{line}");
        let parsed = podssh_cli::parse(&words[3..]);
        let podssh_cli::Parsed::Command { ssh: Some(ssh), .. } = &parsed else { panic!("{line}: {parsed:?}") };
        assert_eq!(ssh.destination, Some(format!("containers-a@127.0.0.1:{port}")), "{line}");
        assert!(ssh.direct && ssh.tty == 1, "{line}");
        let mut want = vec![tool.to_string(), "exec".into(), "-it".into(), name.to_string()];
        if tool == "kubectl" {
            want.push("--".into());
        }
        want.push("sh".into());
        assert_eq!(ssh.command, want, "{line}");
    }
    // --tool: one tool alone.
    let (code, out, err) = on(&home, port, "containers-a", &["--tool", "kubectl"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 2, "{out}");
    assert!(out.lines().all(|l| l.starts_with("kubectl  pod/")), "{out}");
}

#[test]
fn a_tool_that_fails_says_so_and_the_others_go_on() {
    let home = scratch("denied");
    let (_runtime, port, _) = server(&home);
    let (code, out, err) = on(&home, port, "containers-denied-a", &[]);
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("podssh: docker: permission denied while trying to connect"), "{err}");
    assert!(err.contains("docker failed with exit status 1"), "{err}");
    assert_eq!(out.lines().count(), 2, "{out}");
    assert!(out.lines().all(|l| l.starts_with("kubectl")), "{out}");
}

/// The plant of the entry: with no check of the names, `a;b` would be
/// listed, in a command that a shell would split.
#[test]
fn a_name_that_a_shell_would_read_is_left_out_with_65() {
    let home = scratch("bad");
    let (_runtime, port, _) = server(&home);
    let (code, out, err) = on(&home, port, "containers-bad-a", &[]);
    assert_eq!(code, 65, "{err}");
    assert!(!out.contains("a;b"), "{out}");
    assert!(out.lines().any(|l| l.starts_with("docker   web ")), "{out}");
    assert!(err.contains("docker lists \"a;b\", which is no name"), "{err}");
}

#[test]
fn a_host_with_no_tool_exits_69() {
    let home = scratch("none");
    let (_runtime, port, _) = server(&home);
    let (code, out, err) = on(&home, port, "containers-none-a", &[]);
    assert_eq!((code, out.as_str()), (69, ""), "{err}");
    assert!(err.contains("none of docker, podman and kubectl is on the PATH"), "{err}");
    let (code, _, err) = on(&home, port, "containers-none-a", &["--tool", "podman"]);
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("podman is not on the PATH"), "{err}");
}

#[test]
fn exec_enters_the_container_on_the_same_connection() {
    let home = scratch("exec");
    let (_runtime, port, connections) = server(&home);
    // No terminal here: no pty, and -i alone.
    let (code, out, err) = on(&home, port, "containers-a", &["--exec", "web"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "entered: docker exec -i web sh\n", "{err}");
    assert_eq!(connections.load(Ordering::SeqCst), 1, "the list and the session on one connection");
    // -tt: a pty with none here, and -it; a pod by its name alone.
    let (code, out, err) = on(&home, port, "containers-a", &["-tt", "--exec", "worker-0", "--shell", "/bin/bash"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("entered: kubectl exec -it pod/worker-0 -- /bin/bash"), "{out}{err}");
    // A name that no list has.
    let (code, out, err) = on(&home, port, "containers-a", &["--exec", "nope"]);
    assert_eq!((code, out.as_str()), (69, ""), "{err}");
    assert!(err.contains("no container nope on 127.0.0.1: docker and kubectl"), "{err}");
}
