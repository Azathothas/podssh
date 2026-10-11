//! `-W /PATH` (T-040): how `-W` is read, and a Unix socket on the server,
//! against the test's SSH server, which opens the socket `/echo` as
//! direct-streamlocal and sends back what it gets; another socket it
//! refuses.

mod cleanup;
mod ssh_harness;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env};
use podssh_cli::tree::{parse, Parsed};
use podssh_ssh::{Request, RequestTty, StdioTarget};

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

/// The command line alone: no ssh_config file.
fn env() -> Env {
    Env {
        home: Some(PathBuf::from("/home/u")),
        user: Some("envuser".into()),
        ssh_config: Some("none".into()),
        ..Default::default()
    }
}

/// `-W HOST:PORT`, or the absolute path of a Unix socket on the server, as
/// OpenSSH reads `-W /PATH` (T-040); a value with no port, or a relative
/// path, is refused.
#[test]
fn stdio_forward_socket_or_host_and_port() {
    for (value, says) in [
        ("tmp/sock", "the absolute path of a Unix socket"),
        ("db.internal", "expected HOST:PORT"),
        ("5432", "expected HOST:PORT"),
        ("db.internal:", "expected HOST:PORT"),
        ("[::1]", "expected HOST:PORT"),
        ("2001:db8::1", "an IPv6 address needs brackets"),
    ] {
        let err = resolve_or_refuse(&ssh(&["-W", value, "host"]), &env()).unwrap_err();
        assert_eq!(err.code, 64, "{value}");
        assert!(err.message.starts_with(&format!("-W {value}: ")), "{value}: {}", err.message);
        assert!(err.message.contains(says), "{value}: {}", err.message);
    }
    for (value, host, port) in [("db.internal:5432", "db.internal", 5432), ("[::1]:5432", "::1", 5432)] {
        let r = resolve(&ssh(&["-W", value, "host"]), &env()).unwrap_or_else(|e| panic!("{value}: {e}"));
        assert_eq!(r.options.request, Request::StdioForward(StdioTarget::Tcp { host: host.into(), port }), "{value}");
    }
    for path in ["/tmp/s", "/run/postgresql/.s.PGSQL.5432", "/tmp/sock:22"] {
        let r = resolve(&ssh(&["-W", path, "host"]), &env()).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(r.options.request, Request::StdioForward(StdioTarget::Socket(path.into())), "{path}");
        assert_eq!(r.options.request_tty, RequestTty::No);
    }
    // A -J hop keeps its own reading: a host alone is port 22.
    let r = resolve(&ssh(&["-J", "jump.example", "-W", "db:5432", "host"]), &env()).unwrap();
    assert_eq!(r.options.jump[0].port, 22);
}

/// `podssh ssh --direct -v -W PATH u@127.0.0.1` with `input`: the exit code,
/// stdout and stderr.
fn stdio(dir: &std::path::Path, port: u16, path: &str, input: &[u8]) -> (Option<i32>, Vec<u8>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-v", "-p", &port.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(["-W", path, "u@127.0.0.1"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code(), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The server's socket answers on stdin and stdout; a socket that the
/// server refuses ends the run with 255 and names it.
#[test]
fn stdio_forward_socket_reaches_the_servers_socket() {
    let dir = std::env::temp_dir().join(format!("podssh-stdio-socket-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));

    let (code, out, err) = stdio(&dir, port, "/echo", b"ping over a socket\n");
    assert_eq!((code, out.as_slice()), (Some(0), &b"ping over a socket\n"[..]), "{err}");
    let (code, _, err) = stdio(&dir, port, "/no-such.sock", b"");
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("could not open a connection to the socket /no-such.sock"), "{err}");
    assert!(err.contains("-W /no-such.sock: 0 connections (0 open, 1 failed)"), "{err}");

    // T-041: with -v, the end of the run says what -W carried, each way.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = format!("127.0.0.1:{}", echo.local_addr().unwrap().port());
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = echo.accept() {
            let mut back = conn.try_clone().unwrap();
            let _ = std::io::copy(&mut conn, &mut back);
            let _ = back.shutdown(std::net::Shutdown::Write);
        }
    });
    let sent = vec![0x42u8; 262_144];
    let (code, out, err) = stdio(&dir, port, &target, &sent);
    assert_eq!((code, out.len()), (Some(0), sent.len()), "{err}");
    let line = format!("-W {target}: 1 connection (0 open, 0 failed), 262144 bytes up, 262144 bytes down");
    assert!(err.contains(&line), "{err}");
}
