//! `-X` and `-Y` (T-037): the plan of the flags and keywords, the probe
//! before the connection, and an `x11` channel of the test's server to a
//! fake X server on the loopback, which must get the real cookie while the
//! server was given a spoofed one.

mod cleanup;
mod ssh_harness;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::resolve::{resolve, Env};
use podssh_cli::ssh::x11::{self, Plan};
use podssh_cli::tree::{parse, Parsed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-x11-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The last of -X, -Y and -x wins, -Y and ForwardX11Trusted trust, and a
/// run with no session asks for no X11, as OpenSSH reads them.
#[test]
fn x11_flags_and_keywords_make_a_plan() {
    let env = Env { user: Some("u".into()), ..Default::default() };
    let plan = |words: &[&str]| resolve(&ssh(words), &env).unwrap_or_else(|e| panic!("{words:?}: {e}")).x11;
    assert_eq!(plan(&["-X", "h", "true"]), Some(Plan { trusted: false, timeout: Some(x11::TIMEOUT), xauth: None }));
    assert!(plan(&["-Y", "h", "true"]).unwrap().trusted);
    assert_eq!(plan(&["-X", "-x", "h", "true"]), None);
    assert!(plan(&["-x", "-Y", "h", "true"]).is_some());
    assert!(plan(&["-o", "ForwardX11=yes", "h", "true"]).is_some());
    assert!(plan(&["-X", "-o", "ForwardX11Trusted=yes", "h", "true"]).unwrap().trusted);
    let timeout =
        |value: &str| plan(&["-X", "-o", &format!("ForwardX11Timeout={value}"), "h", "true"]).unwrap().timeout;
    assert_eq!(timeout("5m"), Some(Duration::from_secs(300)));
    assert_eq!(timeout("0"), None);
    let xauth = plan(&["-X", "-o", "XAuthLocation=/opt/xauth", "h", "true"]).unwrap().xauth;
    assert_eq!(xauth.as_deref(), Some("/opt/xauth"));
    assert_eq!(plan(&["-X", "-N", "h"]), None, "no session, no X11");
    assert_eq!(plan(&["h", "true"]), None);
}

/// A fake X server on 127.0.0.1, port 6000+N: N, and its listener.
async fn fake_x_server() -> (u16, TcpListener) {
    for n in 150..400u16 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", 6000 + n)).await {
            return (n, listener);
        }
    }
    panic!("no free port from 6150 on");
}

/// The first whole setup request that `listener` takes, answered with
/// success when its cookie is `wanted`: that cookie. A connection closed
/// before its request, as the probe's, is passed over.
async fn serve(listener: TcpListener, wanted: Vec<u8>) -> Vec<u8> {
    loop {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 12];
        if conn.read_exact(&mut head).await.is_err() {
            continue;
        }
        let (n, d) =
            (usize::from(u16::from_le_bytes([head[6], head[7]])), usize::from(u16::from_le_bytes([head[8], head[9]])));
        let pad = |x: usize| (4 - x % 4) % 4;
        let mut rest = vec![0u8; n + pad(n) + d + pad(d)];
        conn.read_exact(&mut rest).await.unwrap();
        let cookie = rest[n + pad(n)..n + pad(n) + d].to_vec();
        conn.write_all(&[u8::from(cookie == wanted)]).await.unwrap();
        return cookie;
    }
}

/// An entry of an authority file for any host, display `number`.
fn authority(number: u16, cookie: &[u8]) -> Vec<u8> {
    let mut out = 65535u16.to_be_bytes().to_vec();
    for field in [&b""[..], number.to_string().as_bytes(), b"MIT-MAGIC-COOKIE-1", cookie] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// The probe refuses before anything connects: no DISPLAY; -X with no
/// xauth, naming -Y; no cookie for an X server that wants one.
#[tokio::test]
async fn x11_probe_refuses_before_the_connection() {
    let trusted = Plan { trusted: true, timeout: None, xauth: None };
    let refused = x11::probe(&trusted, &x11::Env::default()).await.unwrap_err();
    assert!(refused.contains("DISPLAY is not set"), "{refused}");
    let untrusted = Plan { trusted: false, ..trusted.clone() };
    let env = x11::Env { display: Some("127.0.0.1:0".into()), path: Some("".into()), ..Default::default() };
    let refused = x11::probe(&untrusted, &env).await.unwrap_err();
    assert!(refused.contains("no xauth") && refused.contains("-Y"), "{refused}");

    let dir = scratch("probe");
    let (n, listener) = fake_x_server().await;
    let server = tokio::spawn(serve(listener, vec![9; 16]));
    let missing = dir.join("no-such-file").display().to_string();
    let env = x11::Env { display: Some(format!("127.0.0.1:{n}")), authority: Some(missing), ..Default::default() };
    let refused = x11::probe(&trusted, &env).await.unwrap_err();
    assert!(refused.contains("no MIT-MAGIC-COOKIE-1 cookie") && refused.contains("refuses"), "{refused}");
    assert_eq!(server.await.unwrap(), Vec::<u8>::new(), "the probe asked with no cookie");
}

/// -Y against the test's server: it is given a spoofed cookie, and the X
/// client of its `x11` channel reaches the X server with the real one.
#[test]
fn x11_channel_reaches_the_x_server_with_the_real_cookie() {
    let dir = scratch("channel");
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let (n, listener) = runtime.block_on(fake_x_server());
    let real = vec![0x5a; 16];
    let x_server = runtime.spawn(serve(listener, real.clone()));
    let file = dir.join("Xauthority");
    std::fs::write(&file, authority(n, &real)).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-o", "BatchMode=yes", "-Y"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(["x11-u@127.0.0.1", "x11-probe"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &dir).env("USERPROFILE", &dir);
    cmd.env("DISPLAY", format!("127.0.0.1:{n}")).env("XAUTHORITY", &file);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("x11 status 1"), "the X server took the cookie: {stdout}{stderr}");
    let given = stdout.lines().find_map(|l| l.strip_prefix("x11-req cookie ")).unwrap_or_default();
    let real_hex: String = real.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(given.len(), 32, "{stdout}");
    assert_ne!(given, real_hex, "the server was given the real cookie");
    assert_eq!(runtime.block_on(x_server).unwrap(), real);
}
