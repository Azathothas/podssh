//! The passwords that `podssh agent` keeps (T-228), from end to end: the
//! agent serves on a socket of the test, `add-password` gives it a password
//! on stdin, and `podssh ssh --direct -o BatchMode=yes`, with nobody to ask,
//! logs in to a server of the test that takes only passwords, or only
//! keyboard-interactive. A password that the server refuses is forgotten,
//! and the next run does not try it again. `-vvv` names the source, never
//! the value.

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};

const USER: &str = "tester";
/// A password of the test server, made up for it.
const RIGHT: &str = "a-test-password-of-this-test";

/// What the server takes: passwords, or one password prompt of
/// keyboard-interactive; and each secret that a client gave it.
struct Far {
    tried: Arc<Mutex<Vec<String>>>,
}

impl Far {
    fn judge(&mut self, user: &str, secret: &str) -> Auth {
        self.tried.lock().unwrap().push(secret.to_string());
        if user == USER && secret == RIGHT {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(self.judge(user, password))
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: Cow::Borrowed(""),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(vec![(Cow::Borrowed("Password: "), false)]),
            }),
            Some(mut answers) => {
                let answer = answers.next().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
                Ok(self.judge(user, &answer))
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"logged-in\n".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

/// The server on the loopback, taking `method` alone: its port, and the
/// secrets that it was given.
async fn start_server(key: &Path, method: MethodKind) -> (u16, Arc<Mutex<Vec<String>>>) {
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.methods = MethodSet::from(&[method][..]);
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let tried = Arc::new(Mutex::new(Vec::new()));
    let shared = tried.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            let far = Far { tried: shared.clone() };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, far).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, tried)
}

/// `podssh` with HOME under `home`, and none of the machine's settings.
fn podssh(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_TIMEOUT", "SSH_AUTH_SOCK", "SSH_ASKPASS", "HTTPS_PROXY", "https_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// A run of the test: its home, its agent and the agent's socket.
struct Run {
    home: PathBuf,
    agent: Child,
    socket: String,
    runtime: tokio::runtime::Runtime,
}

impl Run {
    fn start(tag: &str) -> Run {
        let home = std::env::temp_dir().join(format!("podssh-agent-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let socket = if cfg!(windows) {
            format!(r"\\.\pipe\podssh-agent-store-{tag}-{}", std::process::id())
        } else {
            home.join("agent.sock").display().to_string()
        };
        let mut agent = podssh(&home)
            .args(["agent", "--socket", &socket])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("podssh agent runs");
        // The agent serves once it says SSH_AUTH_SOCK.
        let mut first = String::new();
        BufReader::new(agent.stdout.take().unwrap()).read_line(&mut first).unwrap();
        assert!(first.starts_with("SSH_AUTH_SOCK="), "{first:?}");
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        Run { home, agent, socket, runtime }
    }

    fn server(&self, method: MethodKind) -> (u16, Arc<Mutex<Vec<String>>>) {
        let key = self.home.join("host_key");
        if !key.exists() {
            let key = key.to_string_lossy().into_owned();
            let made = podssh(&self.home).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key]).status();
            assert!(made.unwrap().success());
        }
        self.runtime.block_on(start_server(&key, method))
    }

    /// `add-password`, with `secret` on stdin.
    fn add_password(&self, port: u16, secret: &str) {
        let mut child = podssh(&self.home)
            .args(["agent", "add-password", &format!("{USER}@127.0.0.1:{port}")])
            .env("SSH_AUTH_SOCK", &self.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{secret}").unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{err}");
        assert!(err.contains(&format!("Added the password for {USER}@127.0.0.1:{port}")), "{err}");
    }

    /// `podssh ssh -vvv` with nobody to ask: its code, stdout and stderr.
    fn ssh(&self, port: u16) -> (Option<i32>, String, String) {
        let known = format!("UserKnownHostsFile={}", self.home.join("known_hosts").display());
        let out = podssh(&self.home)
            .args(["ssh", "--direct", "-vvv", "-p", &port.to_string(), "-o", "BatchMode=yes"])
            .args(["-o", "PubkeyAuthentication=no", "-o", "StrictHostKeyChecking=accept-new", "-o", &known])
            .args([&format!("{USER}@127.0.0.1"), "true"])
            .env("SSH_AUTH_SOCK", &self.socket)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (out.status.code(), text(&out.stdout), text(&out.stderr))
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.agent.kill();
        let _ = self.agent.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[test]
fn a_kept_password_logs_in_with_nobody_to_ask() {
    let run = Run::start("password");
    let (port, tried) = run.server(MethodKind::Password);
    run.add_password(port, RIGHT);
    let (code, out, err) = run.ssh(port);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "logged-in\n");
    assert!(err.contains(&format!("the password for {USER}@127.0.0.1:{port} from podssh agent")), "{err}");
    assert!(!err.contains(RIGHT), "-vvv showed the password");
    assert_eq!(*tried.lock().unwrap(), [RIGHT]);
}

#[test]
fn a_kept_password_answers_keyboard_interactive() {
    let run = Run::start("kbdint");
    let (port, tried) = run.server(MethodKind::KeyboardInteractive);
    run.add_password(port, RIGHT);
    let (code, out, err) = run.ssh(port);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "logged-in\n");
    assert!(!err.contains(RIGHT), "-vvv showed the password");
    assert_eq!(*tried.lock().unwrap(), [RIGHT]);
}

/// `podssh doctor` counts what the agent keeps, and names none of it: no
/// user, no host and no secret (T-228, step 6).
#[test]
fn doctor_counts_what_the_agent_keeps_and_names_none() {
    let run = Run::start("doctor");
    let (port, _) = run.server(MethodKind::Password);
    run.add_password(port, RIGHT);
    let out = podssh(&run.home)
        .arg("doctor")
        .env("SSH_AUTH_SOCK", &run.socket)
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    let line = report.lines().find(|l| l.split_whitespace().nth(1) == Some("agent"));
    let line = line.unwrap_or_else(|| panic!("no agent line:\n{report}"));
    assert!(line.starts_with("  ok"), "{line}");
    assert!(line.ends_with("podssh agent, which keeps 1 password or passphrase"), "{line}");
    // The report names 127.0.0.1 for its own bind on Linux; never the
    // target, its user or its secret.
    for secret in [RIGHT, USER, &format!("{USER}@127.0.0.1:{port}")] {
        assert!(!report.contains(secret), "the report holds {secret}:\n{report}");
    }
}

/// A password that the server refuses is forgotten: the next run neither
/// tries it nor says that it came from the agent.
#[test]
fn a_refused_password_is_forgotten_and_never_tried_twice() {
    let run = Run::start("refused");
    let (port, tried) = run.server(MethodKind::Password);
    let wrong = "not-the-password-of-this-test";
    run.add_password(port, wrong);
    let (code, _, err) = run.ssh(port);
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("was refused, and podssh agent forgets it"), "{err}");
    let (code, _, err) = run.ssh(port);
    assert_eq!(code, Some(255), "{err}");
    assert!(!err.contains("from podssh agent"), "the refused password was asked for again: {err}");
    assert_eq!(*tried.lock().unwrap(), [wrong], "the server saw the refused password once");
}
