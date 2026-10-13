//! A far host for the tests of `podssh job` (T-193): the test's SSH server,
//! whose commands run in sh as on a POSIX host (`ssh_harness::start_shell`),
//! in a home of the test's, with the PATH that the test gives; and the
//! binary run against it with no relay. tmux is the one that
//! `PODSSH_TEST_TMUX` names, else one on PATH; the tmux server of a far
//! home stops with it. On Unix only, as a far host has a POSIX sh.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-jobfar-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    crate::cleanup::at_test_end(&dir);
    dir
}

/// A program on this host's PATH.
pub fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

/// tmux: the one that `PODSSH_TEST_TMUX` names, else the first on PATH.
pub fn tmux() -> Option<PathBuf> {
    match std::env::var_os("PODSSH_TEST_TMUX") {
        Some(named) => {
            let path = PathBuf::from(named);
            assert!(path.is_file(), "PODSSH_TEST_TMUX names {}, and no program is there", path.display());
            Some(path)
        }
        None => on_path("tmux"),
    }
}

/// PATH with the directory of `tmux` first.
pub fn path_with(tmux: &Path) -> String {
    let mine = std::env::var("PATH").unwrap_or_default();
    format!("{}:{mine}", tmux.parent().unwrap().display())
}

/// The far host: its home, the port of its server, and the runtime that
/// serves it; the tmux server of its home stops with it.
pub struct Far {
    pub home: PathBuf,
    pub port: u16,
    pub local: PathBuf,
    tmux: Option<PathBuf>,
    _runtime: tokio::runtime::Runtime,
}

impl Drop for Far {
    fn drop(&mut self) {
        if let Some(tmux) = &self.tmux {
            let _ = Command::new(tmux)
                .arg("kill-server")
                .env("TMUX_TMPDIR", &self.home)
                .stderr(Stdio::null())
                .status();
        }
    }
}

impl Far {
    /// A far host whose commands find their programs on `path`; `tmux`, to
    /// stop its server at the end.
    pub fn new(name: &str, path: String, tmux: Option<PathBuf>) -> Far {
        let dir = scratch(name);
        let key = dir.join("host_key");
        let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(status.success());
        let (home, local) = (dir.join("far"), dir.join("local"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let shell = crate::ssh_harness::Shell { home: home.clone(), path };
        let port = runtime.block_on(crate::ssh_harness::start_shell(&key, shell)).0;
        Far { home, port, local, tmux, _runtime: runtime }
    }

    /// A far host with tmux, or `None` when this host has none, said.
    pub fn with_tmux(name: &str) -> Option<Far> {
        let Some(tmux) = tmux() else {
            eprintln!("did not run: no tmux here; PODSSH_TEST_TMUX names one");
            return None;
        };
        Some(Far::new(name, path_with(&tmux), Some(tmux)))
    }

    pub fn host(&self) -> String {
        format!("a@127.0.0.1:{}", self.port)
    }

    /// `podssh VERB FLAGS... ARGS...` from the local home, with no relay and
    /// the host's key taken: (exit code, stdout, stderr).
    pub fn podssh(&self, verb: &str, args: &[&str]) -> (i32, String, String) {
        let known = format!("UserKnownHostsFile={}", self.local.join("known_hosts").display());
        let mut all = vec![verb, "--direct", "-o", "StrictHostKeyChecking=accept-new", "-o", known.as_str()];
        all.extend_from_slice(args);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(&all)
            .current_dir(&self.local)
            .env("PODSSH_SSH_CONFIG", "none")
            .env("PODSSH_SETTINGS", "none")
            .env("HOME", &self.local)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_OFFLINE"] {
            cmd.env_remove(name);
        }
        let out = cmd.output().unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
    }

    /// `podssh job SUB HOST WORDS...`.
    pub fn job(&self, sub: &str, words: &[&str]) -> (i32, String, String) {
        let host = self.host();
        let mut args = vec![sub, host.as_str()];
        args.extend_from_slice(words);
        self.podssh("job", &args)
    }

    /// `podssh job start HOST -- COMMAND`: the ID that it printed.
    pub fn start(&self, command: &str) -> String {
        let (code, out, err) = self.job("start", &["--", command]);
        assert_eq!(code, 0, "{err}");
        let id = out.trim().to_string();
        assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{out}");
        id
    }

    /// The line of the list for `id`, once `wanted` holds for it, or when
    /// `wait` has passed.
    pub fn line_of(&self, id: &str, wait: Duration, wanted: impl Fn(&str) -> bool) -> Option<String> {
        let until = Instant::now() + wait;
        loop {
            let (code, out, err) = self.job("list", &[]);
            assert_eq!(code, 0, "{err}");
            let line = out.lines().find(|l| l.starts_with(id)).map(str::to_string);
            if line.as_deref().is_some_and(&wanted) || Instant::now() >= until {
                return line;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether tmux on the far host has the session of this exact name.
    pub fn has_session(&self, name: &str) -> bool {
        let tmux = self.tmux.as_ref().expect("a far host with tmux");
        Command::new(tmux)
            .args(["has-session", "-t", &format!("={name}")])
            .env("TMUX_TMPDIR", &self.home)
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}
