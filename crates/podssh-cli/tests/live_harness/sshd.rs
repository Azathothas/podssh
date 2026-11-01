//! OpenSSH's server on this machine's loopback, for a node's TARGET (T-422):
//! software that podssh did not write, which runs a command for this user
//! with a key of the test, and answers with no limit of an outside service.
//! As `scripts/release-check-node.sh` starts its own.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A server that runs until it is dropped.
pub struct Sshd {
    child: Child,
    pub port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The server's program: on the PATH, else where Debian and Ubuntu put it.
fn program() -> Option<PathBuf> {
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|dir| dir.join("sshd"))
        .find(|p| p.is_file());
    on_path.or_else(|| Some(PathBuf::from("/usr/sbin/sshd")).filter(|p| p.is_file()))
}

/// Start the server in `dir` for this user, who logs in with the public key
/// in `authorized`; else why none can run here.
pub fn start(dir: &Path, authorized: &Path) -> Result<Sshd, String> {
    let sshd = program().ok_or("no sshd here")?;
    let port = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?.local_addr().unwrap().port();
    let host_key = dir.join("sshd_host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !made.success() {
        return Err("no host key was made".into());
    }
    let config = dir.join("sshd_config");
    let mut text = format!(
        "ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\nPidFile none\n",
        host_key.display(),
        authorized.display()
    );
    std::fs::write(&config, &text).map_err(|e| e.to_string())?;
    // OpenSSH 9.8 and later penalise a source of many sessions; older ones
    // do not know the keyword.
    let mut knows = Command::new(&sshd);
    knows.arg("-t").arg("-f").arg(&config).args(["-o", "PerSourcePenalties=no"]);
    if knows.stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
        text.push_str("PerSourcePenalties no\n");
        std::fs::write(&config, &text).map_err(|e| e.to_string())?;
    }
    let log = dir.join("sshd.log");
    let child = Command::new(&sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("{}: {e}", sshd.display()))?;
    let server = Sshd { child, port };
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if Instant::now() > deadline {
            let said = std::fs::read_to_string(&log).unwrap_or_default();
            return Err(format!("sshd did not listen within 15 s: {}", said.lines().last().unwrap_or("")));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(server)
}
