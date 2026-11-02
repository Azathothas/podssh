//! wisp-server-python, Mercury Workshop's own Wisp server, on the loopback:
//! software that podssh did not write (AGPL-3.0: run here, never copied).
//! Its version 0.9.0 speaks version 1 of the protocol, gives each stream a
//! credit of 128 packets and a CONTINUE after each 32 that it wrote to the
//! target, and closes a stream that it cannot open with 0x42 (read in its
//! source, MercuryWorkshop/wisp-server-python:src/wisp/server/connection.py).
//! `PODSSH_TEST_WISP_PYTHON` names the Python that has it (default
//! `python3`); where none has it, each test says that it did not run, and
//! fails instead when `PODSSH_TEST_WISP_REQUIRED` is set, as in CI.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const START: Duration = Duration::from_secs(30);

/// The reference server, killed with its process group when dropped.
pub struct Reference {
    child: Child,
    pub port: u16,
    log: std::path::PathBuf,
}

impl Drop for Reference {
    fn drop(&mut self) {
        // Its workers are processes of their own, in its group.
        #[cfg(unix)]
        {
            let group = format!("-{}", self.child.id());
            let _ = Command::new("kill").args(["-KILL", "--", group.as_str()]).stderr(Stdio::null()).status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

fn python() -> String {
    std::env::var("PODSSH_TEST_WISP_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// The reference server on a free port of the loopback, which may dial the
/// loopback; `None`, said, where it is not installed.
pub fn start() -> Option<Reference> {
    let python = python();
    let mut here = Command::new(&python);
    here.args(["-c", "import wisp.server"]).stdout(Stdio::null()).stderr(Stdio::null());
    if !here.status().is_ok_and(|s| s.success()) {
        let why = "no wisp-server-python here (pip install wisp-python==0.9.0; PODSSH_TEST_WISP_PYTHON names the \
                   Python that has it)";
        assert!(std::env::var_os("PODSSH_TEST_WISP_REQUIRED").is_none(), "{why}");
        eprintln!("did not run: {why}");
        return None;
    }
    let port = super::closed_port();
    let mut cmd = Command::new(&python);
    let port_text = port.to_string();
    cmd.args(["-m", "wisp.server", "--host", "127.0.0.1", "--port", port_text.as_str(), "--allow-loopback"]);
    cmd.args(["--threads", "1", "--log-level", "warning"]);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    // Its words go to a file, which no pipe can fill to stop it.
    let log = std::env::temp_dir().join(format!("podssh-wisp-reference-{}-{port}.log", std::process::id()));
    let err = std::fs::File::create(&log).unwrap();
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(err).spawn().unwrap();
    let mut server = Reference { child, port, log: log.clone() };
    let started = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if let Ok(Some(status)) = server.child.try_wait() {
            let mut said = String::new();
            let _ = std::fs::File::open(&log).and_then(|mut f| f.read_to_string(&mut said));
            panic!("wisp-server-python ended before it listened ({status}): {said}");
        }
        assert!(started.elapsed() < START, "wisp-server-python did not listen within {START:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(server)
}
