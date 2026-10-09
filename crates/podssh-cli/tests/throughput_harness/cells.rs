//! The cells of the throughput method: each is the way for `podssh ssh` to
//! reach a far end, set up for the session, or the reason that it cannot be.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{found, lines_of, scripts, wait_for, Far, Session};

/// A way to the far end: `podssh ARGS COMMAND`.
pub struct Cell {
    pub name: String,
    pub args: Vec<String>,
    pub far: Far,
}

/// A cell that is not set up: its name, and why.
pub type Skipped = (String, String);

impl Cell {
    /// The test's server with `--direct`: podssh's own limit, on this machine.
    pub fn direct(s: &Session) -> Cell {
        let mut args = vec!["ssh".to_string()];
        args.extend(s.common());
        args.extend(["--direct", "-p", &s.port.to_string(), "tester@127.0.0.1"].map(String::from));
        Cell { name: "loopback, --direct (podssh's own limit)".into(), args, far: Far::Test }
    }

    /// The forward road through `scripts/fake-relay.py` on the loopback: the
    /// control of the relay, when Python and `openssl` are found here.
    pub fn fake_relay(s: &Session) -> Result<Cell, Skipped> {
        Cell::fake_relay_mode(s, "normal", "forward road, the stand-in relay on the loopback (the control)")
    }

    /// The forward road through a stand-in relay of `mode` (T-203), its own
    /// process; the certificates are made once for the session.
    pub fn fake_relay_mode(s: &Session, mode: &str, name: &str) -> Result<Cell, Skipped> {
        let name = name.to_string();
        let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"]));
        let Some(python) = python else { return Err((name, "no Python here".into())) };
        if !found("openssl", &["version"]) {
            return Err((name, "no openssl here, to make the stand-in's certificate".into()));
        }
        let dir = s.home.join("fake-relay");
        if !dir.join("relay.pem").exists() {
            std::fs::create_dir_all(&dir).map_err(|e| (name.clone(), e.to_string()))?;
            certificates(&dir).map_err(|why| (name.clone(), why))?;
        }
        let port_file = dir.join(format!("port-{}", mode.replace(':', "-")));
        let child = Command::new(python)
            .arg(scripts().join("fake-relay.py"))
            .arg("--cert")
            .arg(dir.join("relay.pem"))
            .arg("--key")
            .arg(dir.join("relay.key"))
            .arg("--port-file")
            .arg(&port_file)
            .arg("--mode")
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| (name.clone(), format!("the stand-in relay: {e}")))?;
        s.keep(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        let port = loop {
            if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
                break port;
            }
            if Instant::now() > deadline {
                return Err((name, "the stand-in relay did not start within 30 s".into()));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let mut args = vec!["ssh".to_string()];
        args.extend(s.common());
        args.extend([
            "--relay-host".to_string(),
            format!("relay-a.test:{port}"),
            "--relay-addr".to_string(),
            "relay-a.test=127.0.0.1".to_string(),
            "--ca-file".to_string(),
            dir.join("ca.pem").display().to_string(),
            "-p".to_string(),
            s.port.to_string(),
            "tester@127.0.0.1".to_string(),
        ]);
        Ok(Cell { name, args, far: Far::Test })
    }

    /// The reverse road through the live relay, with the resumable layer: a
    /// pair, and `podssh node` in front of the test's server.
    pub fn reverse(s: &Session) -> Result<Cell, Skipped> {
        let name = "reverse road, the live relay, with the layer".to_string();
        let label = format!("tp{}", std::process::id());
        let out = s
            .command(&["relay".into(), "pair".into(), label.clone()])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| (name.clone(), e.to_string()))?;
        if !out.status.success() {
            return Err((name, format!("podssh relay pair: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        s.revoke_later(&label);
        let target = format!("127.0.0.1:{}", s.port);
        let mut node = s
            .command(&["node".into(), label.clone(), target])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| (name.clone(), e.to_string()))?;
        let lines = lines_of(&mut node);
        s.keep(node);
        wait_for(&lines, "serving").map_err(|why| (name.clone(), format!("the node: {why}")))?;
        let mut args = vec!["ssh".to_string()];
        args.extend(s.common());
        args.push(format!("node://tester@{label}"));
        Ok(Cell { name, args, far: Far::Test })
    }

    /// The cells whose target a variable names (Q38): none when it is not
    /// set, each with the reason.
    pub fn named(s: &Session) -> Vec<Result<Cell, Skipped>> {
        let mut cells = Vec::new();
        let target = std::env::var("PODSSH_THROUGHPUT_SSH").ok().filter(|t| !t.trim().is_empty());
        for (name, direct) in
            [("forward road, the live relay, to the named server", false), ("direct road, to the named server", true)]
        {
            let Some(target) = &target else {
                cells.push(Err((name.to_string(), "PODSSH_THROUGHPUT_SSH names no server (Q38)".into())));
                continue;
            };
            let mut args = vec!["ssh".to_string()];
            args.extend(s.common());
            if let Ok(key) = std::env::var("PODSSH_THROUGHPUT_KEY") {
                args.extend(["-i".to_string(), key, "-o".into(), "IdentitiesOnly=yes".into()]);
            }
            if direct {
                args.push("--direct".into());
            }
            match target.rsplit_once(':') {
                Some((host, port)) if port.parse::<u16>().is_ok() => {
                    args.extend(["-p".to_string(), port.to_string(), host.to_string()]);
                }
                _ => args.push(target.clone()),
            }
            cells.push(Ok(Cell { name: name.to_string(), args, far: Far::Posix }));
        }
        cells.push(iroh_named(s));
        cells
    }
}

/// The iroh road through the relays of `PODSSH_THROUGHPUT_IROH_RELAY` (Q38),
/// with podssh's own trust store.
#[cfg(feature = "iroh")]
fn iroh_named(s: &Session) -> Result<Cell, Skipped> {
    let name = "iroh road, the named relays".to_string();
    let relays = std::env::var("PODSSH_THROUGHPUT_IROH_RELAY").ok().filter(|t| !t.trim().is_empty());
    let Some(relays) = relays else {
        return Err((name, "PODSSH_THROUGHPUT_IROH_RELAY names no relay (Q38)".into()));
    };
    iroh::cell(s, name, &relays, None)
}

#[cfg(not(feature = "iroh"))]
fn iroh_named(_: &Session) -> Result<Cell, Skipped> {
    Err(("iroh road, the named relays".into(), "this build has no iroh road (--features iroh)".into()))
}

#[cfg(feature = "iroh-test")]
impl Cell {
    /// The iroh road through iroh's relay server on the loopback.
    pub fn iroh_loopback(s: &Session) -> Result<Cell, Skipped> {
        let name = "iroh road, iroh's relay server on the loopback".to_string();
        let relay = s
            .runtime
            .block_on(podssh_iroh::test_relay::spawn(&s.home))
            .map_err(|e| (name.clone(), format!("the relay: {e}")))?;
        let (url, cert) = (relay.url.to_string(), relay.cert.clone());
        s.relays.lock().unwrap().push(relay);
        iroh::cell(s, name, &url, Some(&cert))
    }
}

/// `make CA and leaf`: a test CA and a certificate of `relay-a.test` signed
/// by it, as `scripts/interop-faults.sh` makes them.
fn certificates(dir: &std::path::Path) -> Result<(), String> {
    let p = |name: &str| dir.join(name).display().to_string();
    std::fs::write(dir.join("req.cnf"), "[req]\ndistinguished_name = dn\n[dn]\n").map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("ext"),
        "subjectAltName=DNS:relay-a.test\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\n",
    )
    .map_err(|e| e.to_string())?;
    let steps: [Vec<String>; 3] = [
        ["req", "-config", &p("req.cnf"), "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
            .iter()
            .map(|s| s.to_string())
            .chain(
                [
                    "-days",
                    "2",
                    "-subj",
                    "/CN=podssh-test-ca",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                ]
                .map(String::from),
            )
            .chain([
                "keyUsage=critical,keyCertSign,cRLSign".into(),
                "-keyout".into(),
                p("ca.key"),
                "-out".into(),
                p("ca.pem"),
            ])
            .collect(),
        ["req", "-config", &p("req.cnf"), "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
            .iter()
            .map(|s| s.to_string())
            .chain([
                "-subj".into(),
                "/CN=relay.test".into(),
                "-keyout".into(),
                p("relay.key"),
                "-out".into(),
                p("relay.csr"),
            ])
            .collect(),
        ["x509", "-req", "-in", &p("relay.csr"), "-CA", &p("ca.pem"), "-CAkey", &p("ca.key"), "-CAcreateserial"]
            .iter()
            .map(|s| s.to_string())
            .chain(["-days".into(), "2".into(), "-extfile".into(), p("ext"), "-out".into(), p("relay.pem")])
            .collect(),
    ];
    for step in steps {
        let out = Command::new("openssl").args(&step).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("openssl {}: {}", step[0], String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    Ok(())
}

#[cfg(feature = "iroh")]
mod iroh {
    use std::path::Path;
    use std::process::Stdio;

    use super::{lines_of, wait_for, Cell, Far, Session, Skipped};

    /// The iroh road through `relays`: `podssh node --iroh` in front of the
    /// test's server, which lets in this session's client key, and `podssh
    /// ssh iroh:TICKET`; `cert` is the relays' certificate, when podssh's
    /// trust store does not hold it.
    pub fn cell(s: &Session, name: String, relays: &str, cert: Option<&Path>) -> Result<Cell, Skipped> {
        use podssh_iroh::keys::{self, Place};
        let client_key = s.home.join("iroh-client.key");
        let key = keys::load(&Place::File(client_key.clone()), &mut podssh_relay::session::OsEntropy)
            .map_err(|why| (name.clone(), why))?;
        let allow = s.home.join("iroh-allow");
        std::fs::write(&allow, format!("{}\n", keys::fingerprint(&key.public())))
            .map_err(|e| (name.clone(), e.to_string()))?;
        let mut trust = Vec::new();
        if let Some(cert) = cert {
            trust = vec!["--ca-file".to_string(), cert.display().to_string()];
        }
        let mut node_args =
            vec!["node".to_string(), format!("tpi{}", std::process::id()), format!("127.0.0.1:{}", s.port)];
        node_args.extend(["--iroh", "--iroh-relay", relays, "--iroh-allow"].map(String::from));
        node_args.push(allow.display().to_string());
        node_args.extend(["--iroh-key".to_string(), s.home.join("iroh-node.key").display().to_string()]);
        node_args.extend(trust.iter().cloned());
        let mut node = s
            .command(&node_args)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| (name.clone(), e.to_string()))?;
        let lines = lines_of(&mut node);
        s.keep(node);
        let line = wait_for(&lines, "ticket iroh:").map_err(|why| (name.clone(), format!("the node: {why}")))?;
        let ticket = line[line.find("iroh:").unwrap_or(0)..].trim().to_string();
        let mut args = vec!["ssh".to_string()];
        args.extend(s.common());
        args.extend(trust);
        args.extend([
            "--iroh-relay".to_string(),
            relays.to_string(),
            "--iroh-key".into(),
            client_key.display().to_string(),
        ]);
        args.push(format!("tester@{ticket}"));
        Ok(Cell { name, args, far: Far::Test })
    }
}
