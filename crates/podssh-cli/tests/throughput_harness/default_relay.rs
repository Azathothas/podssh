//! The stand-in relay as the default relay's hosts (T-608): a certificate of
//! the default relay host and its seed pool, signed by the test's CA, so that
//! a stand-in answers for the default list behind a proxy of the test's; and
//! the file of a stand-in's events, which a test follows as they come.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::cells::Skipped;
use super::{Cell, Session};

/// The certificate's file, beside the stand-in's others.
pub const CERT: &str = "relay-default.pem";

/// The file of a stand-in's events, by its mode and its certificate.
pub fn events_name(mode: &str, cert: &str) -> String {
    format!("fake-relay-{}-{cert}-events.log", mode.replace(':', "-"))
}

impl Cell {
    /// The stand-in relay of `mode` with the default relay's certificate:
    /// its port, and the file where its events go as they come.
    pub fn fake_relay_default(s: &Session, mode: &str) -> Result<(u16, PathBuf), Skipped> {
        let cell = Cell::relay_process(s, mode, "the stand-in of the default relay", CERT, None, &[])?;
        let host = cell.args.iter().find(|a| a.starts_with("relay-a.test:")).cloned().unwrap_or_default();
        let port = host.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or_default();
        Ok((port, s.home.join(events_name(mode, CERT))))
    }
}

/// The leaf of the stand-in's key for the default relay host and each host
/// of its seed pool, as `scripts/interop-faults.sh` signs its others.
pub fn certificate(dir: &Path) -> Result<(), String> {
    let seed = podssh_relay::pool::SEED.iter().copied();
    let names = std::iter::once(podssh_relay::relay::DEFAULT_RELAY_HOST).chain(seed);
    let san = names.map(|n| format!("DNS:{n}")).collect::<Vec<_>>().join(",");
    let ext = format!(
        "subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\n"
    );
    std::fs::write(dir.join("ext-default"), ext).map_err(|e| e.to_string())?;
    let p = |name: &str| dir.join(name).display().to_string();
    let args: Vec<String> = ["x509", "-req", "-in", &p("relay.csr"), "-CA", &p("ca.pem"), "-CAkey", &p("ca.key")]
        .iter()
        .map(|s| s.to_string())
        .chain(["-CAcreateserial", "-days", "2", "-extfile"].map(String::from))
        .chain([p("ext-default"), "-out".into(), p(CERT)])
        .collect();
    let out = Command::new("openssl").args(args).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("openssl x509: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}
