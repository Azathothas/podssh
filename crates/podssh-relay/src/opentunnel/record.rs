//! What a node keeps of its tunnel, in one private file of the cache (mode
//! 0600, written through a temporary file and a rename): the service, the
//! tunnel's id and name, its token, the key and the CSR of its name, the
//! node's route, and the certificate once it is ready. The protocol asks a
//! client to keep the identity before it binds the CSR, so that a start
//! that stopped half-way binds the same CSR again; and the service counts
//! only a new CSR against its 5 certificates a day for a tunnel. So a node
//! keeps one tunnel for its life, as the operator's ruling Q76 asks. The
//! token and the key never reach a line: [`Record`]'s `Debug` shows neither.
//!
//! The key and the CSR come from the binary ([`Credentials`]): its ACME
//! client makes both, and the library holds no C.

use std::fmt;
use std::path::PathBuf;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::Service;

/// The key of a tunnel's name, and the CSR of the name, which the binary
/// makes: P-256, as the service's CA signs one.
pub trait Credentials: Send + Sync {
    /// A new P-256 key, as PKCS #8 in PEM (`PRIVATE KEY`).
    fn key(&self) -> Result<Zeroizing<String>, String>;
    /// The CSR (PKCS #10, in PEM) of `hostname` with the key of `key_pem`:
    /// its common name `hostname`, and its names `hostname` and
    /// `*.hostname`, signed with ECDSA and SHA-256, as the service checks a
    /// CSR before each order.
    fn csr(&self, key_pem: &str, hostname: &str) -> Result<String, String>;
}

/// A node's tunnel.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// The service, as [`Service::shown`] names it: a record of another is
    /// not used.
    pub service: String,
    pub id: String,
    pub hostname: String,
    pub token: Zeroizing<String>,
    pub key: Zeroizing<String>,
    pub csr: String,
    /// The node's route: a random label, which the wildcard of the
    /// certificate keeps out of the logs of Certificate Transparency.
    pub route: String,
    /// Once ready: the leaf, its chain, and its expiry in ISO 8601.
    pub certificate: Option<String>,
    pub chain: Option<String>,
    pub expiry: Option<String>,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("service", &self.service)
            .field("hostname", &self.hostname)
            .field("route", &self.route)
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}

impl Record {
    /// The name that a client dials: the route under the tunnel's name.
    pub fn name(&self) -> String {
        format!("{}.{}", self.route, self.hostname)
    }

    /// Whether the certificate is ready.
    pub fn ready(&self) -> bool {
        self.certificate.is_some() && self.expiry.is_some()
    }

    /// The certificate and its chain, as one PEM, for the TLS of the node.
    pub fn chain_pem(&self) -> Option<String> {
        let leaf = self.certificate.as_deref()?;
        let chain = self.chain.as_deref().unwrap_or_default();
        Some(format!("{}\n{}", leaf.trim_end(), chain.trim_end()).trim_end().to_string() + "\n")
    }

    fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(
            json!({
                "service": self.service,
                "id": self.id,
                "hostname": self.hostname,
                "token": self.token.as_str(),
                "key": self.key.as_str(),
                "csr": self.csr,
                "route": self.route,
                "certificate": self.certificate,
                "chain": self.chain,
                "expiry": self.expiry,
            })
            .to_string(),
        )
    }

    fn from_json(text: &str) -> Option<Record> {
        let value: Value = serde_json::from_str(text).ok()?;
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
        let record = Record {
            service: text("service")?,
            id: text("id")?,
            hostname: text("hostname")?,
            token: Zeroizing::new(text("token")?),
            key: Zeroizing::new(text("key")?),
            csr: text("csr")?,
            route: text("route")?,
            certificate: text("certificate"),
            chain: text("chain"),
            expiry: text("expiry"),
        };
        // A route that is not one label would make a name of no tunnel.
        let whole = super::wire::is_route(&record.route) && record.route != super::wire::ROOT_ROUTE;
        whole.then_some(record)
    }
}

/// Where a node's record is: one file in the cache, by the service and the
/// node's label, read from the places of the cache and written to the
/// first that takes it.
#[derive(Debug, Clone)]
pub struct Store {
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    name: String,
}

impl Store {
    /// The record of the node `label` at `service`, in the cache.
    pub fn cache(service: &Service, label: &str) -> Store {
        Store::in_dirs(crate::cache::read_dirs(), crate::cache::candidate_dirs(), service, label)
    }

    /// The same in the directories given (for tests).
    pub fn in_dirs(read: Vec<PathBuf>, write: Vec<PathBuf>, service: &Service, label: &str) -> Store {
        let safe = crate::cache::safe_name;
        let name = format!("opentunnel-{}-{}.json", safe(&service.authority()), safe(label));
        Store { read, write, name }
    }

    /// The file's name.
    pub fn file_name(&self) -> &str {
        &self.name
    }

    /// The record kept, when there is one that reads as one, of `service`.
    pub fn load(&self, service: &Service) -> Option<Record> {
        let text = Zeroizing::new(crate::cache::load_file_from(&self.read, &self.name)?);
        Record::from_json(&text).filter(|record| record.service == service.shown())
    }

    /// Keep `record`, in place of the one before: where it went.
    pub fn save(&self, record: &Record) -> Result<PathBuf, String> {
        crate::cache::store_file_in_first(&self.write, &self.name, record.to_json().as_bytes())
    }

    /// The file that holds the record, in the first place that has one.
    pub fn path(&self) -> Option<PathBuf> {
        self.read.iter().map(|dir| dir.join(&self.name)).find(|path| path.is_file())
    }
}

/// The seconds since the epoch of an ISO 8601 time of the API's, as
/// `2027-01-31T12:34:56.000Z`: the date and the time of day, in UTC.
pub fn expiry_secs(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, time) = text.split_once(['T', 't', ' '])?;
    let mut parts = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let clock = time.get(..8)?;
    let mut hms = clock.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    let (h, min, s) = (hms.next()??, hms.next()??, hms.next()??);
    if h > 23 || min > 59 || s > 60 {
        return None;
    }
    Some(podssh_ws::clock::days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            service: Service::hosted().shown(),
            id: "abcdefghijkl".into(),
            hostname: "abcdefghijkl.opentunnel.xyz".into(),
            token: Zeroizing::new("TOKEN-OF-THE-TEST".into()),
            key: Zeroizing::new("-----BEGIN PRIVATE KEY-----\nKEY-OF-THE-TEST\n-----END PRIVATE KEY-----\n".into()),
            csr: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----\n".into(),
            route: "r7k2qmx4".into(),
            certificate: None,
            chain: None,
            expiry: None,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("podssh-opentunnel-record-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::cache::private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn a_record_is_kept_in_a_private_file_and_read_back_whole_and_its_debug_shows_no_secret() {
        let dir = scratch("kept");
        let store = Store::in_dirs(vec![dir.clone()], vec![dir.clone()], &Service::hosted(), "lab");
        assert_eq!(store.file_name(), "opentunnel-opentunnel.xyz-lab.json");
        assert!(store.load(&Service::hosted()).is_none());
        let mut kept = record();
        let path = store.save(&kept).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(store.load(&Service::hosted()), Some(kept.clone()));
        kept.certificate = Some("LEAF".into());
        kept.expiry = Some("2027-01-31T00:00:00.000Z".into());
        store.save(&kept).unwrap();
        let back = store.load(&Service::hosted()).unwrap();
        assert!(back.ready() && back.name() == "r7k2qmx4.abcdefghijkl.opentunnel.xyz");
        let other = Service::parse("https://tunnels.example.test").unwrap();
        assert!(store.load(&other).is_none(), "a record of another service is not used");
        let shown = format!("{back:?}");
        assert!(!shown.contains("TOKEN-OF-THE-TEST") && !shown.contains("KEY-OF-THE-TEST"), "{shown}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_api_s_expiry_is_read_as_seconds_since_the_epoch() {
        assert_eq!(expiry_secs("1970-01-02T00:00:00.000Z"), Some(86_400));
        assert_eq!(expiry_secs("2027-01-31T12:34:56Z"), Some(1_801_398_896));
        assert_eq!(expiry_secs("not a date"), None);
        assert_eq!(expiry_secs("2027-13-01T00:00:00Z"), None);
    }
}
