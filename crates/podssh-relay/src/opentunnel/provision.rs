//! A node's tunnel, made once and kept (anomalyco/opentunnel:docs/protocol.md
//! at v0.6.1, "Provisioning" and "Renewal"). A start with no record makes a
//! tunnel, a route of its own, a key and the CSR of the name, keeps them,
//! then binds the CSR and polls each 2 s until the certificate is ready. A
//! start whose record has no certificate yet binds the same CSR again, which
//! the service answers with the certificate that it has, and counts against
//! no limit. A start whose record is ready asks for the certificate now, as
//! the service renews it with the same CSR, and keeps the one that it has
//! when the service does not answer and the one kept has not expired. A
//! tunnel that the service no longer knows (401, 404) is made again, and
//! said.

use std::path::PathBuf;
use std::time::Duration;

use tokio::time::Instant;

use super::api::{Api, ApiError, Cert};
use super::record::{expiry_secs, Credentials, Record, Store};
use super::Say;
use crate::session::{Entropy, NoRandom, OsEntropy};

/// How often the certificate is asked for while it is issued.
pub const POLL_EVERY: Duration = Duration::from_secs(2);
/// How long a new certificate may take: the service orders it from its CA
/// by DNS-01, which waits for public resolvers.
pub const READY_LIMIT: Duration = Duration::from_secs(300);
/// The letters of a route: base32's, in lower case.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A node's tunnel, ready.
#[derive(Debug, Clone)]
pub struct Provisioned {
    pub record: Record,
    /// Where it is kept; none when no directory took it.
    pub path: Option<PathBuf>,
    /// The tunnel is new: the service made it in this start.
    pub made: bool,
    /// A CSR that the tunnel did not have was bound in this start.
    pub new_csr: bool,
}

/// A random route of 26 letters (130 bits): a name that a scanner of the
/// logs of Certificate Transparency cannot guess.
pub fn random_route(entropy: &mut dyn Entropy) -> Result<String, NoRandom> {
    let mut bytes = [0u8; 26];
    entropy.fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| ALPHABET[usize::from(b & 31)] as char).collect())
}

/// Whether a certificate that expires at `expiry` still holds now.
pub fn unexpired(expiry: Option<&str>) -> bool {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    expiry.and_then(expiry_secs).is_some_and(|ends| ends > now)
}

/// The steps of a provision, and how long it may poll.
pub struct Provision<'a> {
    pub api: &'a Api,
    pub store: &'a Store,
    pub credentials: &'a dyn Credentials,
    pub say: &'a Say,
    pub poll: Duration,
    pub limit: Duration,
}

impl<'a> Provision<'a> {
    pub fn new(api: &'a Api, store: &'a Store, credentials: &'a dyn Credentials, say: &'a Say) -> Provision<'a> {
        Provision { api, store, credentials, say, poll: POLL_EVERY, limit: READY_LIMIT }
    }

    /// The node's tunnel, ready: the one kept, or a new one.
    pub async fn run(&self) -> Result<Provisioned, String> {
        let service = self.api.service();
        match self.store.load(service) {
            Some(record) if record.ready() => match self.refresh(record).await {
                Refreshed::Kept(provisioned) => return Ok(provisioned),
                Refreshed::Gone(why) => (self.say)(format!("{why}; a new tunnel is made")),
            },
            Some(record) => {
                (self.say)(format!("resuming the tunnel {}: its CSR is bound again", record.hostname));
                return self.order(record, false, false).await;
            }
            None => {}
        }
        self.make().await
    }

    /// A new tunnel, kept before its CSR is bound.
    async fn make(&self) -> Result<Provisioned, String> {
        let service = self.api.service();
        let created = self.api.create().await.map_err(|e| format!("no tunnel was made at {service}: {e}"))?;
        let route = random_route(&mut OsEntropy).map_err(|e| e.to_string())?;
        let key = self.credentials.key().map_err(|why| format!("the tunnel's key: {why}"))?;
        let hostname = created.tunnel.hostname.clone();
        let csr = self.credentials.csr(&key, &hostname).map_err(|why| format!("the CSR of {hostname}: {why}"))?;
        let record = Record {
            service: service.shown(),
            id: created.tunnel.id,
            hostname,
            token: created.token,
            key,
            csr,
            route,
            certificate: None,
            chain: None,
            expiry: None,
        };
        (self.say)(format!("made the tunnel {} at {service}", record.hostname));
        self.order(record, true, true).await
    }

    /// Keep `record`, bind its CSR, and poll until its certificate is ready;
    /// then keep it again, with the certificate.
    async fn order(&self, mut record: Record, made: bool, new_csr: bool) -> Result<Provisioned, String> {
        let path = self.keep(&record);
        let mut cert = self.api.bind_csr(&record.token, &record.id, &record.csr).await.map_err(|e| {
            format!("OpenTunnel did not take the CSR of {}: {e}; the next start binds it again", record.hostname)
        })?;
        let until = Instant::now() + self.limit;
        let (certificate, chain, expiry) = loop {
            match cert {
                Cert::Ready { certificate, chain, expiry } => break (certificate, chain, expiry),
                Cert::Failed(reason) => {
                    return Err(format!("OpenTunnel gave up the certificate of {}: {reason}", record.hostname));
                }
                Cert::Challenge | Cert::Issuing if Instant::now() >= until => {
                    return Err(format!(
                        "the certificate of {} was not ready within {} s; the next start goes on with it",
                        record.hostname,
                        self.limit.as_secs()
                    ));
                }
                Cert::Challenge | Cert::Issuing => tokio::time::sleep(self.poll).await,
            }
            cert =
                self.api.certificate(&record.token, &record.id).await.map_err(|e| {
                    format!("the certificate of {}: {e}; the next start goes on with it", record.hostname)
                })?;
        };
        (record.certificate, record.chain, record.expiry) = (Some(certificate), Some(chain), Some(expiry));
        let path = self.keep(&record).or(path);
        Ok(Provisioned { record, path, made, new_csr })
    }

    /// The certificate of a ready record, as the service holds it now.
    async fn refresh(&self, mut record: Record) -> Refreshed {
        let hostname = record.hostname.clone();
        match self.api.certificate(&record.token, &record.id).await {
            Ok(Cert::Ready { certificate, chain, expiry }) => {
                if record.certificate.as_deref() != Some(certificate.as_str()) {
                    (self.say)(format!("the certificate of {hostname} is renewed, to {expiry}"));
                    (record.certificate, record.chain, record.expiry) = (Some(certificate), Some(chain), Some(expiry));
                    self.keep(&record);
                }
            }
            Err(ApiError::Refused { status: 401 | 404, .. }) => {
                return Refreshed::Gone(format!("OpenTunnel no longer knows the tunnel {hostname}"));
            }
            Ok(_) if unexpired(record.expiry.as_deref()) => {
                (self.say)(format!("OpenTunnel renews the certificate of {hostname}; the one kept serves until then"));
            }
            Err(e) if unexpired(record.expiry.as_deref()) => {
                (self.say)(format!("the certificate of {hostname} was not checked ({e}); the one kept serves"));
            }
            Ok(_) | Err(_) => {
                return Refreshed::Gone(format!("the certificate kept of {hostname} expired and none is ready"));
            }
        }
        let path = self.store.path();
        Refreshed::Kept(Provisioned { record, path, made: false, new_csr: false })
    }

    /// Keep `record`; where it went, or none, which is said: each start then
    /// makes a new tunnel.
    fn keep(&self, record: &Record) -> Option<PathBuf> {
        match self.store.save(record) {
            Ok(path) => Some(path),
            Err(why) => {
                (self.say)(format!(
                    "the tunnel {} could not be kept ({why}): the next start makes a new one",
                    record.hostname
                ));
                None
            }
        }
    }
}

/// What a ready record came to.
enum Refreshed {
    Kept(Provisioned),
    Gone(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);

    impl Entropy for Fixed {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom> {
            buf.iter_mut().for_each(|b| *b = self.0);
            Ok(())
        }
    }

    #[test]
    fn a_route_is_26_letters_of_base32_and_one_label() {
        let route = random_route(&mut Fixed(0)).unwrap();
        assert_eq!(route, "a".repeat(26));
        assert_eq!(random_route(&mut Fixed(31)).unwrap(), "7".repeat(26));
        let route = random_route(&mut OsEntropy).unwrap();
        assert!(super::super::wire::is_route(&route) && route.len() == 26, "{route}");
    }

    #[test]
    fn a_certificate_holds_until_its_expiry() {
        assert!(unexpired(Some("2999-01-01T00:00:00.000Z")));
        assert!(!unexpired(Some("2020-01-01T00:00:00.000Z")));
        assert!(!unexpired(Some("soon")) && !unexpired(None));
    }
}
