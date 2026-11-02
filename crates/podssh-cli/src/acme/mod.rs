//! The ACME client of `podssh relay serve --acme NAME` (T-447, RFC 8555): a
//! certificate for NAME from a CA (Let's Encrypt by default), proven by
//! TLS-ALPN-01 on the role's own listener (RFC 8737), so that nothing else
//! listens and port 443 alone is needed; kept in the cache and renewed in
//! the role before its end. Its keys are P-256 keys of aws-lc-rs, which the
//! binary links already; rule 4 of `AGENTS.md` keeps C out of the library
//! crates, so the client is here and the server's TLS stays podssh-ws's.

pub mod certs;
pub mod client;
pub mod jws;
pub mod order;
pub mod store;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls_server::Served;
use podssh_ws::{ProxyChoice, Trust};
use rustls::sign::CertifiedKey;

use certs::Leaf;
use client::{Client, Http};
use store::Store;

use crate::relay_settings::Refusal;

/// Let's Encrypt's directory, the default CA.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// A certificate is renewed this long before its end, or at a third of its
/// life left when that is shorter, as Let's Encrypt advises.
pub const RENEW_BEFORE: i64 = 30 * 86_400;
/// The first wait after a renewal failed, doubled at each failure after it.
pub const FIRST_RETRY: Duration = Duration::from_secs(300);
pub const MOST_RETRY: Duration = Duration::from_secs(6 * 3600);
/// The limit of one request to the CA.
const REQUEST: Duration = Duration::from_secs(30);
/// The limit of one whole order, its challenges and polls included.
const ORDER: Duration = Duration::from_secs(600);
/// A sleep until a renewal wakes this often, so that a clock that jumped,
/// or a host that slept, is seen.
const NAP: Duration = Duration::from_secs(3600);

/// Where the lines of the role go: each is said on its stderr.
pub type Say = tokio::sync::mpsc::UnboundedSender<String>;

/// A name's certificate at one CA.
#[derive(Debug, Clone)]
pub struct Acme {
    pub name: String,
    pub directory: String,
    pub http: Http,
    pub store: Store,
}

impl Acme {
    /// The client for `name` at the CA of `directory` (Let's Encrypt when
    /// `None`), whose TLS is checked against `trust`.
    pub fn new(name: &str, directory: Option<&str>, trust: Trust) -> Result<Acme, Refusal> {
        let directory = directory.unwrap_or(LETS_ENCRYPT).to_string();
        crate::update::fetch::Url::parse(&directory)
            .map_err(|why| Refusal::usage(format!("--acme-directory {directory}: {why}")))?;
        let store = Store::open(&directory, name)?;
        let http = Http { trust, proxy: ProxyChoice::FromEnvironment, timeout: REQUEST };
        Ok(Acme { name: name.to_string(), directory, http, store })
    }

    /// The CA's host, for a line.
    pub fn host(&self) -> String {
        crate::update::fetch::Url::parse(&self.directory).map(|u| u.host).unwrap_or_default()
    }

    /// The certificate kept for the name, while it holds: served at once.
    pub fn held(&self, now_secs: i64) -> Result<Option<(Arc<CertifiedKey>, Leaf)>, String> {
        let Some(text) = self.store.held()? else { return Ok(None) };
        let (pair, leaf) = certs::load(text.as_bytes(), text.as_bytes())
            .map_err(|why| format!("{}: {why}", self.store.pem_path().display()))?;
        if !leaf.names.contains(&self.name) || leaf.not_after <= now_secs {
            return Ok(None);
        }
        Ok(Some((pair, leaf)))
    }

    /// Order a certificate, keep it, and serve it from the next handshake.
    pub async fn obtain(&self, served: &Served, say: &Say) -> Result<Leaf, String> {
        let account = self.store.account()?;
        let mut client = Client::open(self.http.clone(), &self.directory, account).await?;
        if client.account().await? {
            let terms = client.directory.terms.clone().map(|t| format!(", under its terms ({t})")).unwrap_or_default();
            let _ = say.send(format!("a new account at {}{terms}", self.host()));
        }
        let issued = match tokio::time::timeout(ORDER, order::order(&mut client, &self.name, served)).await {
            Ok(issued) => issued?,
            Err(_) => return Err(format!("no certificate within {} s", ORDER.as_secs())),
        };
        let path = self.store.keep(&issued.key, &issued.chain)?;
        // What is served is what was kept: the file, read again.
        let text = self.store.held()?.ok_or_else(|| format!("{} is gone", path.display()))?;
        let (pair, leaf) = certs::load(text.as_bytes(), text.as_bytes())?;
        served.set(pair);
        Ok(leaf)
    }
}

/// When a certificate of this life is renewed: 30 days before its end, or
/// at a third of its life left for a shorter one.
pub fn renew_at(leaf: &Leaf) -> i64 {
    let life = leaf.not_after.saturating_sub(leaf.not_before).max(0);
    leaf.not_after - (life / 3).min(RENEW_BEFORE)
}

/// The wait after a renewal that failed, when the wait before it was `last`.
pub fn next_retry(last: Duration) -> Duration {
    (last * 2).min(MOST_RETRY)
}

/// "for NAME, until DATE", of a leaf.
pub fn about(leaf: &Leaf) -> String {
    let names = if leaf.names.is_empty() { "no DNS name".to_string() } else { leaf.names.join(", ") };
    format!("for {names}, until {}", crate::pairs::utc(leaf.not_after.saturating_mul(1000)))
}

/// Keep the name's certificate for as long as the role runs: the first one
/// now when `held` is none, then each renewal at its time. A renewal that
/// fails is said and asked again later, and the certificate of before stays.
/// Ends only when there is no certificate to serve: the first order failed.
pub async fn keep(acme: Acme, served: Arc<Served>, mut held: Option<Leaf>, say: Say) -> String {
    let mut wait = FIRST_RETRY;
    loop {
        if let Some(leaf) = &held {
            sleep_until(renew_at(leaf)).await;
        }
        match acme.obtain(&served, &say).await {
            Ok(leaf) => {
                let (from, renewed) = (acme.host(), crate::pairs::utc(renew_at(&leaf).saturating_mul(1000)));
                let _ = say.send(format!("a certificate from {from} {}; renewed from {renewed}", about(&leaf)));
                held = Some(leaf);
                wait = FIRST_RETRY;
            }
            Err(why) => match &held {
                None => return format!("ACME at {}: {why}; no certificate for {} to serve", acme.host(), acme.name),
                Some(leaf) => {
                    let _ = say.send(format!(
                        "the renewal of the certificate {} failed: {why}; it stays, and ACME is asked again in {} min",
                        about(leaf),
                        wait.as_secs() / 60
                    ));
                    tokio::time::sleep(wait).await;
                    wait = next_retry(wait);
                }
            },
        }
    }
}

/// Sleep until `at`, seconds since the epoch, by the wall clock.
async fn sleep_until(at: i64) {
    loop {
        let left = at.saturating_sub(order::now_secs());
        if left <= 0 {
            return;
        }
        tokio::time::sleep(NAP.min(Duration::from_secs(left as u64))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(not_before: i64, days: i64) -> Leaf {
        Leaf { names: vec!["relay.podssh.test".into()], not_before, not_after: not_before + days * 86_400 }
    }

    #[test]
    fn a_certificate_is_renewed_30_days_before_its_end_or_at_a_third_of_a_short_life() {
        // Let's Encrypt's 90 days: day 60.
        assert_eq!(renew_at(&leaf(0, 90)), 60 * 86_400);
        // A life of a year: still 30 days before.
        assert_eq!(renew_at(&leaf(0, 365)), 335 * 86_400);
        // Six days (Let's Encrypt's short-lived profile): two days before.
        assert_eq!(renew_at(&leaf(0, 6)), 4 * 86_400);
        // Pebble's 180 s of the harness: 60 s before.
        let short = Leaf { names: vec![], not_before: 1000, not_after: 1180 };
        assert_eq!(renew_at(&short), 1120);
    }

    #[test]
    fn a_failed_renewal_is_asked_again_later_each_time_up_to_6_hours() {
        let mut wait = FIRST_RETRY;
        let mut waits = vec![wait.as_secs()];
        for _ in 0..8 {
            wait = next_retry(wait);
            waits.push(wait.as_secs());
        }
        assert_eq!(waits, [300, 600, 1200, 2400, 4800, 9600, 19200, 21600, 21600]);
    }

    #[test]
    fn a_leaf_is_said_with_its_names_and_its_end() {
        assert_eq!(about(&leaf(1_793_620_800, 90)), "for relay.podssh.test, until 2027-01-31T12:00:00Z");
    }
}
