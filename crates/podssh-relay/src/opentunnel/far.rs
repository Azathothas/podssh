//! The node of the OpenTunnel road: its tunnel, made once and kept
//! ([`super::provision`]); a bridge that claims the node's route alone,
//! attached again after each loss with the protocol's backoff, from 250 ms
//! to 30 s with jitter, again from the start after each attach; and each
//! visitor's connection, whose TLS podssh-ws's server ends with the tunnel's
//! certificate and key, served by the resumable layer's far end with the
//! node's keeper, which another road may share, so that a session resumes on
//! either. A new session reaches its target only after its handshake, and
//! the end-to-end channel above it. The service renews the certificate with
//! the same CSR: the node asks for it each 12 hours, each minute in its last
//! 30 days, and presents a new one from the next handshake on.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls_server::{self, Served};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};

use super::api::{Api, Cert};
use super::bridge::{self, Failed};
use super::conn::Visitor;
use super::provision::{unexpired, Provision, Provisioned};
use super::record::{expiry_secs, Credentials, Record, Store};
use super::Say;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::{far, Settings};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// The bound of a visitor's TLS handshake.
pub const TLS_LIMIT: Duration = Duration::from_secs(20);
/// The waits between bridges: the protocol's.
const RECONNECT_FIRST: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// The wait after `cert_not_ready`, which the service may say while it
/// moves a tunnel's record: long, as each try costs it an attach.
const NOT_READY_WAIT: Duration = Duration::from_secs(60);
/// How often the certificate is asked for, and in its last 30 days.
const CHECK_FRESH: Duration = Duration::from_secs(12 * 3600);
const CHECK_DUE: Duration = Duration::from_secs(60);
const RENEWAL_WINDOW: i64 = 30 * 86_400;

/// A node of the OpenTunnel road.
pub struct Node {
    pub api: Api,
    pub record: Record,
    /// Where the record is kept, for a renewed certificate.
    pub store: Option<Store>,
    /// The tunnel's certificate and key, as the node's TLS presents them.
    pub served: Arc<Served>,
    pub say: Say,
}

impl Node {
    /// The node of `record`, whose certificate is ready.
    pub fn new(api: Api, record: Record, store: Option<Store>, say: Say) -> Result<Node, String> {
        let chain = record.chain_pem().ok_or("the tunnel's certificate is not ready")?;
        let pair = tls_server::certified(chain.as_bytes(), record.key.as_bytes())
            .map_err(|why| format!("the tunnel's certificate: {why}"))?;
        Ok(Node { api, record, store, served: Served::new(Some(pair)), say })
    }

    /// The name that a client dials: the node's route under the tunnel.
    pub fn name(&self) -> String {
        self.record.name()
    }
}

/// The node's tunnel, made or kept by `store`, and the node of it.
pub async fn online(
    api: Api,
    store: Store,
    credentials: &dyn Credentials,
    say: Say,
) -> Result<(Node, Provisioned), String> {
    let provisioned = Provision::new(&api, &store, credentials, &say).run().await?;
    let node = Node::new(api, provisioned.record.clone(), Some(store), say)?;
    Ok((node, provisioned))
}

/// The wait before bridge `attempt`, from 0.
fn reconnect_wait(attempt: u32) -> Duration {
    let base = RECONNECT_FIRST.saturating_mul(1u32 << attempt.min(16)).min(RECONNECT_MAX);
    let ms = base.as_millis() as u64;
    Duration::from_millis(rand::rng().random_range(ms / 2..=ms))
}

/// Serve the sessions of each visitor of `node`, with a keeper of its own,
/// until the service refuses the tunnel for good: why.
pub async fn serve<A, O, F>(node: Node, settings: Settings, budget: usize, open: O) -> String
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    serve_kept(node, settings, budget, open, keeper).await
}

/// [`serve`] with `keeper`, which another road's far end may share. It ends
/// only when the service refuses the tunnel's token, or knows no tunnel.
pub async fn serve_kept<A, O, F>(
    node: Node,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
) -> String
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
    let renewal = tokio::spawn(renew(
        node.api.clone(),
        node.record.clone(),
        node.store.clone(),
        node.served.clone(),
        node.say.clone(),
    ));
    let acceptor = match tls_server::acceptor_for(node.served.clone(), &[]) {
        Ok(acceptor) => acceptor,
        Err(why) => {
            renewal.abort();
            return format!("the node's TLS: {why}");
        }
    };
    let (say, name) = (node.say.clone(), node.name());
    let routes = vec![node.record.route.clone()];
    let opened = |visitor: Visitor| {
        let (acceptor, keeper, open, say) = (acceptor.clone(), keeper.clone(), open.clone(), say.clone());
        tokio::spawn(async move {
            let peer = visitor.peer.clone();
            let tls = match tokio::time::timeout(TLS_LIMIT, acceptor.accept(visitor)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => return say(format!("a visitor from {peer}: TLS failed: {e}")),
                Err(_) => return say(format!("a visitor from {peer}: no TLS within {} s", TLS_LIMIT.as_secs())),
            };
            far::serve(tls, Role::NODE, settings, &keeper, budget, open).await;
        });
    };
    let (mut attempt, mut attached_once) = (0u32, false);
    let why = loop {
        match bridge::attach(&node.api, &node.record.id, &node.record.token, &routes).await {
            Ok((session, attached)) => {
                attempt = 0;
                let again = if attached_once { " again" } else { "" };
                say(format!("attached{again} to OpenTunnel at {}: a client dials {name}", node.api.service()));
                attached_once = true;
                let ended = bridge::serve(session, &attached, &node.record.hostname, &routes, &opened).await;
                say(format!("the bridge to OpenTunnel ended: {ended}"));
            }
            Err(Failed::Fatal(why)) => break why,
            Err(Failed::NotReady(why)) => {
                say(format!("{why}; again in {} s", NOT_READY_WAIT.as_secs()));
                tokio::time::sleep(NOT_READY_WAIT).await;
                continue;
            }
            Err(Failed::Again(why)) => say(format!("no bridge to OpenTunnel: {why}")),
        }
        let wait = reconnect_wait(attempt);
        attempt = attempt.saturating_add(1);
        say(format!("a bridge to OpenTunnel again in {} ms", wait.as_millis()));
        tokio::time::sleep(wait).await;
    };
    renewal.abort();
    why
}

/// Whether a certificate that expires at `expiry` is in its last 30 days.
fn due(expiry: Option<&str>) -> bool {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    expiry.and_then(expiry_secs).is_none_or(|ends| ends - now < RENEWAL_WINDOW)
}

/// Ask for the certificate each 12 hours, each minute in its last 30 days:
/// a renewed one is presented from the next handshake on, and kept.
async fn renew(api: Api, mut record: Record, store: Option<Store>, served: Arc<Served>, say: Say) {
    loop {
        tokio::time::sleep(if due(record.expiry.as_deref()) { CHECK_DUE } else { CHECK_FRESH }).await;
        let Ok(Cert::Ready { certificate, chain, expiry }) = api.certificate(&record.token, &record.id).await else {
            if !unexpired(record.expiry.as_deref()) {
                say(format!("the certificate of {} expired, and the service has no new one yet", record.hostname));
            }
            continue;
        };
        if record.certificate.as_deref() == Some(certificate.as_str()) {
            continue;
        }
        let next =
            Record { certificate: Some(certificate), chain: Some(chain), expiry: Some(expiry), ..record.clone() };
        let pem = next.chain_pem().unwrap_or_default();
        match tls_server::certified(pem.as_bytes(), next.key.as_bytes()) {
            Ok(pair) => served.set(pair),
            Err(why) => {
                say(format!("a renewed certificate that does not fit the tunnel's key was not taken: {why}"));
                continue;
            }
        }
        say(format!("the certificate of {} is renewed, to {}", next.hostname, next.expiry.as_deref().unwrap_or("?")));
        if let Some(store) = &store {
            if let Err(why) = store.save(&next) {
                say(format!("the renewed certificate was not kept: {why}"));
            }
        }
        record = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_waits_between_bridges_double_from_250_ms_to_30_s() {
        for attempt in 0..20 {
            let wait = reconnect_wait(attempt);
            let base = RECONNECT_FIRST.saturating_mul(1u32 << attempt.min(16)).min(RECONNECT_MAX);
            assert!(wait >= base / 2 && wait <= base, "{attempt}: {wait:?}");
        }
        assert!(reconnect_wait(30) <= RECONNECT_MAX);
    }

    #[test]
    fn a_certificate_is_due_in_its_last_30_days() {
        assert!(!due(Some("2999-01-01T00:00:00Z")));
        assert!(due(Some("2020-01-01T00:00:00Z")) && due(None));
    }
}
