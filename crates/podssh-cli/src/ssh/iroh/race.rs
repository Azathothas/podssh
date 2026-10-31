//! The iroh road of `podssh ssh node://NAME --iroh-ticket TICKET` (T-164),
//! one road of the race of a node's roads (`crate::ssh::roads`, T-379): its
//! endpoint, made at its first attempt, so that the roads after it need not
//! wait for it.

use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, RelayUrl};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{Dialer, Failure, Options, Udp};
use podssh_relay::session::OsEntropy;
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::OnceCell;

use super::Race;
use crate::ssh::roads::Road;

/// How long the endpoint may take to close after the session.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// The iroh road: its endpoint, made at its first attempt, so that the
/// pair's road need not wait for it.
pub(crate) struct IrohRoad<'a> {
    race: &'a Race,
    trust: &'a Trust,
    addr: EndpointAddr,
    made: OnceCell<(Endpoint, Dialer)>,
    log: &'a Log,
}

impl<'a> IrohRoad<'a> {
    /// The road to the node of `race`'s ticket; else why it is no ticket.
    pub(crate) fn new(race: &'a Race, trust: &'a Trust, log: &'a Log) -> Result<IrohRoad<'a>, String> {
        let addr = podssh_iroh::ticket::parse(&race.ticket)?;
        Ok(IrohRoad { race, trust, addr, made: OnceCell::new(), log })
    }

    /// The node's identity, which the ticket names, for the channel of
    /// T-088: the node has one key for each road.
    pub(crate) fn node_key(&self) -> podssh_relay::identity::PublicKey {
        keys::identity_key(&self.addr.id)
    }

    async fn dialer(&self) -> Result<&Dialer, String> {
        // Boxed, as each large future here: the session's whole future is
        // made on a stack of 1 MiB on Windows before it moves to the heap.
        let made = self.made.get_or_try_init(|| Box::pin(self.make())).await?;
        Ok(&made.1)
    }

    /// This client's key, the first relay that answers (the ticket's
    /// first), and the endpoint.
    async fn make(&self) -> Result<(Endpoint, Dialer), String> {
        let place = match &self.race.key {
            Some(file) => Place::File(file.into()),
            None => keys::client_place(),
        };
        let key = keys::load(&place, &mut OsEntropy).map_err(|why| format!("this client's key: {why}"))?;
        let fingerprint = keys::fingerprint(&key.public());
        if key.made {
            self.log.info(&format!(
                "a new iroh key for this client: {fingerprint}; a node lets it in once its allowlist holds it"
            ));
        }
        let mut list: Vec<RelayUrl> = self.addr.relay_urls().cloned().collect();
        for relay in self.race.relays.iter().filter_map(|text| podssh_iroh::relays::parse_url(text).ok()) {
            if !list.contains(&relay) {
                list.push(relay);
            }
        }
        let proxy = ProxyChoice::FromEnvironment;
        let (home, _) = podssh_iroh::relays::home(&list, self.trust, &proxy).await;
        let options = Options {
            relays: home,
            proxy,
            trust: self.trust.clone(),
            udp: Udp::from_environment(),
            secret: Some(key.secret.clone()),
            accepts: false,
            ..Options::default()
        };
        let opened = podssh_iroh::endpoint::open(&options).await.map_err(|e| e.to_string())?;
        // Which answer the road took of this host's UDP (T-359).
        self.log.verbose(&format!("the iroh road: {}", opened.udp));
        let endpoint = opened.endpoint;
        Ok((endpoint.clone(), Dialer::new(endpoint, self.addr.clone())))
    }

    pub(crate) async fn link(&self) -> Result<Road, String> {
        match self.dialer().await?.link().await {
            Ok(stream) => Ok(Road::Iroh(stream)),
            Err(Failure::Refused) => Err(Failure::Refused.to_string()),
            Err(Failure::Failed(why)) => Err(why),
        }
    }

    /// Whether the node refused this client's key on the iroh road.
    pub(crate) async fn refused(&self) -> bool {
        match self.made.get() {
            Some((_, dialer)) => dialer.refused().await,
            None => false,
        }
    }

    /// Which path carried the iroh road's links, once it had one (T-335).
    pub(crate) fn path(&self) -> Option<&'static str> {
        self.made.get().and_then(|(_, dialer)| dialer.path())
    }

    pub(crate) async fn close(&self) {
        if let Some((endpoint, dialer)) = self.made.get() {
            dialer.close().await;
            let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
        }
    }
}
