//! The iroh road of `podssh ssh node://NAME --iroh-ticket TICKET` (T-164),
//! one road of the race of a node's roads (`crate::ssh::roads`, T-379): its
//! endpoint, made at its first attempt, so that the roads after it need not
//! wait for it. The iroh road of a node's record (T-445) is one too, with
//! the record's finder, so that a node that moved again is found again.
//!
//! A second session of this process to the same node (a copy beside a
//! terminal, T-666) takes a stream of the connection that the first made,
//! in its own lane: `podssh_iroh::share`. The connection and its endpoint
//! close with the last session's road.

use iroh::{EndpointAddr, RelayUrl};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{Dialer, Failure, Finder, Lane, Lease, Options, Udp};
use podssh_relay::session::OsEntropy;
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::OnceCell;

use super::Race;
use crate::ssh::roads::Road;

/// The iroh road: its lease of the node's dialer, taken at its first
/// attempt, so that the pair's road need not wait for it.
pub(crate) struct IrohRoad<'a> {
    race: Race,
    trust: Trust,
    addr: EndpointAddr,
    made: OnceCell<Lease>,
    /// The node's record, asked when the ticket's relay does not reach it.
    finder: Option<Finder>,
    log: &'a Log,
}

impl<'a> IrohRoad<'a> {
    /// The road to the node of `race`'s ticket; else why it is no ticket.
    pub(crate) fn new(race: &Race, trust: &Trust, log: &'a Log) -> Result<IrohRoad<'a>, String> {
        let addr = podssh_iroh::ticket::parse(&race.ticket)?;
        let (race, trust) = (race.clone(), trust.clone());
        Ok(IrohRoad { race, trust, addr, made: OnceCell::new(), finder: None, log })
    }

    /// With `finder`, which asks for the node's record when the ticket's
    /// relay does not reach the node (T-350).
    pub(crate) fn finding(mut self, finder: Finder) -> IrohRoad<'a> {
        self.finder = Some(finder);
        self
    }

    /// The node's identity, which the ticket names, for the channel of
    /// T-088: the node has one key for each road.
    pub(crate) fn node_key(&self) -> podssh_relay::identity::PublicKey {
        keys::identity_key(&self.addr.id)
    }

    async fn lease(&self) -> Result<&Lease, String> {
        // Boxed, as each large future here: the session's whole future is
        // made on a stack of 1 MiB on Windows before it moves to the heap.
        self.made.get_or_try_init(|| Box::pin(self.take())).await
    }

    /// This client's key, then the node's dialer: the one that a session
    /// of this process made, else a new one.
    async fn take(&self) -> Result<Lease, String> {
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
        if let Some(note) = key.path.as_deref().and_then(podssh_relay::cache::kept_note) {
            self.log.info(&format!("this client's iroh key: {note}"));
        }
        let secret = key.secret.clone();
        let lease = podssh_iroh::share::lease(key.public(), self.addr.id, || Box::pin(self.make(secret))).await?;
        if lease.joined() {
            let lane = match lease.lane() {
                Lane::Bulk => "a copy, below a terminal",
                Lane::Interactive => "a session",
            };
            self.log.verbose(&format!("the iroh road: a new stream of this process's connection, for {lane}"));
        }
        Ok(lease)
    }

    /// The first relay that answers (the ticket's first), the endpoint, and
    /// its dialer.
    async fn make(&self, secret: iroh::SecretKey) -> Result<Dialer, String> {
        let mut list: Vec<RelayUrl> = self.addr.relay_urls().cloned().collect();
        for relay in self.race.relays.iter().filter_map(|text| podssh_iroh::relays::parse_url(text).ok()) {
            if !list.contains(&relay) {
                list.push(relay);
            }
        }
        let proxy = ProxyChoice::FromEnvironment;
        let (home, _) = podssh_iroh::relays::home(&list, &self.trust, &proxy).await;
        let options = Options {
            relays: home,
            proxy,
            trust: self.trust.clone(),
            udp: Udp::from_environment(),
            secret: Some(secret),
            accepts: false,
            ..Options::default()
        };
        let opened = podssh_iroh::endpoint::open(&options).await.map_err(|e| e.to_string())?;
        // Which answer the road took of this host's UDP (T-359), and the arm
        // of QUIC's settings when it is not iroh's own (T-665).
        self.log.verbose(&format!("the iroh road: {}", opened.udp));
        for line in opened.quic_lines() {
            self.log.verbose(&format!("the iroh road's {line}"));
        }
        let dialer = Dialer::new(opened.endpoint, self.addr.clone());
        Ok(match &self.finder {
            Some(finder) => dialer.finding(finder.clone()),
            None => dialer,
        })
    }

    pub(crate) async fn link(&self) -> Result<Road, String> {
        match self.lease().await?.link().await {
            Ok(stream) => Ok(Road::Iroh(stream)),
            Err(Failure::Refused) => Err(Failure::Refused.to_string()),
            Err(Failure::Failed(why)) => Err(why),
        }
    }

    /// Whether the node refused this client's key on the iroh road.
    pub(crate) async fn refused(&self) -> bool {
        match self.made.get() {
            Some(lease) => lease.dialer().refused().await,
            None => false,
        }
    }

    /// Which path carried the iroh road's links, once it had one (T-335).
    pub(crate) fn path(&self) -> Option<&'static str> {
        self.made.get().and_then(|lease| lease.dialer().path())
    }

    /// The road's lease given back: the connection and its endpoint close
    /// with the last session's.
    pub(crate) async fn close(&self) {
        if let Some(lease) = self.made.get() {
            lease.release().await;
        }
    }
}
