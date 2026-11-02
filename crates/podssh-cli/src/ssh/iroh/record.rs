//! The roads of a node's record (T-445): `podssh ssh node://NAME` to a
//! member of the net, whose key the net names, asks the member's record of
//! pkarr and races each road that it names and that no ticket gave: the
//! iroh road at its home relay, the DERP road at its DERP home, and its
//! quick tunnel. The record is asked only once each road before it failed,
//! as T-350 asks it only when the ticket's relay fails; it is kept for its
//! names' life, then asked again at the next race. The record is the
//! node's word, signed by the key that the net names; the end-to-end channel
//! checks that key on each road, so a road of a record reaches the node or
//! nothing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{EndpointAddr, PublicKey};
use podssh_iroh::pkarr::{self, Finder, Record, Roads};
use podssh_relay::derp::{servers, Dialer, Server, Ticket};
use podssh_relay::identity::KeyName;
use podssh_relay::session::race::{Start, HEAD_START};
use podssh_ssh::Log;
use podssh_ws::cloudflare::Access;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::OnceCell;
use tokio::time::Instant;

use super::{IrohRoad, Race};
use crate::relay_settings::Refusal;
use crate::ssh::roads::{Going, Road};

/// How long a record is kept: the life of its names in a cache of DNS.
const KEEP: Duration = Duration::from_secs(pkarr::TTL as u64);

/// The roads' names, in the race's lines.
const IROH: &str = "the iroh road of its record";
const DERP: &str = "the DERP road of its record";
const QUICK: &str = "the quick tunnel of its record";

/// What the record of a run is asked for, decided before anything connects.
#[derive(Debug, Clone)]
pub(crate) struct RecordAsk {
    key: PublicKey,
    server: pkarr::Server,
    /// The relays after the record's, when its iroh road races: no
    /// --iroh-ticket and no iroh ticket of the net.
    iroh: Option<Vec<String>>,
    /// The DERP servers after the record's home, when its DERP road races:
    /// no DERP ticket given, of the net, or kept, and PODSSH_DERP not no.
    derp: Option<Vec<Server>>,
    /// This client's key file, of --client-key.
    client_key: Option<String>,
}

/// The record of the member `label`, when this run asks one: the net names
/// the member by its key (a fingerprint alone is no key to ask by), the
/// end-to-end channel is on, and a server of pkarr is chosen (n0's for n0's
/// relays, else that of PODSSH_IROH_PKARR). A bad variable is a
/// configuration error (78), before anything connects.
pub(crate) fn record_ask(
    label: &str,
    iroh_given: bool,
    derp: &crate::ssh::derp::Race,
    channel: &crate::channel::Ask,
) -> Result<Option<RecordAsk>, Refusal> {
    let Some(member) = crate::net::lookup::member(label).filter(|_| !channel.off) else { return Ok(None) };
    let KeyName::Key(key) = member.key else { return Ok(None) };
    let Ok(key) = PublicKey::from_bytes(&key.0) else { return Ok(None) };
    let (relays, _) = podssh_iroh::relays::from_environment(None).map_err(Refusal::config)?;
    let Some(server) = pkarr::choose(&relays).map_err(Refusal::config)? else { return Ok(None) };
    let iroh = (!iroh_given).then(|| relays.iter().map(ToString::to_string).collect());
    let derp = (derp.fallback && derp.road(label).is_none()).then(|| derp.servers.clone());
    Ok(Some(RecordAsk { key, server, iroh, derp, client_key: channel.client_key.clone() }))
}

/// The roads of the record in one run: the record, once asked; the iroh
/// road, made from the first record that names a relay; the DERP road's
/// dialers, one for each DERP home that a record named.
pub(crate) struct RecordRoads<'a> {
    ask: &'a RecordAsk,
    trust: &'a Trust,
    log: &'a Arc<Log>,
    shown: &'a str,
    looked: tokio::sync::Mutex<Option<(Instant, Result<Record, String>)>>,
    iroh: OnceCell<IrohRoad<'a>>,
    derp: Mutex<Vec<(Ticket, Arc<Dialer>)>>,
}

impl<'a> RecordRoads<'a> {
    pub(crate) fn new(ask: &'a RecordAsk, trust: &'a Trust, log: &'a Arc<Log>, shown: &'a str) -> RecordRoads<'a> {
        let (looked, iroh, derp) = (Default::default(), OnceCell::new(), Mutex::new(Vec::new()));
        RecordRoads { ask, trust, log, shown, looked, iroh, derp }
    }

    /// The attempts of one race, each with its start and its name: the
    /// first only once each road before it failed, each next 250 ms after.
    pub(crate) fn race(&self) -> Vec<(Start, Going<'_>, &'static str)> {
        let mut list: Vec<(Start, Going<'_>, &'static str)> = Vec::new();
        if self.ask.iroh.is_some() {
            list.push((Start::After(HEAD_START), Box::pin(self.iroh_link()), IROH));
        }
        if self.ask.derp.is_some() {
            list.push((Start::After(HEAD_START), Box::pin(self.derp_link()), DERP));
        }
        list.push((Start::After(HEAD_START), Box::pin(self.quick_link()), QUICK));
        if let Some(first) = list.first_mut() {
            first.0 = Start::WhenAllFailed;
        }
        list
    }

    /// The record: kept for [`KEEP`], else asked again, once at a time.
    async fn record(&self) -> Result<Record, String> {
        let mut looked = self.looked.lock().await;
        if let Some((_, found)) = looked.as_ref().filter(|(at, _)| at.elapsed() < KEEP) {
            return found.clone();
        }
        let found = Box::pin(self.look()).await;
        *looked = Some((Instant::now(), found.clone()));
        found
    }

    async fn look(&self) -> Result<Record, String> {
        let (shown, host) = (self.shown, self.ask.server.host().to_string());
        self.log.verbose(&format!("{shown}: asking the node's record at {host}, by the key that the net names"));
        let finder = Finder::new(self.ask.server.clone(), self.trust.clone(), ProxyChoice::FromEnvironment);
        match finder.find(&self.ask.key).await {
            Ok(Some(record)) => {
                let (relay, derp, quick) = (record.relays.first().cloned(), record.derp.clone(), record.quick.clone());
                let roads = Roads { relay, derp, quick };
                self.log.verbose(&format!("{shown}: its record at {host} names {}", roads.said()));
                for why in &record.set_aside {
                    self.log.verbose(&format!("{shown}: of its record, {why}"));
                }
                Ok(record)
            }
            Ok(None) => Err(format!("it has no record at {host}")),
            Err(why) => Err(format!("its record at {host}: {why}")),
        }
    }

    async fn iroh_link(&self) -> Result<Road, String> {
        let record = self.record().await?;
        let road = self.iroh.get_or_try_init(|| async { self.iroh_road(&record) }).await?;
        road.link().await
    }

    /// The iroh road of the record's relays, with the record's finder, so
    /// that a node whose home moved again is found there.
    fn iroh_road(&self, record: &Record) -> Result<IrohRoad<'a>, String> {
        let (Some(relays), false) = (&self.ask.iroh, record.relays.is_empty()) else {
            return Err("its record names no iroh relay".into());
        };
        let addr = record.relays.iter().cloned().fold(EndpointAddr::new(self.ask.key), EndpointAddr::with_relay_url);
        let (ticket, key) = (podssh_iroh::ticket::format(&addr), self.ask.client_key.clone());
        let race = Race { ticket, key, relays: relays.clone() };
        let finder = Finder::new(self.ask.server.clone(), self.trust.clone(), ProxyChoice::FromEnvironment);
        Ok(IrohRoad::new(&race, self.trust, &**self.log)?.finding(finder))
    }

    async fn derp_link(&self) -> Result<Road, String> {
        let record = self.record().await?;
        let (Some(servers), Some(ticket)) = (&self.ask.derp, record.derp) else {
            return Err("its record names no DERP home".into());
        };
        let dialer = self.derp_dialer(&ticket, servers)?;
        dialer.link().await.map(Road::Derp)
    }

    /// The dialer of `ticket`: the one made for it, else a new one, the
    /// record's home first, then the client's list. An older one stays, as
    /// a link of it may carry the session.
    fn derp_dialer(&self, ticket: &Ticket, list: &[Server]) -> Result<Arc<Dialer>, String> {
        let mut made = self.derp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, dialer)) = made.iter().find(|(had, _)| had == ticket) {
            return Ok(dialer.clone());
        }
        let order = servers::for_client_in(&ticket.server, list);
        let dialer = Arc::new(crate::ssh::derp::dialer(ticket, &order, self.trust, self.log, self.shown)?);
        made.push((ticket.clone(), dialer.clone()));
        Ok(dialer)
    }

    /// A new WebSocket to the record's quick tunnel, which no Access guards.
    async fn quick_link(&self) -> Result<Road, String> {
        let record = self.record().await?;
        let Some(name) = record.quick else { return Err("its record names no quick tunnel".into()) };
        let opened = crate::ssh::cloudflare::open(&name, &Access::default(), self.trust).await;
        opened.map(Road::Tunnel).map_err(|(line, _)| line)
    }

    /// Which road of the record carried the session, for `-v`.
    pub(crate) async fn carried(&self) -> Option<String> {
        if let Some(path) = self.iroh.get().and_then(IrohRoad::path) {
            return Some(format!("{IROH}: {path}"));
        }
        let dialers: Vec<Arc<Dialer>> = self.dialers();
        for dialer in dialers {
            if let Some(server) = dialer.server().await {
                return Some(format!("{DERP}: the DERP server {server}"));
            }
        }
        None
    }

    fn dialers(&self) -> Vec<Arc<Dialer>> {
        let made = self.derp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        made.iter().map(|(_, dialer)| dialer.clone()).collect()
    }

    pub(crate) async fn close(&self) {
        for dialer in self.dialers() {
            dialer.close().await;
        }
        if let Some(iroh) = self.iroh.get() {
            iroh.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn race(ticket: Option<Ticket>, fallback: bool) -> crate::ssh::derp::Race {
        crate::ssh::derp::Race { ticket, servers: vec![Server::parse("tc301a.ipn.dev").unwrap()], fallback }
    }

    fn ask(iroh: bool, derp: bool) -> RecordAsk {
        RecordAsk {
            key: iroh::SecretKey::from_bytes(&[5; 32]).public(),
            server: pkarr::Server::parse("https://pkarr.example/pkarr").unwrap(),
            iroh: iroh.then(Vec::new),
            derp: derp.then(|| vec![Server::parse("tc301a.ipn.dev").unwrap()]),
            client_key: None,
        }
    }

    #[test]
    fn a_label_that_the_net_does_not_name_by_its_key_asks_no_record() {
        // No net here: the label is no member, so no record is asked, and
        // the variable is not even read.
        let channel = crate::channel::Ask::default();
        assert!(record_ask("not-a-member-of-any-net", false, &race(None, true), &channel).unwrap().is_none());
    }

    #[test]
    fn the_record_s_first_road_waits_for_each_road_before_it_and_the_next_follow_it() {
        let (log, trust) = (Arc::new(Log::new(podssh_ssh::LogLevel::Quiet)), Trust::Default);
        for (iroh, derp, names) in [
            (true, true, vec![IROH, DERP, QUICK]),
            (false, true, vec![DERP, QUICK]),
            (true, false, vec![IROH, QUICK]),
            (false, false, vec![QUICK]),
        ] {
            let ask = ask(iroh, derp);
            let roads = RecordRoads::new(&ask, &trust, &log, "node://lab");
            let list = roads.race();
            let got: Vec<&str> = list.iter().map(|(_, _, name)| *name).collect();
            assert_eq!(got, names);
            assert_eq!(list[0].0, Start::WhenAllFailed, "the record is asked once each road before it failed");
            assert!(list[1..].iter().all(|(start, _, _)| *start == Start::After(HEAD_START)));
        }
    }
}
