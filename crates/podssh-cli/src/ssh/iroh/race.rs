//! `podssh ssh node://NAME --iroh-ticket TICKET` (T-164): the iroh road to
//! the node's ticket and the reverse road of its pair, raced at the start
//! and at each resume: the iroh road first, the pair's road after 250 ms, or
//! at once when the iroh road fails before; the first far end that speaks
//! carries the session, and the other link ends before it sends a byte.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, RelayUrl};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{Dialer, Failure, Options, Udp};
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_relay::session::race::{race, Won, HEAD_START};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{client, Ask, End, Ended, OsEntropy};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;

use super::Race;
use crate::layered::{self, Line};

/// Each direction of the pipes between SSH, the layer and a leg.
const PIPE: usize = 256 * 1024;
/// How long the endpoint may take to close after the session.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// A link on either road.
pub enum Road {
    Iroh(podssh_iroh::Stream),
    Pair(DuplexStream),
}

impl AsyncRead for Road {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Iroh(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Road {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Road::Iroh(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Iroh(link) => Pin::new(link).poll_flush(cx),
            Road::Pair(link) => Pin::new(link).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Iroh(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pair(link) => Pin::new(link).poll_shutdown(cx),
        }
    }
}

/// The iroh road: its endpoint, made at its first attempt, so that the
/// pair's road need not wait for it.
struct Iroh<'a> {
    race: &'a Race,
    trust: &'a Trust,
    addr: EndpointAddr,
    made: OnceCell<(Endpoint, Dialer)>,
    log: &'a Log,
}

impl Iroh<'_> {
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
        let endpoint = podssh_iroh::bind(&options).await.map_err(|e| e.to_string())?;
        Ok((endpoint.clone(), Dialer::new(endpoint, self.addr.clone())))
    }

    async fn link(&self) -> Result<Road, String> {
        match self.dialer().await?.link().await {
            Ok(stream) => Ok(Road::Iroh(stream)),
            Err(Failure::Refused) => Err(Failure::Refused.to_string()),
            Err(Failure::Failed(why)) => Err(why),
        }
    }

    /// Whether the node refused this client's key on the iroh road.
    async fn refused(&self) -> bool {
        match self.made.get() {
            Some((_, dialer)) => dialer.refused().await,
            None => false,
        }
    }

    async fn close(&self) {
        if let Some((endpoint, dialer)) = self.made.get() {
            dialer.close().await;
            let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
        }
    }
}

/// SSH to the node of the pair under `label`, over the iroh road of `race`
/// or the pair's road, whichever answers first, again at each resume.
pub(in crate::ssh) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    race_road: &Race,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let shown = format!("{}{label}", crate::ssh::node::SCHEME);
    let part = match crate::pairs::operator_part(label, pair_file).and_then(|part| {
        crate::pairs::online()?;
        Ok(part)
    }) {
        Ok(part) => part,
        Err(refusal) => {
            log.error(&format!("{shown}: {}", refusal.message));
            return EXIT_FAILURE;
        }
    };
    let addr = match podssh_iroh::ticket::parse(&race_road.ticket) {
        Ok(addr) => addr,
        Err(why) => {
            log.error(&why);
            return EXIT_FAILURE;
        }
    };
    // The channel of T-088, to the node that the ticket names, on whichever
    // road wins: the node has one key for both.
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let ticket_key = podssh_iroh::keys::identity_key(&addr.id);
    let channel = match ask.operator(crate::channel::Expect::Ticket(ticket_key), &say_line) {
        Ok(channel) => channel,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    let iroh = Iroh { race: race_road, trust, addr, made: OnceCell::new(), log: &log };
    let legs: Mutex<Option<JoinHandle<LegOutcome>>> = Mutex::new(None);
    let pair_final = AtomicBool::new(false);
    let (config, legs_ref, pair_final_ref) = (&config, &legs, &pair_final);
    // The pair's road: a new leg, unless the last one ended with a close
    // that a new leg would only get again.
    let pair = move |previous: Option<JoinHandle<LegOutcome>>| async move {
        if let Some(handle) = previous {
            if let Ok(Ok(outcome)) = tokio::time::timeout(layered::LEG_WAIT, handle).await {
                if let Some(stop) = layered::stops(&outcome) {
                    pair_final_ref.store(true, Ordering::SeqCst);
                    return Err(stop);
                }
            }
        }
        if pair_final_ref.load(Ordering::SeqCst) {
            return Err("the pair's road ended for good".to_string());
        }
        let (link, leg_end) = tokio::io::duplex(PIPE);
        match operator::start(config, leg_end).await {
            Ok(handle) => {
                *layered::lock(legs_ref) = Some(handle);
                Ok(Road::Pair(link))
            }
            Err(e) => {
                if layered::is_final(&e) {
                    pair_final_ref.store(true, Ordering::SeqCst);
                }
                Err(crate::pairs::connect_refusal(&e, label).message)
            }
        }
    };
    log.verbose(&format!(
        "connecting to {shown}: the iroh road first, the pair's road {} ms after",
        HEAD_START.as_millis()
    ));
    let first = match race(Box::pin(iroh.link()), Box::pin(pair(None)), HEAD_START).await {
        Ok((won, took)) => winner(won, took, &shown, &log),
        Err(lost) => {
            let refused = if iroh.refused().await { " (the node refused this client's key)" } else { "" };
            log.error(&format!(
                "{shown}: no road reached the node: the iroh road: {}{refused}; the pair's road: {}",
                lost.first, lost.second
            ));
            iroh.close().await;
            return EXIT_FAILURE;
        }
    };
    let settings = layered::settings();
    let client = match Box::pin(client::start(first, Ask::New, settings, &mut OsEntropy)).await {
        Ok(client) => client,
        Err(e) => {
            log.error(&format!("{shown}: {e}"));
            iroh.close().await;
            return EXIT_FAILURE;
        }
    };
    log.verbose(&format!("{shown}: {}", client.found()));
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    };
    let (iroh_ref, shown_ref, log_ref) = (&iroh, &shown, &log);
    // Each resume races the two roads again.
    let connect = |ended: &Ended| {
        let previous = if matches!(ended.end, End::Moving) { None } else { layered::lock(legs_ref).take() };
        async move {
            match race(Box::pin(iroh_ref.link()), Box::pin(pair(previous)), HEAD_START).await {
                Ok((won, took)) => Next::Link(winner(won, took, shown_ref, log_ref)),
                Err(lost) if pair_final_ref.load(Ordering::SeqCst) && iroh_ref.refused().await => {
                    Next::Stop(lost.to_string())
                }
                Err(lost) => Next::Retry(lost.to_string()),
            }
        }
    };
    let note = |note: Note| say(layered::line_of(note));
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let me = channel.as_ref().map(|c| c.identity.clone());
    let pin_say = {
        let (log, shown) = (log.clone(), shown.clone());
        move |line: String| log.info(&format!("{shown}: {line}"))
    };
    let (layer_app, session) = crate::channel::around(layer_end, channel, pin_say);
    let session = async move {
        match session {
            Some(session) => session.await.err(),
            None => None,
        }
    };
    let mut entropy = OsEntropy;
    let (code, outcome, failed) = tokio::join!(
        Box::pin(podssh_ssh::run(ssh_end, opts, None, log.clone())),
        Box::pin(resume::run(client, layer_app, connect, note, &mut entropy)),
        session
    );
    if let Some((_, why)) = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref())) {
        log.error(&format!("{shown}: {why}"));
        let _ = layered::last(&legs).await;
        iroh.close().await;
        return EXIT_FAILURE;
    }
    if let (true, Some(why)) = (code == EXIT_FAILURE, layered::why_ended(outcome)) {
        log.error(&format!("{shown}: {why}"));
    }
    let _ = layered::last(&legs).await;
    iroh.close().await;
    code
}

/// The winner's link, with the bytes that the race read given back first,
/// and a line with `-v`.
fn winner(won: Won<Road, Road>, took: Duration, shown: &str, log: &Log) -> client::Rewound<Road> {
    let (road, greeted) = match won {
        Won::First(greeted) => ("the iroh road", greeted),
        Won::Second(greeted) => ("the pair's road", greeted),
    };
    log.verbose(&format!("{shown}: {road} answered first, in {} ms", took.as_millis()));
    greeted.rewound()
}
