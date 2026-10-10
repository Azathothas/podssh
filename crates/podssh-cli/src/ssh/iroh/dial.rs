//! The dial of `podssh ssh iroh:TICKET` (T-163): this client's key, an
//! endpoint set up as podssh's other roads, and SSH over a session of the
//! resumable layer, carried to a new link after each lost one. `podssh pipe
//! iroh:` (T-175) sets up its dial the same way (`prepare`).

use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{ticket, Dialer, Failure, Options, Udp};
use podssh_relay::session::resume::Note;
use podssh_relay::session::{OsEntropy, Settings};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};

use crate::layered::Line;

/// Each direction of the pipe between the SSH client and the layer.
const PIPE: usize = 256 * 1024;
/// How long the endpoint may take to close after the session.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// A dial, set up: the dialer, its endpoint, how the node is shown, and
/// this client's key as its allowlist names it.
pub(crate) struct Prepared {
    pub dialer: Dialer,
    pub endpoint: iroh::Endpoint,
    pub shown: String,
    pub fingerprint: String,
}

/// Set up the dial of the node of the ticket `text`: this client's key,
/// the relays (the ticket's first), and the endpoint; else the line that
/// says why not.
pub(crate) async fn prepare(
    text: &str,
    key: Option<&str>,
    relays: &[String],
    trust: &Trust,
    log: &Log,
) -> Result<Prepared, String> {
    let addr = ticket::parse(text)?;
    let shown = format!("{}{}", super::SCHEME, keys::fingerprint(&addr.id));
    crate::pairs::online().map_err(|refusal| format!("{shown}: {}", refusal.message))?;
    let place = match key {
        Some(file) => Place::File(file.into()),
        None => Place::Cache(keys::CLIENT_FILE.into()),
    };
    let key = keys::load(&place, &mut OsEntropy).map_err(|why| format!("{shown}: this client's key: {why}"))?;
    let fingerprint = keys::fingerprint(&key.public());
    let kept = key.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
    if key.made {
        log.info(&format!(
            "a new iroh key for this client, in {kept}: {fingerprint}; a node lets it in once its allowlist holds it"
        ));
    }
    log.verbose(&format!("this client's iroh key: {fingerprint} ({kept})"));
    // The ticket's relays first: this client's home relay is then the
    // node's, when it answers (T-165).
    let mut list: Vec<RelayUrl> = addr.relay_urls().cloned().collect();
    for relay in relays.iter().filter_map(|text| podssh_iroh::relays::parse_url(text).ok()) {
        if !list.contains(&relay) {
            list.push(relay);
        }
    }
    let proxy = ProxyChoice::FromEnvironment;
    let (home, missed) = podssh_iroh::relays::home(&list, trust, &proxy).await;
    for why in &missed {
        log.verbose(&format!("{shown}: an iroh relay did not answer: {why}"));
    }
    let options = Options {
        relays: home,
        proxy,
        trust: trust.clone(),
        udp: Udp::from_environment(),
        secret: Some(key.secret.clone()),
        accepts: false,
        ..Options::default()
    };
    let endpoint = podssh_iroh::bind(&options).await.map_err(|e| format!("{shown}: {e}"))?;
    let through: Vec<String> = addr.relay_urls().map(ToString::to_string).collect();
    log.verbose(&format!("connecting to {shown} over the iroh road, through {}", through.join(", ")));
    let dialer = Dialer::new(endpoint.clone(), addr);
    Ok(Prepared { dialer, endpoint, shown, fingerprint })
}

/// What a session of the iroh road that failed says; nothing for a clean
/// end. A refused key names itself, and what lets it in.
pub(crate) fn why_failed(
    carried: Result<podssh_relay::session::client::Outcome, Failure>,
    fingerprint: &str,
) -> Option<String> {
    match carried {
        Err(Failure::Refused) => Some(format!(
            "the node refused this client's key {fingerprint}: it is not in the node's allowlist; the node's \
             operator adds the key to the file of --iroh-allow"
        )),
        Err(Failure::Failed(why)) => Some(why),
        Ok(outcome) => crate::layered::why_ended(outcome),
    }
}

pub(super) async fn connect(
    text: &str,
    key: Option<&str>,
    relays: &[String],
    trust: &Trust,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let Prepared { dialer, endpoint, shown, fingerprint } = match prepare(text, key, relays, trust, &log).await {
        Ok(prepared) => prepared,
        Err(why) => {
            log.error(&why);
            return EXIT_FAILURE;
        }
    };
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    };
    let note = |note: Note| say(crate::layered::line_of(note));
    let settings = Settings { features: podssh_iroh::FEATURES, ..crate::layered::settings() };
    // The SSH client and the layer in one task: when the client closes its
    // end, the layer sends `CLOSE` on the link that it has.
    let (code, carried) = tokio::join!(
        podssh_ssh::run(ssh_end, opts, None, log.clone()),
        podssh_iroh::carry(&dialer, layer_end, settings, note)
    );
    if let (true, Some(why)) = (code == EXIT_FAILURE, why_failed(carried, &fingerprint)) {
        log.error(&format!("{shown}: {why}"));
    }
    dialer.close().await;
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    code
}
