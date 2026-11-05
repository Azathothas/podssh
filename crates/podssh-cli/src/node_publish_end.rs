//! `podssh node NAME --publish-tls TARGET --acme SITE` (T-649): the node of a
//! published site ends each visitor's TLS itself, with a certificate for SITE
//! from an ACME CA, and TARGET gets each session's bytes in cleartext. The CA
//! proves SITE by TLS-ALPN-01 (RFC 8737) on port 443 of the name, where
//! podssh's relay role sends a validation of a published name to its node as
//! it sends each visitor; so the node needs no port of its own. The order,
//! the store in the cache and the renewals are those of `relay serve --acme`
//! (`crate::acme`); the first order starts once the node is online, as the
//! validation can reach it only then, and one that fails with no certificate
//! kept stops the node (69), as no TLS could end here.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, Exit, Handler, NodeConfig, Opening, SessionId};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::tls_server::{acceptor_for, Served, TlsAcceptor, ACME_TLS_1, HTTP1};
use podssh_ws::Trust;
use tokio::io::{AsyncWriteExt as _, DuplexStream};
use tokio::sync::{oneshot, Notify};

use crate::acme::{self, certs::Leaf, Acme};
use crate::node::DIAL_LIMIT;
use crate::node_expiry::Say;
use crate::relay_settings::Refusal;

/// Each direction of the pipe between a session and its TLS.
const PIPE: usize = 256 * 1024;
/// How long a visitor has to finish its handshake, as the relay role's
/// listener allows.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);

/// The node's own TLS for a published site, and the certificate's keeper.
pub(crate) struct Ending {
    /// The site's name, lower-cased.
    pub name: String,
    ca: Acme,
    served: Arc<Served>,
    /// The certificate kept in the cache, while it holds.
    held: Option<Leaf>,
    acceptor: TlsAcceptor,
}

impl Ending {
    /// The TLS of SITE `name`, with a certificate from the CA of `directory`
    /// (Let's Encrypt's when none), reached with `trust`: the one kept in the
    /// cache at once while it holds, else none until the first order.
    pub(crate) fn open(name: &str, directory: Option<&str>, trust: Trust) -> Result<Ending, Refusal> {
        let name = podssh_relay::serve::published::dns_name(name).ok_or_else(|| {
            Refusal::usage(format!(
                "--acme {name:?}: the published name, a DNS name of two labels or more, with no wildcard and no \
                 address"
            ))
        })?;
        let ca = Acme::new(&name, directory, trust)?;
        let (served, held) = match ca.held(acme::order::now_secs()) {
            Ok(Some((pair, leaf))) => (Served::new(Some(pair)), Some(leaf)),
            // A store that cannot be read is ordered again, as the role does.
            Ok(None) | Err(_) => (Served::new(None), None),
        };
        // The visitor's HTTP/1.1, and a CA's validation.
        let acceptor = acceptor_for(served.clone(), &[HTTP1, ACME_TLS_1]).map_err(Refusal::config)?;
        Ok(Ending { name, ca, served, held, acceptor })
    }

    /// The words of the first line: the certificate, or the one to ask for.
    pub(crate) fn shown(&self) -> String {
        let host = self.ca.host();
        match &self.held {
            Some(leaf) => format!("with the certificate from ACME at {host} {}", acme::about(leaf)),
            None => format!("with a certificate for {} that ACME at {host} is asked for once online", self.name),
        }
    }

    /// Run the node of `config` with each session's TLS ended here and its
    /// cleartext to `target`, until it ends: its exit, or why the first
    /// order failed. The order starts at the first line `online`, which
    /// `online` hears; the keeper's lines go to `say`.
    pub(crate) async fn run(
        self,
        config: &mut NodeConfig<'_>,
        target: &Route,
        online: Arc<Notify>,
        say: Say,
    ) -> Result<Exit, String> {
        let Ending { ca, served, held, acceptor, .. } = self;
        let (lines, mut heard) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (failed, failure) = oneshot::channel::<String>();
        let keeper = tokio::spawn(async move {
            online.notified().await;
            let _ = failed.send(acme::keep(ca, served, held, lines).await);
        });
        let teller = tokio::spawn(async move {
            while let Some(line) = heard.recv().await {
                say(line);
            }
        });
        // The node stops for its own stop, or for an order that failed.
        let why = Arc::new(Mutex::new(None));
        let slot = why.clone();
        let stop = async move {
            tokio::select! {
                () = crate::node_upgrade::stop() => {}
                Ok(failed) = failure => *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(failed),
            }
        };
        let handler = TlsEnd { acceptor, host: target.host.clone(), port: target.port };
        let exit = Box::pin(reverse::run(config, Arc::new(handler), stop)).await;
        keeper.abort();
        teller.abort();
        let failed = why.lock().unwrap_or_else(PoisonError::into_inner).take();
        match failed {
            Some(why) => Err(why),
            None => Ok(exit),
        }
    }
}

/// Each session: one end of a pipe, whose other end this node's TLS ends,
/// then TARGET in cleartext.
struct TlsEnd {
    acceptor: TlsAcceptor,
    host: String,
    port: u16,
}

impl Handler for TlsEnd {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let (near, far) = tokio::io::duplex(PIPE);
        tokio::spawn(end_one(far, self.acceptor.clone(), self.host.clone(), self.port));
        Box::pin(async move { Ok(near) })
    }
}

/// End the TLS of one visitor on `far`, then carry its cleartext to
/// `host:port`, until either side ended. A CA's validation (`acme-tls/1`)
/// wants the handshake alone (RFC 8737, section 3).
async fn end_one(far: DuplexStream, acceptor: TlsAcceptor, host: String, port: u16) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_WAIT, acceptor.accept(far)).await else { return };
    if tls.get_ref().1.alpn_protocol() == Some(ACME_TLS_1) {
        let _ = tls.shutdown().await;
        return;
    }
    // TARGET as the node's other roads dial it: the loopback directly.
    let Ok(mut target) = podssh_ws::dial::dial(&host, port, &ProxyChoice::FromEnvironment, DIAL_LIMIT).await else {
        let _ = tls.shutdown().await;
        return;
    };
    let _ = target.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-649: the name of --acme is the published one, lower-cased, never a
    // wildcard or an address.
    #[test]
    fn the_name_of_acme_is_a_dns_name() {
        for wrong in ["*.example.org", "192.0.2.7", "example", "-a.example.org"] {
            let Err(refused) = Ending::open(wrong, None, Trust::Default) else { panic!("{wrong} taken") };
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{wrong}");
            assert!(refused.message.starts_with("--acme "), "{refused:?}");
        }
    }
}
