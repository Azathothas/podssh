//! The far end of the iroh road: each connection to the endpoint, and each
//! session stream on it, served by the resumable layer's far end, with the
//! sessions kept across links by one keeper (T-153). A new session reaches
//! its target only after its handshake, as on the reverse road; a client
//! whose key is not admitted gets no session at all (T-163).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, PublicKey};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::record::Role;
use podssh_relay::session::{far, Settings};
use tokio::io::{AsyncRead, AsyncWrite};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// Serve the sessions of each connection to `endpoint` until it closes. A
/// new session's target comes from `open`; the replay buffers of all
/// sessions stay within `budget` bytes. A connection whose key `admit`
/// refuses is closed with [`crate::allow::REFUSED`] before any stream.
pub async fn serve<A, O, F, G>(endpoint: Endpoint, settings: Settings, budget: usize, open: O, admit: G)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
    G: Fn(&PublicKey) -> bool + Clone + Send + Sync + 'static,
{
    let keeper: Arc<Keeper<A>> = Arc::new(Keeper::new(settings.resume_deadline));
    let sweeping = {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        })
    };
    while let Some(incoming) = endpoint.accept().await {
        let (keeper, open, admit) = (keeper.clone(), open.clone(), admit.clone());
        tokio::spawn(async move {
            // A connection that fails its own handshake carries nothing.
            let Ok(connection) = incoming.await else { return };
            // The handshake proved the client's key; the allowlist decides.
            if !admit(&connection.remote_id()) {
                let reason = crate::allow::REFUSED_REASON.as_bytes();
                connection.close(crate::allow::REFUSED.into(), reason);
                return;
            }
            while let Ok(stream) = crate::stream::accept_session(&connection).await {
                let (keeper, open) = (keeper.clone(), open.clone());
                tokio::spawn(async move {
                    far::serve(stream, Role::NODE, settings, &keeper, budget, open).await;
                });
            }
        });
    }
    sweeping.abort();
}
