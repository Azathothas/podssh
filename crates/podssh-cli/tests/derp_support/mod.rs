//! Stand-in DERP servers on the loopback for the tests of the command line
//! (T-379): podssh-relay's own stand-in (`tests/derp_stand_in`, which keeps
//! its frames apart from the library's), behind TLS of the test's own CA.
//! Each connection is bridged to a pipe of the stand-in; a front that stops
//! closes its listener and each of its connections, as a server that went
//! away.

#![allow(dead_code)]

#[path = "../../../podssh-relay/tests/derp_stand_in/mod.rs"]
pub mod derp_stand_in;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use derp_stand_in::StandIn;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_rustls::TlsAcceptor;

/// One stand-in server, over TLS on a port of the loopback.
pub struct Front {
    pub port: u16,
    pub stand_in: Arc<StandIn>,
    accepting: JoinHandle<()>,
    bridges: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Front {
    /// A new stand-in behind `acceptor`, in the runtime of the caller.
    pub async fn start(acceptor: TlsAcceptor) -> Front {
        let stand_in = StandIn::new(0);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let bridges: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
        let (serving, kept) = (stand_in.clone(), bridges.clone());
        let accepting = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, serving) = (acceptor.clone(), serving.clone());
                let bridge = tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut pipe = serving.connect();
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut pipe).await;
                });
                kept.lock().unwrap().push(bridge.abort_handle());
            }
        });
        Front { port, stand_in, accepting, bridges }
    }

    /// The server as podssh names it: `127.0.0.1:PORT`.
    pub fn server(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The server goes away: it takes no new connection, and each one ends.
    pub fn stop(&self) {
        self.accepting.abort();
        for bridge in self.bridges.lock().unwrap().drain(..) {
            bridge.abort();
        }
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        self.stop();
    }
}
