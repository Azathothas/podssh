//! The node's side of the frp road: a connection to frps, the login, the
//! STCP service of the node's name, a heartbeat each 30 s as frpc sends one,
//! and a work connection each time frps asks for one, handed to the caller
//! once a visitor took it. A lost connection is made again, after 1 s and up
//! to 30 s between tries, from 1 s again after a connection that lasted a
//! minute; a refused token ends the road, as no try again would pass.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::DuplexStream;
use zeroize::Zeroizing;

use super::control::Session;
use super::dial::{self, Server};
use super::msg;
use super::mux::Mux;
use super::FrpError;
use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// frpc's heartbeat (`transport.heartbeatInterval`'s default).
pub const HEARTBEAT: Duration = Duration::from_secs(30);
/// frps ends a client that sent no heartbeat for this long (frpc's own
/// timeout of a pong, `heartbeatTimeout`'s default).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
/// The bound of the connection and its TLS.
pub const DIAL_LIMIT: Duration = Duration::from_secs(20);
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
const STEADY: Duration = Duration::from_secs(60);

/// The road of a node through frps.
#[derive(Clone)]
pub struct Road {
    pub server: Server,
    pub token: Arc<Zeroizing<String>>,
    pub secret: Arc<Zeroizing<String>>,
    pub trust: Trust,
}

/// A line of the road, as the caller says it.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// Serve the STCP service `name` on `road` until frps refuses its token:
/// why. Each work connection that a visitor took goes to `work`.
pub async fn serve<W, F>(road: Road, name: String, say: Say, work: W) -> String
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let mut wait = RETRY_FIRST;
    loop {
        let started = Instant::now();
        match once(&road, &name, &say, work.clone()).await {
            Err(e) if e.is_bad_token() => return e.to_string(),
            Err(e) => say(format!("the road through {} ended: {e}; trying again", road.server.shown())),
            Ok(()) => {}
        }
        if started.elapsed() >= STEADY {
            wait = RETRY_FIRST;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
}

/// One connection's life: until it ends.
async fn once<W, F>(road: &Road, name: &str, say: &Say, work: W) -> Result<(), FrpError>
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let proxy = ProxyChoice::FromEnvironment;
    let conn = dial::connect(&road.server, &road.trust, &proxy, DIAL_LIMIT).await.map_err(FrpError::Ended)?;
    let mux = Mux::client(conn);
    let mut session = Session::login(mux.clone(), &road.token).await?;
    session.write.lock().await.send(msg::NEW_PROXY, &msg::new_stcp(name, &road.secret)).await?;
    let heartbeat = {
        let (write, token) = (session.write.clone(), road.token.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT).await;
                if write.lock().await.send(msg::PING, &msg::ping(&token, msg::now())).await.is_err() {
                    return;
                }
            }
        })
    };
    let result = control_loop(&mut session, road, name, say, work).await;
    heartbeat.abort();
    mux.close();
    result
}

/// Read frps's control messages: the service's answer, frps's asks for work
/// connections and its pongs.
async fn control_loop<W, F>(session: &mut Session, road: &Road, name: &str, say: &Say, work: W) -> Result<(), FrpError>
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let mut last_pong = Instant::now();
    loop {
        let next = tokio::time::timeout(HEARTBEAT_TIMEOUT, session.read.recv()).await;
        let m = match next {
            Ok(m) => m?,
            Err(_) => {
                return Err(FrpError::Ended(format!(
                    "frps said nothing for {} s, its pong neither",
                    HEARTBEAT_TIMEOUT.as_secs()
                )))
            }
        };
        match m.kind {
            msg::NEW_PROXY_RESP => match m.error() {
                Some(words) => return Err(FrpError::Refused { step: "the service", words: words.into() }),
                None => say(format!("waiting for visitors at {} as the STCP service {name}", road.server.shown())),
            },
            msg::REQ_WORK_CONN => {
                let (mux, token, run_id) = (session.mux.clone(), road.token.clone(), session.run_id.clone());
                let (work, say) = (work.clone(), say.clone());
                tokio::spawn(async move {
                    match Session::work_conn(&mux, &token, &run_id).await {
                        Ok((stream, _start)) => work(stream).await,
                        Err(e) => say(format!("a work connection failed: {e}")),
                    }
                });
            }
            msg::PONG => {
                if let Some(words) = m.error() {
                    return Err(FrpError::Refused { step: "the heartbeat", words: words.into() });
                }
                last_pong = Instant::now();
            }
            // Messages of frp's other services, which podssh registers none of.
            _ => {}
        }
        if last_pong.elapsed() > HEARTBEAT_TIMEOUT {
            return Err(FrpError::Ended("frps answered no heartbeat in time".into()));
        }
    }
}

/// A visitor's stream to `name`: a connection of its own and the visit; the
/// connection ends with the stream, so that each visit costs one.
pub async fn visit(road: &Road, name: &str) -> Result<DuplexStream, FrpError> {
    let proxy = ProxyChoice::FromEnvironment;
    let conn = dial::connect(&road.server, &road.trust, &proxy, DIAL_LIMIT).await.map_err(FrpError::Ended)?;
    let mux = Mux::client(conn);
    // No login: frps admits a visitor with no run id, its user empty, as a
    // service of an empty user allows.
    let mut stream = match super::control::visit(&mux, name, &road.secret, "").await {
        Ok(stream) => stream,
        Err(e) => {
            mux.close();
            return Err(e);
        }
    };
    let (user, mut ours) = tokio::io::duplex(VISIT_PIPE);
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut ours, &mut stream).await;
        mux.close();
    });
    Ok(user)
}

/// The pipe between a visitor's user and its stream.
const VISIT_PIPE: usize = 64 * 1024;
