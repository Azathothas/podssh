//! One resolver of DNS over HTTPS asked straight at its address, as the
//! dialer's fallback and `podssh doctor` ask it, with how its connection
//! ended beside the words of a failure (T-604): `doctor` counts a resolver
//! that the egress reset as it counts a relay host, by the kind of the
//! error, never by the system's words.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::{h2, parse_answer, read, way, wire, Doh, Form, Miss, DOH_CONNECT, DOH_EACH, MAX_ANSWER, NXDOMAIN};
use crate::cut::{Cut, Missed};
use crate::http;
use crate::tls::{self, Trust};

/// The port of DNS over HTTPS.
const PORT: u16 = 443;

/// One resolver, straight to its address: A, then AAAA when A gave none,
/// each in the first of its forms that answers in its form, within
/// [`DOH_EACH`] and `deadline`. The addresses and the form that gave them, or
/// why none came, each reason after the resolver's address.
pub async fn doh_ask(resolver: &Doh, host: &str, deadline: Instant) -> Result<(Vec<IpAddr>, Form), String> {
    doh_ask_kept(resolver, host, deadline).await.map_err(|missed| missed.why)
}

/// [`doh_ask`], with how the connection ended beside the words: the cut of
/// the failure that ended the asking, where no answer came before it. A
/// resolver that answered once completed a handshake, so a later cut says
/// nothing of the way to it.
pub async fn doh_ask_kept(resolver: &Doh, host: &str, deadline: Instant) -> Result<(Vec<IpAddr>, Form), Missed> {
    ask_at(resolver, PORT, host, deadline).await
}

/// [`doh_ask_kept`] at `port` of the resolver's address: a stand-in's in a
/// test, which binds no port below 1024.
pub(super) async fn ask_at(
    resolver: &Doh,
    port: u16,
    host: &str,
    deadline: Instant,
) -> Result<(Vec<IpAddr>, Form), Missed> {
    let ip = resolver.ip;
    let each = (Instant::now() + DOH_EACH).min(deadline);
    let config = tls::config_for(&Trust::Default).map_err(|e| Missed::words(format!("{ip}: {e}")))?;
    let mut forms = resolver.forms();
    let (mut found, mut by, mut reasons) = (Vec::new(), None, Vec::new());
    // The cut that ended the asking, and whether an answer came before it.
    let (mut cut, mut answered) = (None, false);
    'kinds: for kind in ["A", "AAAA"] {
        while let Some(&form) = forms.first() {
            match tokio::time::timeout_at(each, ask_direct(&config, resolver, port, form, host, kind)).await {
                Ok(Ok(mut ips)) => {
                    found.append(&mut ips);
                    by = Some(form);
                    answered = true;
                    break;
                }
                Ok(Err(Miss::Said(e))) if e == NXDOMAIN => return Err(Missed::words(format!("{ip}: {e}"))),
                // The other form would say the same.
                Ok(Err(Miss::Said(e))) => {
                    reasons.push(format!("{ip}: {e}"));
                    answered = true;
                    break;
                }
                // Not served here, or not as podssh reads it: the next form,
                // for this question and the next.
                Ok(Err(Miss::Form(e))) => {
                    reasons.push(format!("{ip} ({}): {e}", form.words()));
                    answered = true;
                    forms.remove(0);
                }
                Ok(Err(Miss::Way(e, ended))) => {
                    reasons.push(format!("{ip}: {e}"));
                    cut = ended;
                    break 'kinds;
                }
                Err(_) => {
                    reasons.push(format!("{ip}: timed out"));
                    cut = Some(Cut::TimedOut);
                    break 'kinds;
                }
            }
        }
        if !found.is_empty() {
            break;
        }
    }
    match by {
        Some(form) if !found.is_empty() => Ok((found, form)),
        _ if reasons.is_empty() => Err(Missed::words(format!("{ip}: no addresses"))),
        _ => Err(Missed { why: reasons.join("; "), cut: if answered { None } else { cut } }),
    }
}

/// One question over a connection of its own, straight to the resolver.
async fn ask_direct(
    config: &Arc<ClientConfig>,
    resolver: &Doh,
    port: u16,
    form: Form,
    host: &str,
    kind: &str,
) -> Result<Vec<IpAddr>, Miss> {
    let target = resolver.target(form, host, kind).map_err(way)?;
    let response = get_direct(config, resolver, port, &target, form.accept())
        .await
        .map_err(|missed| Miss::Way(missed.why, missed.cut))?;
    read(&response, |body| match (form, wire::code(kind)) {
        (Form::Json, _) => parse_answer(body, kind),
        (Form::Wire, Some(code)) => wire::addrs(body, host, code),
        (Form::Wire, None) => Err(format!("no record type {kind}")),
    })
}

/// GET `target` of `resolver`: TCP within [`DOH_CONNECT`], then TLS
/// verified for its address, and HTTP/2 where it serves no HTTP/1.1. A
/// failure of the connection or of the handshake keeps its cut; one after
/// the handshake has none.
async fn get_direct(
    config: &Arc<ClientConfig>,
    resolver: &Doh,
    port: u16,
    target: &str,
    accept: &str,
) -> Result<http::Response, Missed> {
    let ip = resolver.ip;
    let name = rustls_pki_types::ServerName::try_from(ip.to_string()).map_err(|e| Missed::words(e.to_string()))?;
    let addr: IpAddr = ip.parse().map_err(|_| Missed::words(format!("{ip} is not an IP")))?;
    let tcp = match tokio::time::timeout(DOH_CONNECT, TcpStream::connect(SocketAddr::new(addr, port))).await {
        Err(_) => {
            let why = format!("no connection within {} s", DOH_CONNECT.as_secs());
            return Err(Missed { why, cut: Some(Cut::TimedOut) });
        }
        Ok(Err(e)) => return Err(Missed { why: e.to_string(), cut: Some(Cut::of(e.kind())) }),
        Ok(Ok(tcp)) => tcp,
    };
    if resolver.http2 {
        return h2::get_over_kept(config, tcp, ip, target, accept, MAX_ANSWER).await;
    }
    let mut stream = tokio_rustls::TlsConnector::from(config.clone())
        .connect(name, tcp)
        .await
        .map_err(|e| Missed::tls(&e, tls::context().words()))?;
    http::exchange(&mut stream, "GET", ip, target, &[("Accept", accept)], b"", MAX_ANSWER)
        .await
        .map_err(|e| Missed::words(e.to_string()))
}
