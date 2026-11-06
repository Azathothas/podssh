//! A GET over HTTPS through podssh's way out: pod-proxy's client
//! ([`pod_proxy::Client`]) with podssh's dial, its TLS context, its user
//! agent and its reader of HTTPS records, so that a hello is sealed with ECH
//! where the user asks for it. A failure is a [`ConnectError`], as each
//! caller of podssh reads it.

use std::sync::Arc;
use std::time::Duration;

use pod_core::{Class, Failure, Stage};

use super::ConnectError;
use crate::dial::{self, DialError, ProxyChoice};
use crate::http;
use crate::tls::{self, Trust};

/// GET over HTTPS, through the same path as everything else (proxy, TLS
/// verification, sealed with ECH where asked, bounded waits): pod-proxy's
/// client ([`getter`]). The body is capped at `max_body` bytes.
pub async fn https_get(
    host: &str,
    port: u16,
    path: &str,
    max_body: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    let client = getter(proxy);
    client.https_get(host, port, path, max_body, trust, timeout).await.map_err(|failure| get_error(failure, timeout))
}

/// GET over HTTPS as [`https_get`], with `accept` as the answer's type: a
/// resolver's JSON API answers `application/dns-json` (T-339).
#[allow(clippy::too_many_arguments)]
pub async fn https_get_accepting(
    host: &str,
    port: u16,
    path: &str,
    accept: &str,
    max_body: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    let client = getter(proxy);
    let get = client.https_get_accepting(host, port, path, accept, max_body, trust, timeout);
    get.await.map_err(|failure| get_error(failure, timeout))
}

/// pod-proxy's client over the dial of `proxy`, with the process's TLS and
/// podssh's user agent; a name's HTTPS record is read through that proxy.
pub fn getter(proxy: &ProxyChoice) -> pod_proxy::Client {
    pod_proxy::Client::new(tls::context().clone(), Arc::new(dial::dialer(proxy, false)))
        .with_user_agent(dial::user_agent())
        .with_records(Arc::new(crate::ech::Records(proxy.clone())))
}

/// The failure of a GET as podssh's callers read it: the dial's error as it
/// was, the handshake's as [`tls::connect_error`] says it, and a failure of
/// the exchange (`the HTTPS request failed: ...`, `the HTTPS request timed
/// out after Ns`) as the step of the request.
fn get_error(failure: Failure, limit: Duration) -> ConnectError {
    let cause = std::error::Error::source(&failure);
    if failure.stage != Stage::Connect || cause.is_some_and(|e| e.is::<DialError>()) {
        return tls::connect_error(failure, limit);
    }
    match cause.and_then(|e| e.downcast_ref::<std::io::Error>()) {
        Some(e) => ConnectError::Http(e.to_string()),
        None if failure.class == Class::Timeout => ConnectError::Timeout { step: "the HTTPS request", after: limit },
        None => ConnectError::Http(failure.text().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cut::Cut;

    /// A failure of the exchange is the step of the request, with the
    /// words of its error; the dial's error and the handshake's stay as
    /// podssh's roads say them.
    #[test]
    fn a_failure_of_a_get_is_podssh_s_connect_error() {
        let limit = Duration::from_secs(3);
        let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let text = format!("the HTTPS request failed: {reset}");
        let failed = Failure::caused(Stage::Connect, Class::of_io(reset.kind()), text, reset);
        let failed = get_error(failed, limit);
        assert!(matches!(&failed, ConnectError::Http(why) if !why.starts_with("the HTTPS")), "{failed:?}");
        assert_eq!(failed.to_string(), "the HTTPS request failed: connection reset");
        let late = Failure::new(Stage::Connect, Class::Timeout, "the HTTPS request timed out after 3s");
        let late = get_error(late, limit);
        assert_eq!(late, ConnectError::Timeout { step: "the HTTPS request", after: limit });
        assert_eq!(late.to_string(), "the HTTPS request timed out after 3s");
        let dial = DialError::Connect {
            target: "t:443".into(),
            detail: "refused".into(),
            cut: Some(Cut::Refused),
            kind: None,
        };
        assert_eq!(get_error(Failure::from(dial.clone()), limit), ConnectError::Dial(dial));
        let slow = Failure::new(Stage::Tls, Class::Timeout, "the TLS handshake timed out after 3s");
        assert_eq!(get_error(slow, limit), ConnectError::Timeout { step: "the TLS handshake", after: limit });
    }
}
