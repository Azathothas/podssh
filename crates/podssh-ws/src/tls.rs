//! podssh's TLS: `pod-tls` of PodUtils/podcrates, with one context for the
//! process ([`context`]): podssh's pure-Rust provider, its words, the
//! `podssh-ca.pem` next to the binary, the mode of `PODSSH_ECH`, and the
//! configuration of each trust, kept so that TLS resumes (T-444).
//!
//! **There is no `--insecure`, and there is no parameter that would become
//! one.** The only verifier that `pod-tls` builds is rustls's
//! `WebPkiServerVerifier`, whose `verify_server_cert` calls
//! `verify_server_name` each time. A library that embeds podssh can bring its
//! own `rustls::ClientConfig` instead ([`Trust::caller`]): podvm keeps `ring`
//! and TLS 1.2 for proxies that intercept TLS. Its verifier is then the
//! caller's, which podssh cannot check; podssh's binary never takes that
//! form, and a test keeps it out.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pod_core::{Class, Failure};
use pod_tls::{Context, Settings, Words};
use rustls::ClientConfig;

use crate::client::ConnectError;
use crate::cut::{Cut, TlsFailure};
use crate::dial::DialError;
use crate::error::WsError;

pub use pod_tls::{
    clock_refused, roots_from_compiled_set, CallerConfig, TlsRoots, Trust, ROOTS_PUBLISHED, ROOTS_VERSION,
    SYSTEM_BUNDLES,
};

/// The process's TLS: made at its first use, with podssh's settings.
pub fn context() -> &'static Arc<Context> {
    static CONTEXT: OnceLock<Arc<Context>> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let mut settings = Settings::new(words());
        settings.extra_bundle = crate::bundle::default_bundle_path().ok();
        let context = Context::new(Arc::new(crate::crypto::provider()), settings);
        // The variable's mode until a command sets its own (`ech::set_mode`);
        // a word that is none of its own is off here, as a command refuses
        // it before (78), and a library's caller gets what it set.
        context.ech().set_mode(pod_tls::ech::chosen(None, crate::ech::mode_from_env()));
        Arc::new(context)
    })
}

/// podssh's names in the words of a failed handshake.
fn words() -> Words {
    Words {
        app: "podssh".into(),
        replace_roots: "--ca-file FILE or SSL_CERT_FILE".into(),
        add_roots: Some(format!("{} next to the binary", crate::bundle::BUNDLE_FILE_NAME)),
        ech_strict: crate::ech::STRICT.into(),
    }
}

/// The trust anchors for `trust`. A caller's configuration holds its own,
/// which podssh cannot list.
pub fn roots_for(trust: &Trust) -> Result<TlsRoots, WsError> {
    Ok(context().roots_for(trust)?)
}

/// The rustls configuration for `trust`: the caller's as it is, or podssh's
/// own over the roots of `trust`, made once in the process, so TLS resumes.
pub fn config_for(trust: &Trust) -> Result<Arc<ClientConfig>, WsError> {
    Ok(context().config_for(trust)?)
}

/// The default trust store: the compiled-in Mozilla roots, plus a
/// `podssh-ca.pem` next to the binary, plus the roots of the system's stores,
/// plus the first readable system bundle.
pub fn default_roots() -> TlsRoots {
    context().default_roots()
}

/// The roots of the PEM file at `path`, alone.
pub fn roots_from_bundle(path: &std::path::Path) -> Result<TlsRoots, WsError> {
    Ok(pod_tls::roots_from_bundle(path)?)
}

/// podssh's configuration over `roots`, with the process's provider and the
/// groups that servers took.
pub fn client_config(roots: &TlsRoots) -> Result<Arc<ClientConfig>, WsError> {
    Ok(context().client_config(roots)?)
}

/// A TLS client over `stream`, a connection that is already open (a relay
/// session to an IRC server, for `podssh chat --irc`): the certificate is
/// checked against `server_name` and the roots of `trust`, within `limit`.
/// A failure is the caller's to say, and never a fall back to plain text.
pub async fn connect_over<S>(
    stream: S,
    server_name: &str,
    trust: &Trust,
    limit: Duration,
) -> Result<tokio_rustls::client::TlsStream<S>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    context().connect_over(stream, server_name, trust, limit).await.map_err(|e| e.text().to_string())
}

/// What to do when a TLS handshake failed with `error`: for an issuer that no
/// root here signs, where its CA goes (T-340); for a certificate that is
/// expired or not valid yet, this host's clock and its reading (T-345); none
/// for another failure.
pub fn handshake_hint(error: &std::io::Error) -> Option<String> {
    pod_tls::handshake_hint(error, context().words())
}

/// The text of a failed handshake, with its hint when it has one.
pub fn handshake_failure(error: &std::io::Error) -> String {
    pod_tls::handshake_failure(error, context().words())
}

/// The failure of a TLS road of `pod-tls` as podssh's roads say it: the
/// dial's error as it was, a configuration or a name that cannot be used, the
/// bound of the handshake, or the handshake's words with the cut of its
/// error of I/O (T-487).
pub(crate) fn connect_error(failure: Failure, limit: Duration) -> ConnectError {
    let cause = std::error::Error::source(&failure);
    if let Some(dial) = cause.and_then(|e| e.downcast_ref::<DialError>()) {
        return ConnectError::Dial(dial.clone());
    }
    let kind = cause.and_then(|e| e.downcast_ref::<std::io::Error>()).map(|e| e.kind());
    match (failure.class, kind) {
        (Class::Config | Class::Usage, _) => ConnectError::Config(failure.text().to_string()),
        (Class::Timeout, None) => ConnectError::Timeout { step: "the TLS handshake", after: limit },
        // rustls's own refusal (a certificate, a name, a protocol) says
        // nothing of the path.
        (_, kind) => ConnectError::Tls(TlsFailure {
            why: failure.text().to_string(),
            cut: kind.filter(|k| *k != std::io::ErrorKind::InvalidData).map(Cut::of),
        }),
    }
}

/// The group that each server took, kept across runs, and the store of
/// sessions that offers it (T-664): `pod_tls::groups`, with the process's.
pub mod groups {
    pub use pod_tls::groups::*;

    /// Give the process's configurations the file of the groups, once a run,
    /// before any dial; `false` when they have one already.
    pub fn keep_in(file: Box<dyn GroupFile>) -> bool {
        super::context().groups().keep_in(file)
    }

    /// What the process has to say of its file of groups, once.
    pub fn take_note() -> Option<String> {
        super::context().groups().take_note()
    }
}

impl From<pod_tls::Error> for WsError {
    fn from(e: pod_tls::Error) -> WsError {
        match e {
            pod_tls::Error::Bundle { path, why } => WsError::Bundle { path, why },
            pod_tls::Error::Config(why) => WsError::Config(why),
            other => WsError::Config(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{CertificateError, Error};

    /// podssh's words give podssh's hint, word for word (T-340).
    #[test]
    fn an_unknown_issuer_gets_podssh_s_hint() {
        let typed = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Error::InvalidCertificate(CertificateError::UnknownIssuer),
        );
        assert_eq!(
            handshake_hint(&typed).as_deref(),
            Some(
                "no root that podssh trusts here signs the certificate: a proxy that re-signs TLS needs its CA, in \
                 --ca-file FILE or SSL_CERT_FILE, which replace podssh's roots, or in podssh-ca.pem next to the \
                 binary, which adds to them"
            )
        );
    }

    /// A failure of a road keeps the kind of its cut, its bound and its
    /// words, as podssh's roads said them.
    #[test]
    fn a_failure_of_a_road_is_podssh_s_connect_error() {
        let limit = Duration::from_secs(3);
        let reset =
            pod_tls::handshake_error(std::io::Error::from(std::io::ErrorKind::ConnectionReset), context().words());
        assert!(matches!(connect_error(reset, limit), ConnectError::Tls(TlsFailure { cut: Some(Cut::Reset), .. })));
        let refused = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Error::InvalidCertificate(CertificateError::UnknownIssuer),
        );
        let refused = connect_error(pod_tls::handshake_error(refused, context().words()), limit);
        assert!(matches!(&refused, ConnectError::Tls(TlsFailure { cut: None, why }) if why.contains("--ca-file")));
        let slow = Failure::new(pod_core::Stage::Tls, Class::Timeout, "the TLS handshake timed out after 3s");
        assert_eq!(connect_error(slow, limit), ConnectError::Timeout { step: "the TLS handshake", after: limit });
        let dial = DialError::InvalidTarget("a name".into());
        let failed = Failure::caused(pod_core::Stage::Connect, Class::Usage, dial.to_string(), dial.clone());
        assert_eq!(connect_error(failed, limit), ConnectError::Dial(dial));
        let config = Failure::from(pod_tls::Error::Config("no roots".into()));
        assert_eq!(connect_error(config, limit), ConnectError::Config("TLS configuration: no roots".into()));
    }
}
