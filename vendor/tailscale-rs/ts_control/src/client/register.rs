use std::fmt;

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, RegisterAuth, RegisterRequest, RegisterResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use url::Url;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Error registering this node with the control server.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum RegistrationError {
    /// The machine's keys weren't authorized to join the tailnet.
    ///
    /// The contained URL, if present, may be visited by the user in a browser to interactively
    /// authenticate the machine.
    #[error("machine was not authorized by control to join tailnet")]
    MachineNotAuthorized(Option<Url>),

    /// A network error occurred. Retrying later may resolve the problem.
    #[error("Network error")]
    NetworkError,

    /// An internal error occurred.
    #[error("error during registration: {0}")]
    Internal(InternalErrorKind),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InternalErrorKind {
    Url,
    SerDe,
    Utf8,
    Http,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
        }
    }
}

impl From<url::ParseError> for RegistrationError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL");
        RegistrationError::Internal(InternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for RegistrationError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serialization/deserialization error in registration");
        RegistrationError::Internal(InternalErrorKind::SerDe)
    }
}

impl From<ts_http_util::Error> for RegistrationError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error sending registration request");

        if crate::http_error_is_recoverable(error) {
            RegistrationError::NetworkError
        } else {
            RegistrationError::Internal(InternalErrorKind::Http)
        }
    }
}

impl From<core::str::Utf8Error> for RegistrationError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "utf8 error in registration response");
        RegistrationError::Internal(InternalErrorKind::Utf8)
    }
}

impl From<RegistrationError> for crate::Error {
    fn from(e: RegistrationError) -> Self {
        match e {
            RegistrationError::MachineNotAuthorized(Some(u)) => {
                crate::Error::MachineNotAuthorized(u)
            }
            RegistrationError::MachineNotAuthorized(None) => crate::Error::Internal(
                crate::InternalErrorKind::MachineAuthorization,
                crate::Operation::Registration,
            ),
            RegistrationError::Internal(k) => {
                crate::Error::Internal(k.into(), crate::Operation::Registration)
            }
            RegistrationError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::Registration)
            }
        }
    }
}

impl From<InternalErrorKind> for crate::InternalErrorKind {
    fn from(e: InternalErrorKind) -> Self {
        match e {
            InternalErrorKind::Url => crate::InternalErrorKind::Url,
            InternalErrorKind::SerDe => crate::InternalErrorKind::SerDe,
            InternalErrorKind::Utf8 => crate::InternalErrorKind::Utf8,
            InternalErrorKind::Http => crate::InternalErrorKind::Http,
        }
    }
}

/// Send a request to the control server to register this device.
///
/// If the `followup` argument is present, the request blocks in a long-poll until the user
/// authorizes the device using a browser. The url should have been produced by a previous call to
/// `register` via [`RegistrationError::MachineNotAuthorized`].
#[tracing::instrument(skip_all, fields(%control_url))]
pub async fn register(
    config: &crate::Config,
    control_url: &Url,
    auth_key: Option<&str>,
    followup: Option<Url>,
    node_keystate: &ts_keys::NodeState,
    http2_conn: &Http2<BytesBody>,
) -> Result<(), RegistrationError> {
    let node_public_key = node_keystate.node_keys.public;
    let network_lock_public_key = node_keystate.network_lock_keys.public;

    let register_req = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref(),
            app: &config.format_client_name(),
            ipn_version: crate::PKG_VERSION,
            ..Default::default()
        },
        nl_key: Some(network_lock_public_key),
        auth: auth_key.map(RegisterAuth::from),
        followup,
        ephemeral: config.ephemeral,
        ..Default::default()
    };

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&register_req)?
    } else {
        serde_json::to_string(&register_req)?
    };

    let register_url = control_url.join("machine/register")?;
    tracing::trace!(
        url = %register_url.as_str(),
        %body,
        "sending registration request"
    );

    let response = http2_conn
        .post(
            &register_url,
            [(
                LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
                node_public_key.to_string().parse().unwrap(),
            )],
            Bytes::from(body).into(),
        )
        .await?;

    let status = response.status();

    tracing::debug!(%status, "received registration response");

    if !status.is_success() {
        // Attempt to collect the body to log the error, truncating to prevent spamming the logs.
        let mut body = response.collect_bytes().await.unwrap_or_default();
        body.truncate(512);
        let body = core::str::from_utf8(&body).unwrap_or("<invalid utf8>");
        tracing::error!(%body, %status, "registration failed");

        return Err(RegistrationError::Internal(InternalErrorKind::Http));
    }

    let body = response.collect_bytes().await?;
    let body = core::str::from_utf8(&body)?;

    tracing::trace!(registration_response_body = %body);

    let register_resp: RegisterResponse = serde_json::from_str(body)?;

    if !register_resp.machine_authorized {
        if !register_resp.auth_url.is_empty() {
            Err(RegistrationError::MachineNotAuthorized(Some(
                register_resp.auth_url.parse()?,
            )))
        } else {
            Err(RegistrationError::MachineNotAuthorized(None))
        }
    } else {
        Ok(())
    }
}

/// Why a logout did not happen (podssh's patch 0016).
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum LogoutError {
    /// The node has not registered with the control server: there is nothing to log out.
    #[error("the node has not registered with the control server")]
    NotRegistered,

    /// The request could not be built or sent, or its answer could not be read.
    #[error("the request failed: {0}")]
    Request(#[from] RegistrationError),

    /// The control server answered with a status that is not a success.
    #[error("the control server answered HTTP {0}")]
    Status(u16),

    /// The control server answered with an error, as its response says it.
    #[error("the control server refused: {0}")]
    Refused(String),

    /// No answer came within the time given.
    #[error("no answer within the time given")]
    Timeout,

    /// The runtime that would send the request has stopped.
    #[error("the runtime has stopped")]
    Stopped,
}

/// The longest refusal text kept from a response: a server's text, shown to a user.
const MAX_REFUSAL: usize = 200;

/// The body of the request that logs this node out (podssh's patch 0016): this node's key, and an
/// expiry in the past, which expires that key at once ([`RegisterRequest::expiry`]). The expiry is
/// the one Go's client sends to log out (`time.Unix(123, 0)`). The control server finds the node
/// by its key, so no auth key goes with it: Go's client attaches its key to each register
/// request, and the key need not cross the network once more.
pub fn logout_body(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
) -> Result<String, RegistrationError> {
    let client_name = config.format_client_name();
    let request = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_keystate.node_keys.public,
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref(),
            app: &client_name,
            ipn_version: crate::PKG_VERSION,
            ..Default::default()
        },
        nl_key: Some(node_keystate.network_lock_keys.public),
        expiry: chrono::DateTime::from_timestamp(123, 0),
        ephemeral: config.ephemeral,
        ..Default::default()
    };

    Ok(serde_json::to_string(&request)?)
}

/// Log this node out (podssh's patch 0016): send [`logout_body`] to the control server, which
/// expires the node key and deletes an ephemeral node at once.
///
/// Any success status is an answer, unless the body names an error. The answer is not read as a
/// registration: it says the machine is no longer authorized (headscale answers so for an
/// ephemeral node that it deleted).
#[tracing::instrument(skip_all, fields(%control_url))]
pub async fn logout(
    config: &crate::Config,
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    http2_conn: &Http2<BytesBody>,
) -> Result<(), LogoutError> {
    let node_public_key = node_keystate.node_keys.public;
    let body = logout_body(config, node_keystate)?;
    let register_url = control_url
        .join("machine/register")
        .map_err(RegistrationError::from)?;

    let response = http2_conn
        .post(
            &register_url,
            [(
                LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
                node_public_key.to_string().parse().unwrap(),
            )],
            Bytes::from(body).into(),
        )
        .await
        .map_err(RegistrationError::from)?;

    let status = response.status();
    tracing::debug!(%status, "received logout response");

    let body = response.collect_bytes().await.unwrap_or_default();
    if !status.is_success() {
        let shown = String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned();
        tracing::error!(body = %shown, %status, "logout failed");
        return Err(LogoutError::Status(status.as_u16()));
    }

    let refusal = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|doc| doc.get("Error")?.as_str().map(str::to_owned))
        .unwrap_or_default();
    if !refusal.is_empty() {
        let shown: String = refusal
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_REFUSAL)
            .collect();
        tracing::error!(error = %shown, "logout refused");
        return Err(LogoutError::Refused(shown));
    }

    Ok(())
}
