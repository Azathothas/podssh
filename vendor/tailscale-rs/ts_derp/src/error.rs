/// Errors encountered during derp client operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error failed to parse.
    #[error(transparent)]
    BadUrl(#[from] url::ParseError),

    /// Deserializing JSON failed.
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),

    /// There was an error parsing the derp frame.
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),

    /// An underlying IO error was encountered.
    #[error(transparent)]
    IoFailure(#[from] std::io::Error),

    /// Dialling a derp server failed.
    #[error(transparent)]
    Dial(#[from] crate::dial::Error),

    /// No derp server in the region was reachable.
    #[error("no reachable DERP server in the region")]
    NoServerReachable,

    /// The WebSocket transport failed. Boxed: as a value it made each `Result` of this crate
    /// large (podssh's patch 0020).
    #[error(transparent)]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),

    /// Unsupported derp protocol version.
    #[error("unsupported DERP protocol version {0}, only supported version is {1}")]
    UnsupportedProtocolVersion(usize, usize),

    /// Received an unknown frame type.
    #[error("received unexpected DERP frame type '{0}'")]
    UnexpectedRecvFrameType(crate::frame::FrameType),

    /// Error in HTTP connection.
    #[error("http error")]
    Http,
}

impl Error {
    /// The WebSocket close that ended the connection, when one did (podssh's patch 0019).
    pub fn ws_close(&self) -> Option<&crate::ws::WsClose> {
        match self {
            Error::IoFailure(e) => e.get_ref()?.downcast_ref(),
            _ => None,
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Error::WebSocket(Box::new(e))
    }
}

impl From<ts_http_util::Error> for Error {
    fn from(_: ts_http_util::Error) -> Self {
        Error::Http
    }
}
