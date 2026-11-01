//! The first bytes of each QUIC stream of a quick tunnel (T-301), sans-IO:
//! six bytes that name the kind of stream and the version `01`, then a Cap'n
//! Proto `ConnectRequest` from the edge, or the node's `ConnectResponse`
//! (cloudflared 2026.10.6: `tunnelrpc/quic/protocol.go`,
//! `tunnelrpc/proto/quic_metadata_protocol.capnp`). Metadata carries what
//! HTTP/2 carries in headers: `HttpMethod`, `HttpHost` and `HttpHeader:NAME`
//! in a request, `HttpStatus` and `HttpHeader:NAME` in an answer
//! (`connection/quic_connection.go`).

use super::capnp::{Builder, Malformed, Message, CONTROL_BUDGET};

/// The signature of a data stream, and of an RPC stream of the edge.
pub const DATA_STREAM: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];
pub const RPC_STREAM: [u8; 6] = [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];
/// The one version.
pub const VERSION: [u8; 2] = *b"01";
/// The signature and the version, before each message.
pub const PREAMBLE: usize = 8;
/// The metadata's prefix of a header, and the key of an answer's status.
pub const HEADER: &str = "HttpHeader:";
pub const STATUS: &str = "HttpStatus";

/// What a stream of the edge carries (`ConnectionType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Http,
    WebSocket,
    Tcp,
    /// A type that cloudflared 2026.10.6 does not have.
    Other(u16),
}

/// A stream by its first six bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Data,
    Rpc,
    Unknown,
}

pub fn stream(signature: &[u8; 6]) -> Stream {
    match *signature {
        DATA_STREAM => Stream::Data,
        RPC_STREAM => Stream::Rpc,
        _ => Stream::Unknown,
    }
}

/// The edge's request on a data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub dest: String,
    pub kind: Kind,
    pub metadata: Vec<(String, String)>,
}

impl ConnectRequest {
    /// The header `name`, in any case of its letters, as HTTP reads one.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.metadata.iter().find_map(|(key, value)| {
            let header = key.strip_prefix(HEADER)?;
            header.eq_ignore_ascii_case(name).then_some(value.as_str())
        })
    }
}

/// The request of a frame: `dest` (pointer 0), `type` (the data's first two
/// bytes), `metadata` (pointer 1), each pair a `key` and a `val`. Read within
/// the control stream's budget, so the pairs are at most that many (T-403).
pub fn read_request(frame: &[u8]) -> Result<ConnectRequest, Malformed> {
    let message = Message::read_within(frame, CONTROL_BUDGET)?;
    let root = message.root()?;
    let dest = root.get_text(0)?.unwrap_or_default().to_string();
    let kind = match root.u16(0) {
        0 => Kind::Http,
        1 => Kind::WebSocket,
        2 => Kind::Tcp,
        n => Kind::Other(n),
    };
    // No capacity from the count: it is the edge's word, which the budget
    // bounds, and each pair is read before it is kept.
    let mut metadata = Vec::new();
    for pair in root.get_struct_list(1)? {
        let key = pair.get_text(0)?.unwrap_or_default().to_string();
        let value = pair.get_text(1)?.unwrap_or_default().to_string();
        metadata.push((key, value));
    }
    Ok(ConnectRequest { dest, kind, metadata })
}

/// The preamble of the node's answer.
pub fn preamble() -> [u8; PREAMBLE] {
    let mut out = [0u8; PREAMBLE];
    out[..6].copy_from_slice(&DATA_STREAM);
    out[6..].copy_from_slice(&VERSION);
    out
}

/// A `ConnectResponse` as a frame: `error` (pointer 0, none when empty) and
/// `metadata` (pointer 1), the fields in the order that capnp's encoder lays
/// them out.
pub fn response(error: &str, metadata: &[(&str, &str)]) -> Vec<u8> {
    let (mut b, root) = Builder::new(0, 2);
    if !error.is_empty() {
        b.set_text(root, 0, error);
    }
    if !metadata.is_empty() {
        let pairs = b.init_struct_list(root, 1, metadata.len() as u32, 0, 2);
        for (at, (key, value)) in pairs.into_iter().zip(metadata) {
            b.set_text(at, 0, key);
            b.set_text(at, 1, value);
        }
    }
    b.frame()
}

/// The answer to a visitor's WebSocket: 101, and the headers of the upgrade,
/// as cloudflared's origin proxy writes them over QUIC.
pub fn websocket_answer(key: &str) -> Vec<u8> {
    let accept = podssh_ws::handshake::accept_key(key);
    let pairs = [
        (STATUS, "101"),
        ("HttpHeader:Connection", "Upgrade"),
        ("HttpHeader:Sec-Websocket-Accept", accept.as_str()),
        ("HttpHeader:Upgrade", "websocket"),
    ];
    response("", &pairs)
}

/// The refusal of any other request: 404, and why.
pub fn refusal() -> Vec<u8> {
    response("podssh serves only a visitor's WebSocket here", &[(STATUS, "404")])
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
