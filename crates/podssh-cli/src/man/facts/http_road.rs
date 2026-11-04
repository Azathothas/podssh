//! THE RELAY's items on the HTTP road (T-319) and on the WebSocket over
//! HTTP/2 (T-321), apart from `facts.rs` for the length of that file; each
//! number is read from the constant the road uses.

use super::super::model::{Block, Span};

/// The item, after the relay's own.
pub(super) fn blocks() -> Vec<Block> {
    use podssh_relay::http_road::{client, BATCH_MAX, DOWN_MAX, WAIT_MAX};
    use podssh_relay::serve::http_road::sessions;
    let text = format!(
        "For a proxy that ends TLS for the relay's name, refuses the WebSocket upgrade and still carries plain \
         HTTPS requests. When each relay host failed and the way to one of them refused the upgrade (a page of the \
         proxy's, or a 426 of a relay that got the request with its Upgrade taken off), podssh ssh, each command \
         that reaches a server as it does, and podssh proxy carry the session over requests of HTTP/1.1 to that \
         host, which podssh relay serve serves, with the same token, the same targets and the same limits as the \
         WebSocket road. The split form comes first, on two connections, which the operator's ruling Q44 allows on \
         this road alone: the bytes up in numbered batches of {batch} KiB at most, one POST after another, and the \
         bytes down from their offset in a request that waits up to {wait} s; the role holds {window} batches and \
         {down} MiB down that the client has not acknowledged, and an answer down ends a moment after nothing more \
         came, or at {answer} MiB, so that a hop that holds an answer to its end holds a short one. Each request \
         goes again, as it was, until an answer comes, for {retry} s at most: a batch's number and an offset make it \
         one that may come twice. When the second connection does not answer within {limit} s, the serial form \
         follows on the first: one POST after another, each with a batch up when one waits and the bytes down in \
         its answer. A session's id goes in its paths, and its key in a header alone. PODSSH_HTTP_ROAD turns the \
         road off, or names one form. The default relay serves no HTTP road.",
        batch = BATCH_MAX / 1024,
        wait = WAIT_MAX.as_secs(),
        window = sessions::WINDOW,
        down = sessions::DOWN_WINDOW >> 20,
        answer = DOWN_MAX >> 20,
        retry = client::RETRY_FOR.as_secs(),
        limit = client::LIMIT.as_secs(),
    );
    vec![Block::Item { term: vec![Span::Lit("The HTTP road".into())], text }, h2_road()]
}

/// The item of the WebSocket over HTTP/2.
fn h2_road() -> Block {
    use podssh_ws::h2_road::{CONNECTION_WINDOW, IDLE, REMEMBERED, STREAMS, STREAM_WINDOW};
    let text = format!(
        "Where a relay host offers it, as podssh relay serve does, a session of podssh ssh, of each command that \
         reaches a server as it does, and of podssh proxy is one stream of an HTTP/2 connection (RFC 8441): podssh \
         offers h2, then http/1.1, by ALPN, on a TLS connection of this road alone, and once the server's SETTINGS \
         offer extended CONNECT, it asks for the session with a CONNECT whose :protocol is websocket, with the path, \
         the name and the token of the upgrade, the token in a field that HPACK never indexes; a 200 opens it, and \
         another status is the relay's refusal, as for the upgrade. The sessions of one process share a connection, \
         {streams} at most, each with a window of {stream} MiB in a window of {connection} MiB for the connection; \
         another session opens another connection, and one with no session closes after {idle} s. A lost connection \
         is a lost link for each of its sessions. Where TLS chose http/1.1, the upgrade goes on that connection; \
         where the SETTINGS offer no extended CONNECT, or HTTP/2 did not carry the CONNECT, that connection closes, \
         the upgrade goes on a new one, -v says why, and the run takes HTTP/1.1 to that host for {remembered} \
         minutes. PODSSH_H2 says which hosts take the road: by default a relay host that you named, and no host of \
         the default relay, whose edge offers no extended CONNECT. podssh doctor's line http2 names what a host \
         offers.",
        streams = STREAMS,
        stream = STREAM_WINDOW >> 20,
        connection = CONNECTION_WINDOW >> 20,
        idle = IDLE.as_secs(),
        remembered = REMEMBERED.as_secs() / 60,
    );
    Block::Item { term: vec![Span::Lit("The WebSocket over HTTP/2".into())], text }
}
