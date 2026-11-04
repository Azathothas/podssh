//! THE RELAY's item on the HTTP road (T-319), apart from `facts.rs` for the
//! length of that file; each number is read from the constant the road uses.

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
    vec![Block::Item { term: vec![Span::Lit("The HTTP road".into())], text }]
}
