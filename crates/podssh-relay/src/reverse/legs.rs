//! The operator's legs with tokens of one leg (T-615), and what a node's
//! socket heard of them. A session's first leg opens with the pair's connect
//! token; each leg after it, a resume, a move or a spare, with the next token
//! of the session, which the node's verdict gave the seed of
//! (`crate::e2e::legs`), so that a token that a proxy logged from a leg's
//! headers is spent already. A role that refuses one is no refusal of the
//! pair: the leg is tried again, and after twice the window of refusals in a
//! row the session's legs take the pair's token, as before.
//!
//! podssh's relay role says in its `hello` that it registers the tokens, and
//! that it rotates a pair's stop token (`POST /v1/rotate/<name>`); the binary
//! rotates its node's stop token only where a socket of the process heard
//! that ([`rotates`]), and the stop token of the next pair that the node
//! goes on with at an expiry only once a socket heard it after that move
//! ([`offers`], T-620).

use std::sync::atomic::{AtomicU64, Ordering};

use podssh_ws::client::ConnectError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use super::control::Hello;
use super::operator::{self, OperatorConfig, Outcome};
pub use crate::e2e::legs::{current, during, Pick, Taker, WINDOW};

/// The field of a role's `hello` that says that it rotates a pair's stop
/// token.
pub const ROTATION: &str = "stopRotation";

/// Why a leg did not open when the role refused its token of one leg: the
/// session goes on, with the next leg.
pub const REFUSED: &str = "the relay refused this session's token of one leg (403 reverse: forbidden): the next leg \
                           takes it again, then the next one, and the pair's token after a run of refusals";

/// The sockets of this process that heard a role that rotates stop tokens:
/// a count, not a flag, so that a node that moved to its next pair can wait
/// for that pair's own socket (T-620).
static ROTATES: AtomicU64 = AtomicU64::new(0);

/// What a node's socket heard in its role's `hello`.
pub fn heard(hello: &Hello) {
    if says_rotation(hello) {
        ROTATES.fetch_add(1, Ordering::SeqCst);
    }
}

/// Whether a role's `hello` says that it rotates stop tokens: `true`, and
/// nothing else (`crate::answer`).
pub fn says_rotation(hello: &Hello) -> bool {
    crate::answer::offers(hello.extra.get(ROTATION))
}

/// Whether a socket of this process's node heard a role that rotates the
/// pair's stop token.
pub fn rotates() -> bool {
    offers() > 0
}

/// How many sockets of this process's node heard a role that rotates the
/// pair's stop token. A node takes the count when it begins with a pair, and
/// rotates that pair's token once the count grew: a socket of the pair heard
/// it, as a node's sockets are of one pair at a time.
pub fn offers() -> u64 {
    ROTATES.load(Ordering::SeqCst)
}

/// [`operator::start`] for a leg of a session after its first: with the
/// session's next token of one leg, where its node gave a seed ([`current`],
/// inside [`during`]), else with the pair's connect token of `config`.
pub async fn start<IO>(config: &OperatorConfig<'_>, io: IO) -> Result<JoinHandle<Outcome>, ConnectError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let picked = current().map(|taker| {
        let pick = taker.pick();
        (taker, pick)
    });
    let Some((taker, Pick::Leg(index, token))) = picked else { return operator::start(config, io).await };
    let leg = OperatorConfig {
        relay: config.relay,
        name: config.name,
        connect_token: &token,
        trust: config.trust,
        proxy: config.proxy,
        timeout: config.timeout,
        limits: config.limits,
        wire: config.wire,
    };
    match operator::start(&leg, io).await {
        // The role took the token: the next leg takes the next one.
        Ok(handle) => {
            taker.upgraded(index);
            Ok(handle)
        }
        Err(ConnectError::Refused { status: 403, .. }) => {
            taker.refused(index);
            Err(ConnectError::Upgrade(REFUSED.into()))
        }
        // No answer of the role's about the token: the next leg tries it again.
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_true_of_its_field_says_that_the_role_rotates() {
        let read = |text: &str| -> Hello { serde_json::from_str(text).unwrap() };
        assert!(says_rotation(&read(r#"{"maxSessions":64,"stopRotation":true}"#)));
        for text in
            [r#"{"maxSessions":64}"#, r#"{"stopRotation":false}"#, r#"{"stopRotation":"yes"}"#, r#"{"stopRotation":1}"#]
        {
            assert!(!says_rotation(&read(text)), "{text}");
        }
        let before = offers();
        heard(&read(r#"{"stopRotation":true}"#));
        assert!(rotates(), "once heard, for the process");
        assert!(offers() > before, "each socket that heard it counts (T-620)");
        let after = offers();
        heard(&read(r#"{"maxSessions":64}"#));
        assert_eq!(offers(), after, "a hello with no offer counts nothing");
    }
}
