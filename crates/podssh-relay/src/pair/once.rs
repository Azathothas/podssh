//! A pair whose connect token takes one upgrade alone (T-226), which
//! podssh's relay role makes for `POST /v1/pair?once=1` and offers in its
//! `/relays.json`: a token that leaks from a log after its use is worth
//! nothing. The query holds no credential, and the proof of a key (T-448)
//! signs the path alone, as the role checks it.

use super::{now_ms, parse, refused, Pair, PairContext, PairError};

/// `POST /v1/pair`, asking with `once` for a connect token of one upgrade:
/// the pair, and whether the relay said that its token is so (`"once":
/// true`). A relay that does not offer it makes a pair of before, which the
/// caller refuses or keeps. A `409` means "pair again", which is done once.
pub async fn create_with(ctx: &PairContext<'_>, once: bool) -> Result<(Pair, bool), PairError> {
    create_by(ctx, once, None).await
}

/// [`create_with`], proving `identity` where the relay asks for a key, so
/// that the pair's maker is that key (T-434): a node's pair at a member of
/// its net, which another member finds by the node's key.
pub async fn create_by(
    ctx: &PairContext<'_>,
    once: bool,
    identity: Option<&crate::identity::Identity>,
) -> Result<(Pair, bool), PairError> {
    let query = if once { "?once=1" } else { "" };
    for _ in 0..2 {
        let (host, port) = (&ctx.relay.host, ctx.relay.port);
        let response =
            crate::keyed::post_by(identity, host, port, "/v1/pair", query, ctx.trust, ctx.proxy, ctx.timeout)
                .await
                .map_err(PairError::Connect)?;
        match response.status {
            200..=299 => {
                let pair = parse(ctx.relay, &response.body, now_ms())?;
                return Ok((pair, said_once(&response.body)));
            }
            409 => continue,
            status => return Err(refused(status, &response)),
        }
    }
    Err(PairError::Failed { status: 409, detail: ": the relay asked twice to pair again".into() })
}

/// Whether an answer of `/v1/pair` says that its connect token takes one
/// upgrade: a guarantee that `--once` asks for, which only `true` gives
/// (`crate::answer`).
pub fn said_once(body: &[u8]) -> bool {
    let answer = serde_json::from_slice::<serde_json::Value>(body);
    answer.is_ok_and(|answer| crate::answer::says_true(answer.get("once")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_answer_that_says_once_is_one() {
        assert!(said_once(br#"{"name":"p-a","once":true}"#));
        for body in
            [&br#"{"name":"p-a"}"#[..], br#"{"once":false}"#, br#"{"once":"true"}"#, br#"{"once":1}"#, b"not json"]
        {
            assert!(!said_once(body), "{}", String::from_utf8_lossy(body));
        }
    }
}
