//! `POST /v1/leg/<KEY>` (T-434): a member of the owner's net that reaches a
//! node by no other road asks the role for a leg to the pair that the node's
//! key KEY made here. The asker proves its own key as for a mint (the `401`
//! with a challenge, then the signature of it, `keys::prove`); the answer is
//! `{"name", "token", "expires"}`, a token of one leg of that pair
//! ([`super::reverse::Pairs::draw_leg`]) for one upgrade of
//! `/v1/connect/<name>`. Only a role that mints for keys gives one: a role
//! that mints for anyone would hand a stranger a way to a member's node.

use std::sync::Arc;

use podssh_ws::http::request::{self, Request};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

use super::reverse::pairs::NoLeg;
use super::{answer, docs, tokens, Config};
use crate::identity::PublicKey;

/// The path's head.
pub const PREFIX: &str = "/v1/leg/";
/// The body is the proof: a key, a challenge, a signature.
const BODY_MAX: usize = 4096;

/// Whether `path` is a leg's.
pub fn serves(path: &str) -> bool {
    path.starts_with(PREFIX)
}

/// Serve one request for a leg on `stream`.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>, sni: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    if head.method != "POST" {
        let why = format!("{path}: not {}, but POST", head.method);
        return answer(&mut stream, request::refusal(405, &why, &[("Allow", "POST")])).await;
    }
    let body = match super::body(&mut stream, &head, pending, BODY_MAX, &path).await {
        Ok(body) => body,
        Err(refusal) => return answer(&mut stream, refusal).await,
    };
    let Some(maker) = path.strip_prefix(PREFIX).and_then(PublicKey::parse) else {
        let why = format!("{path}: the node's key is 64 hex digits after {PREFIX}");
        return answer(&mut stream, request::refusal(400, &why, &[])).await;
    };
    if super::keys::Whom::of(&cfg.mint).is_none() {
        let why = format!("{PREFIX}: this relay gives a leg only to the keys that it mints for");
        return answer(&mut stream, request::refusal(403, &why, &[])).await;
    }
    // The asker's key, proven; `Ok(None)` comes only from a role with no
    // list, which the check above refused.
    match super::proven(&cfg, &head, sni.as_deref(), &path, &body) {
        Ok(Some(_)) => {}
        Ok(None) => return answer(&mut stream, request::refusal(403, &format!("{path}: no key proven"), &[])).await,
        Err(refusal) => return answer(&mut stream, refusal).await,
    }
    match cfg.pairs.draw_leg(&maker, tokens::now_ms()) {
        Ok((name, token, expires)) => {
            cfg.event("leg drawn");
            answer(&mut stream, docs::json(&json!({ "name": name, "token": token, "expires": expires }))).await
        }
        // The same words for no pair and a node not joined: the asker learns
        // nothing of a key's pairs that its node does not serve now.
        Err(NoLeg::NoPair) => {
            let why = format!("{PREFIX}: no node of that key is joined here");
            answer(&mut stream, request::refusal(404, &why, &[])).await
        }
        Err(NoLeg::Failed(why)) => answer(&mut stream, request::refusal(503, &format!("{PREFIX}: {why}"), &[])).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leg_s_path_is_served_and_no_other() {
        assert!(serves("/v1/leg/00"));
        assert!(!serves("/v1/legs"));
        assert!(!serves("/v1/pair"));
    }
}
