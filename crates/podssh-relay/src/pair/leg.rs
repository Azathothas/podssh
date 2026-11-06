//! A leg to a node of the net at a member's relay role (T-434): `POST
//! /v1/leg/<KEY>`, KEY the node's key as the net's document names it, with
//! the client's key proven when the role asks for it (`crate::keyed`): the
//! key of its end-to-end channel, the one that the net names for it. The
//! role answers with the name of the pair that the node's key made there,
//! and a token of one leg of it, which one upgrade of `/v1/connect/<name>`
//! takes. The client needs no pair of the node's: the two ends share the net,
//! and the role lends its sockets to the keys that it mints for.

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{refused, PairContext, PairError};
use crate::cache::valid_token;
use crate::identity::{Identity, PublicKey};
use crate::relay::check_node_name;

/// What the role drew: the pair's name, and a token of one leg of it.
pub struct Drawn {
    pub name: String,
    token: Zeroizing<String>,
    /// When the token ends, in milliseconds since the epoch.
    pub expires_ms: u64,
}

impl Drawn {
    /// For one upgrade of `/v1/connect/<name>`. Never printed.
    pub fn token(&self) -> &str {
        &self.token
    }
}

#[derive(Deserialize)]
struct Answer {
    name: String,
    token: String,
    expires: u64,
}

/// The path of a leg to the node of `key`.
pub fn path(key: &PublicKey) -> String {
    format!("/v1/leg/{}", key.hex())
}

/// Ask the role of `ctx` for a leg to the node of `node`, proving
/// `identity`, or this host's client key with none.
pub async fn ask(ctx: &PairContext<'_>, node: &PublicKey, identity: Option<&Identity>) -> Result<Drawn, PairError> {
    let (host, port) = (&ctx.relay.host, ctx.relay.port);
    let path = path(node);
    let response = crate::keyed::post_by(identity, host, port, &path, "", ctx.trust, ctx.proxy, ctx.timeout)
        .await
        .map_err(PairError::Connect)?;
    match response.status {
        200..=299 => parse(&response.body),
        status => Err(refused(status, &response)),
    }
}

/// The role's answer: a name that cannot change the path, and a token of a
/// token's shape. No error quotes the body, which holds the token.
fn parse(body: &[u8]) -> Result<Drawn, PairError> {
    let Answer { name, token, expires } =
        serde_json::from_slice(body).map_err(|_| PairError::BadAnswer("not the expected JSON of a leg"))?;
    let token = Zeroizing::new(token);
    check_node_name(&name).map_err(|_| PairError::BadAnswer("the name could change the relay path"))?;
    if !valid_token(&token) {
        return Err(PairError::BadAnswer("the token does not have the shape of a token"));
    }
    Ok(Drawn { name, token, expires_ms: expires })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leg_reads_its_name_and_token_and_refuses_a_name_that_leaves_the_path() {
        let token = "ab".repeat(32);
        let body = format!(r#"{{"name":"p-a","token":"{token}","expires":5}}"#);
        let drawn = parse(body.as_bytes()).expect("a leg");
        assert_eq!((drawn.name.as_str(), drawn.token(), drawn.expires_ms), ("p-a", token.as_str(), 5));
        let body = format!(r#"{{"name":"../x","token":"{token}","expires":5}}"#);
        assert!(parse(body.as_bytes()).is_err());
        assert!(parse(br#"{"name":"p-a","token":"x","expires":5}"#).is_err(), "a token too short");
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn the_path_names_the_node_s_key_in_hex() {
        let key = PublicKey([1; 32]);
        assert_eq!(path(&key), format!("/v1/leg/{}", "01".repeat(32)));
    }
}
