//! A pair that its owner renews in podssh's relay role (T-592), beside the
//! contract, which renews none. `POST /v1/renew/<name>` with the stop token,
//! which the owner alone holds, extends the pair to 72 h from then with its
//! three tokens, so that each operator's file keeps working; and the role's
//! status names the pair's end beside the contract's fields, so that an
//! operator's host, whose file names the end that it was given, learns the
//! new one. A relay of the contract answers the path as one that it does not
//! have (404, or 405), which is no refusal: it renews no pair.

use serde::Deserialize;

use super::{checked, refused, with_token, OperatorPart, Pair, PairContext, PairError, Presence};

/// The path of a renewal, before the pair's name.
pub const PATH: &str = "/v1/renew/";

/// What a renewal gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewed {
    /// The pair's new end, in milliseconds since the epoch.
    Until(i64),
    /// The relay renews no pair: 404 or 405 at the path.
    NotServed,
}

#[derive(Deserialize)]
struct Answer {
    expires: i64,
}

/// `POST /v1/renew/<name>` with `pair`'s stop token. A `403` is the
/// contract's refusal of a token: the pair was stopped, or it ended.
pub async fn renew(ctx: &PairContext<'_>, pair: &Pair) -> Result<Renewed, PairError> {
    let path = format!("{PATH}{}", checked(&pair.name)?);
    let response = with_token(ctx, "POST", &path, pair.stop_token()).await?;
    match response.status {
        200..=299 => {
            let answer: Answer = serde_json::from_slice(&response.body)
                .map_err(|_| PairError::BadAnswer("not the expected answer to renew"))?;
            // The role's end is never earlier than it was: an answer that
            // says so renewed nothing.
            if answer.expires < pair.expires_ms {
                return Err(PairError::BadAnswer("an end before the pair's own"));
            }
            Ok(Renewed::Until(answer.expires))
        }
        404 | 405 => Ok(Renewed::NotServed),
        status => Err(refused(status, &response)),
    }
}

impl Pair {
    /// This pair with its end at `expires_ms` and its tokens the same: the
    /// copy that a renewal keeps. Each copy zeroes its tokens when it is
    /// dropped.
    pub fn with_expiry(&self, expires_ms: i64) -> Pair {
        Pair {
            relay: self.relay.clone(),
            name: self.name.clone(),
            node_token: self.node_token.clone(),
            connect_token: self.connect_token.clone(),
            stop_token: self.stop_token.clone(),
            expires_ms,
        }
    }
}

/// A pair's status, and its end where the relay names it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Status {
    pub online: bool,
    pub sessions: u64,
    /// The end in milliseconds since the epoch: podssh's relay role gives
    /// it, a relay of the contract does not.
    #[serde(default)]
    pub expires: Option<i64>,
    /// Its owner halted it, and why (T-647): podssh's relay role says so, a
    /// relay of the contract says neither.
    #[serde(default)]
    pub halted: bool,
    #[serde(default)]
    pub halt_reason: Option<String>,
}

impl Status {
    /// The contract's part of it.
    pub fn presence(&self) -> Presence {
        Presence { online: self.online, sessions: self.sessions }
    }
}

/// `GET /v1/status/<name>` with the connect token, as [`super::status`]
/// asks it, with the pair's end where the relay gives it.
pub async fn status(ctx: &PairContext<'_>, part: &OperatorPart) -> Result<Status, PairError> {
    let path = format!("/v1/status/{}", checked(&part.name)?);
    let response = with_token(ctx, "GET", &path, part.connect_token()).await?;
    match response.status {
        200..=299 => {
            serde_json::from_slice(&response.body).map_err(|_| PairError::BadAnswer("not the expected status"))
        }
        status => Err(refused(status, &response)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_of_the_contract_has_no_end_and_the_role_s_has_one() {
        let contract: Status = serde_json::from_str(r#"{"online": false, "sessions": 0}"#).unwrap();
        assert_eq!(contract.expires, None);
        assert_eq!(contract.presence(), Presence { online: false, sessions: 0 });
        let role: Status = serde_json::from_str(r#"{"online": true, "sessions": 2, "expires": 5}"#).unwrap();
        assert_eq!((role.online, role.sessions, role.expires), (true, 2, Some(5)));
        assert!(!contract.halted && !role.halted && role.halt_reason.is_none());
        let halted = r#"{"online": true, "sessions": 0, "expires": 5, "halted": true, "halt_reason": "a disk"}"#;
        let halted: Status = serde_json::from_str(halted).unwrap();
        assert_eq!((halted.halted, halted.halt_reason.as_deref()), (true, Some("a disk")), "the role's halt (T-647)");
    }

    #[test]
    fn a_renewed_copy_keeps_each_token_and_takes_the_new_end() {
        let (name, token) = (format!("p-{}", "0".repeat(32)), "a".repeat(64));
        let body = format!(
            r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":3600000}}"#
        );
        let relay = crate::relay::Relay { host: "relay.test".into(), port: 443 };
        let pair = super::super::parse(&relay, body.as_bytes(), 0).unwrap();
        let renewed = pair.with_expiry(7_200_000);
        assert_eq!((renewed.name.as_str(), renewed.expires_ms), (name.as_str(), 7_200_000));
        assert_eq!(renewed.stop_token(), pair.stop_token());
        assert_eq!(renewed.connect_token(), pair.connect_token());
        assert_eq!(renewed.node_token(), pair.node_token());
    }
}
