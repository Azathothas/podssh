//! A pair that its owner halts, and resumes, in podssh's relay role
//! (T-647), beside the contract, which halts none. `POST /v1/halt/<name>`
//! with the stop token, which the owner alone holds, and the owner's words,
//! closes each session of the pair and refuses each operator with those
//! words, while the pair's node keeps its socket; `POST /v1/resume/<name>`
//! takes operators again. A relay of the contract answers the paths as ones
//! that it does not have (404, or 405), which is no refusal: it halts no
//! pair.

use serde::Deserialize;

use super::{checked, refused, Pair, PairContext, PairError};

/// The paths of a halt and of a resume, before the pair's name.
pub const HALT: &str = "/v1/halt/";
pub const RESUME: &str = "/v1/resume/";
/// The longest words of a halt, in bytes, as the role takes them.
pub const REASON_MAX: usize = 200;
/// What each session of a halted pair hears with `1011`, and what each
/// refusal of an operator says first: a client that reads it knows that
/// each new leg gets it again until the owner resumes the pair.
pub const HALTED: &str = "the pair's owner halted it";

/// Whether `body`, of a `503` to an operator's upgrade, is a halt's.
pub fn is_halt(body: &str) -> bool {
    body.contains(HALTED)
}

/// What a halt gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halted {
    /// Halted now: the sessions that the halt closed.
    Now { sessions: u64 },
    /// Halted already, since that time, in ms since the epoch: nothing
    /// changed.
    Already { since: i64 },
    /// The relay halts no pair: 404 or 405 at the path.
    NotServed,
}

/// What a resume gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resumed {
    /// It was halted, and takes operators again.
    Now,
    /// It was not halted.
    NotHalted,
    /// The relay halts no pair: 404 or 405 at the path.
    NotServed,
}

#[derive(Deserialize)]
struct HaltAnswer {
    #[serde(default)]
    sessions: u64,
    #[serde(default)]
    since: i64,
    #[serde(default)]
    already: bool,
}

#[derive(Deserialize)]
struct ResumeAnswer {
    resumed: bool,
}

/// Whether `words` can be a halt's: [`REASON_MAX`] bytes at most, and no
/// control character, which the role would refuse (400).
pub fn check_reason(words: &str) -> Result<(), String> {
    if words.len() > REASON_MAX {
        return Err(format!("the reason is {} bytes; a halt takes {REASON_MAX} at most", words.len()));
    }
    if words.chars().any(char::is_control) {
        return Err("the reason holds a control character, such as a new line; a halt takes one line".into());
    }
    Ok(())
}

/// `POST /v1/halt/<name>` with `pair`'s stop token and `reason`. A `403` is
/// the contract's refusal of a token: the pair was stopped, or it ended.
pub async fn halt(ctx: &PairContext<'_>, pair: &Pair, reason: Option<&str>) -> Result<Halted, PairError> {
    let path = format!("{HALT}{}", checked(&pair.name)?);
    let body = match reason {
        Some(words) => serde_json::json!({ "reason": words }).to_string(),
        None => "{}".to_string(),
    };
    let response = post(ctx, &path, body.as_bytes(), pair.stop_token()).await?;
    match response.status {
        200..=299 => {
            let answer: HaltAnswer = serde_json::from_slice(&response.body)
                .map_err(|_| PairError::BadAnswer("not the expected answer to halt"))?;
            if answer.already {
                return Ok(Halted::Already { since: answer.since });
            }
            Ok(Halted::Now { sessions: answer.sessions })
        }
        404 | 405 => Ok(Halted::NotServed),
        status => Err(refused(status, &response)),
    }
}

/// `POST /v1/resume/<name>` with `pair`'s stop token.
pub async fn resume(ctx: &PairContext<'_>, pair: &Pair) -> Result<Resumed, PairError> {
    let path = format!("{RESUME}{}", checked(&pair.name)?);
    let response = post(ctx, &path, b"{}", pair.stop_token()).await?;
    match response.status {
        200..=299 => {
            let answer: ResumeAnswer = serde_json::from_slice(&response.body)
                .map_err(|_| PairError::BadAnswer("not the expected answer to resume"))?;
            Ok(if answer.resumed { Resumed::Now } else { Resumed::NotHalted })
        }
        404 | 405 => Ok(Resumed::NotServed),
        status => Err(refused(status, &response)),
    }
}

async fn post(
    ctx: &PairContext<'_>,
    path: &str,
    body: &[u8],
    token: &str,
) -> Result<podssh_ws::http::Response, PairError> {
    podssh_ws::client::https_with_token(
        "POST",
        &ctx.relay.host,
        ctx.relay.port,
        path,
        body,
        token,
        16 * 1024,
        ctx.trust,
        ctx.proxy,
        ctx.timeout,
    )
    .await
    .map_err(PairError::Connect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_halts_refusal_is_told_from_a_restart() {
        assert!(is_halt("reverse: the pair's owner halted it: a new disk\n"));
        assert!(!is_halt("reverse: relay restarting\n") && !is_halt("reverse: node unavailable"));
    }

    #[test]
    fn a_reason_is_one_short_line() {
        assert!(check_reason("a new disk, back at 14:00").is_ok());
        assert!(check_reason(&"a".repeat(REASON_MAX)).is_ok());
        assert!(check_reason(&"a".repeat(REASON_MAX + 1)).unwrap_err().contains("201 bytes"));
        assert!(check_reason("two\nlines").unwrap_err().contains("control character"));
    }
}
