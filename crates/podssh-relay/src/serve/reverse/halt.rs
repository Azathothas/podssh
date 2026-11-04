//! A pair that its owner halts, and resumes (T-647, GitHub #145), beside the
//! contract. `POST /v1/halt/<name>` with the stop token, which the owner
//! alone holds, and `{}` or `{"reason": TEXT}`, closes each session of the
//! pair once, with `1011 the pair's owner halted it`, its node hearing each
//! `close` with those words; then each operator's upgrade gets `503` with
//! the owner's words and no `Retry-After`, before a token of `once` or of
//! one leg is spent. The node keeps its socket, and so its name, and hears
//! `{"type":"halted"}`, which a node of before skips as a type that it does
//! not know. `POST /v1/resume/<name>` takes the next operator on the same
//! socket. A halt lives in memory alone: a role that restarts serves the
//! pair again, and nothing else ends a halt but a resume, a stop or the
//! pair's end.

use podssh_ws::http::request;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};

use super::close;
use super::pairs::{Pair, Pairs, Session};
use crate::reverse::framing::SessionId;
use crate::serve::{answer, docs, tokens, Config};

// The longest words of a halt, which go into a refusal's body and the
// status, never into a Close, whose reason is short; and what each session
// of a halted pair hears with `1011`, once, and each refusal says first:
// the words that podssh's client reads. One place for both sides.
pub use crate::pair::halt::{HALTED, REASON_MAX};
/// The field of the node's `hello` that says that the role halts a pair.
pub const OFFER: &str = "halt";
/// The close code of a halted session: the contract's for an end by the
/// relay, as `node unavailable`.
pub const CODE: u16 = 1011;

/// A pair's halt: since when, in ms since the epoch, and its owner's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halt {
    pub since_ms: u64,
    pub why: Option<String>,
}

impl Halt {
    /// The body of an operator's `503`: the halt, then its owner's words.
    pub fn refusal(&self) -> String {
        match &self.why {
            Some(why) => format!("reverse: {HALTED}: {why}"),
            None => format!("reverse: {HALTED}"),
        }
    }

    /// `{"type":"halted"}` for the node, with since when and its owner's
    /// words.
    pub fn frame(&self) -> String {
        let mut frame = json!({ "type": "halted", "since": self.since_ms });
        if let Some(why) = &self.why {
            frame["reason"] = json!(why);
        }
        frame.to_string()
    }
}

/// `{"type":"resumed"}` for the node of a pair that its owner resumed.
pub fn resumed() -> String {
    json!({ "type": "resumed" }).to_string()
}

/// The halt in a status, beside the contract's fields: `halted`, and while
/// it holds, since when and its owner's words.
pub fn status(body: &mut Value, halt: Option<&Halt>) {
    body["halted"] = json!(halt.is_some());
    if let Some(halt) = halt {
        body["halted_since"] = json!(halt.since_ms);
        if let Some(why) = &halt.why {
            body["halt_reason"] = json!(why);
        }
    }
}

const BAD_BODY: &str =
    "/v1/halt: the body is {} or {\"reason\": TEXT}, TEXT of 200 bytes at most, with no control character";

/// The owner's words in the body of a halt: `{}`, nothing, or `{"reason":
/// TEXT}`; blank words are none. `Err` with the words of a `400`.
pub fn reason(body: &[u8]) -> Result<Option<String>, &'static str> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let asked: Value = serde_json::from_slice(body).map_err(|_| BAD_BODY)?;
    match asked.as_object().map(|fields| fields.get("reason")) {
        Some(None | Some(Value::Null)) => Ok(None),
        Some(Some(Value::String(text))) if text.len() <= REASON_MAX && !text.chars().any(char::is_control) => {
            let text = text.trim();
            Ok((!text.is_empty()).then(|| text.to_string()))
        }
        _ => Err(BAD_BODY),
    }
}

/// What a halt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halted {
    /// The halt that holds: the first one, when the pair was halted already.
    pub halt: Halt,
    /// The sessions that it closed: none for a second halt.
    pub sessions: usize,
    pub already: bool,
}

impl Halted {
    /// The answer of `/v1/halt/<name>`.
    fn answer(&self) -> Value {
        let mut body = json!({ "halted": true, "sessions": self.sessions, "since": self.halt.since_ms });
        if self.already {
            body["already"] = json!(true);
        }
        body
    }
}

impl Pair {
    /// The halt that holds, when its owner halted the pair.
    pub fn halted(&self) -> Option<Halt> {
        self.lock().halted.clone()
    }
}

impl Pairs {
    /// Halt the pair `name` at `now_ms`, with its owner's words `why`; the
    /// caller checked the stop token. Each of its sessions ends once: its
    /// operator hears [`CODE`] and [`HALTED`] after what waits for it, and
    /// its node `close` with the same words after the session's bytes; each
    /// id stays in flight for a frame that crosses the halt (T-421). The
    /// node keeps its socket and hears `halted`. A second halt changes
    /// nothing. `None` for no such pair, or one that ended.
    pub fn halt(&self, name: &str, why: Option<String>, now_ms: u64) -> Option<Halted> {
        let pair = self.named(name)?;
        let mut state = pair.lock();
        if state.ended {
            return None;
        }
        if let Some(halt) = &state.halted {
            return Some(Halted { halt: halt.clone(), sessions: 0, already: true });
        }
        let halt = Halt { since_ms: now_ms, why };
        state.halted = Some(halt.clone());
        let ids: Vec<SessionId> = state.sessions.keys().copied().collect();
        let ended: Vec<(SessionId, Session)> = ids.iter().filter_map(|id| state.forget(id).map(|s| (*id, s))).collect();
        let node = state.node_outbox();
        drop(state);
        for (id, session) in &ended {
            if let Some(node) = &node {
                node.text_after(*id, close(id, Some(HALTED)));
            }
            session.operator.close(CODE, HALTED);
        }
        if let Some(node) = &node {
            node.text(halt.frame());
        }
        Some(Halted { halt, sessions: ended.len(), already: false })
    }

    /// Resume the pair `name`: its next operator joins on its node's socket,
    /// which hears `resumed`. Whether it was halted; `None` for no such pair,
    /// or one that ended. The caller checked the stop token.
    pub fn resume(&self, name: &str) -> Option<bool> {
        let pair = self.named(name)?;
        let mut state = pair.lock();
        if state.ended {
            return None;
        }
        let was = state.halted.take().is_some();
        let node = state.node_outbox();
        drop(state);
        if let (true, Some(node)) = (was, node) {
            node.text(resumed());
        }
        Some(was)
    }
}

/// `POST /v1/halt/<name>`, whose stop token was checked: `{"halted": true,
/// "sessions": N, "since": MS}`, and `"already": true` for a pair halted
/// before. A body that is not `{}` or a reason gets `400`; a pair that
/// ended meanwhile, the `403` of each failed authentication.
pub(super) async fn serve_halt<S>(stream: &mut S, name: &str, body: &[u8], cfg: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let why = match reason(body) {
        Ok(why) => why,
        Err(words) => return answer(stream, request::refusal(400, words, &[])).await,
    };
    match cfg.pairs.halt(name, why, tokens::now_ms()) {
        Some(halted) => {
            cfg.event("reverse halt");
            answer(stream, docs::json(&halted.answer())).await
        }
        None => answer(stream, request::refusal(403, "reverse: forbidden", &[])).await,
    }
}

/// `POST /v1/resume/<name>`, whose stop token was checked: `{"resumed":
/// true}`, or `false` for a pair that was not halted; a pair that ended
/// meanwhile gets `403`.
pub(super) async fn serve_resume<S>(stream: &mut S, name: &str, cfg: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match cfg.pairs.resume(name) {
        Some(was) => {
            if was {
                cfg.event("reverse resume");
            }
            answer(stream, docs::json(&json!({ "resumed": was }))).await
        }
        None => answer(stream, request::refusal(403, "reverse: forbidden", &[])).await,
    }
}

/// An operator's upgrade of `pair` while it is halted: `503` with its
/// owner's words, and no `Retry-After`, as no second ends a halt; `false`
/// when it is not halted, and nothing was said. No line of the role's for
/// it: each try of an operator would be one.
pub(super) async fn refused<S>(stream: &mut S, pair: &Pair) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(halt) = pair.halted() else { return false };
    answer(stream, request::refusal(503, &halt.refusal(), &[])).await;
    true
}

#[cfg(test)]
#[path = "halt_tests.rs"]
mod tests;
