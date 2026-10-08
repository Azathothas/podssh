//! E15 — ⛔ **the DoH seam, so the one stage this machine cannot exercise has a
//! test.**
//!
//! ⛔ **`DohTransport` is `Box::pin` and not `#[async_trait]`.** ⛔ A trait with an
//! `async fn` is ⛔ **not `dyn`-compatible**, ⛔ and ⛔ [`crate::dns::Sources`] needs
//! to hold one behind an `Arc` ⛔ — ⛔ **so the seam is a boxed future and the cost
//! is one `Pin<Box<..>>` per query.** ⛔ The seam matters more than the
//! ergonomics, ⛔ because ⛔ **the DoH stage is the only one that cannot be
//! exercised from this machine at all** ⛔ and ⛔ **a stage with no substitutable
//! transport is a stage with no test.**
//!
//! ⛔ **Nothing inside `send` may call a resolver.** ⛔ The endpoint already holds
//! an IP literal ⛔ — ⛔ **a DoH request resolved by name makes the fallback
//! depend on the thing it is a fallback for** ⛔ — ⛔ so ⛔ **the only way to carry
//! this request is to dial the literal.**

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use super::{DohEndpoint, DohResponse, TYPE_A, TYPE_AAAA};
use super::wire::base64url_decode;

/// ⛔ **One query answered, as a value.** ⛔ `DohTransport` returns this rather
/// than a bare body so ⛔ **the stage can be tested against a fake transport
/// without a socket**, ⛔ and ⛔ **so the `Doh` stage has a seam at all on a
/// machine where no DoH endpoint has ever been measured as reachable.**
///
/// ⛔ **`Box::pin` and not `async fn` in the trait** ⛔ — ⛔ `#[async_trait]` is a
/// dependency this crate does not carry and ⛔ **a trait with an `async fn` is
/// not `dyn`-compatible**, ⛔ which is what [`Sources`](crate::dns::Sources)
/// needs. ⛔ **The seam matters more than the ergonomics**, ⛔ because ⛔ **the DoH
/// stage is the only one that cannot be exercised from this machine at all** and
/// a test that cannot substitute a transport would leave it untested.
pub trait DohTransport: Send + Sync {
    /// ⛔ **Send the request and return the response.** ⛔ **No host is resolved
    /// here**: the endpoint already holds a literal address, and ⛔ **nothing
    /// inside this call may call a resolver**, because that would be the
    /// fallback depending on itself.
    fn send(
        &self,
        endpoint: &DohEndpoint,
        request_line: &str,
        headers: &[(String, String)],
        budget: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DohResponse, String>> + Send + '_>>;
}

/// ⛔ **A transport that answers from a table, for a plant.** ⛔ **It exists
/// in the library and not only in the tests** ⛔ because ⛔ **E05's probe will
/// need to carry exactly this request**, ⛔ and ⛔ **a probe written separately
/// from the stage it probes is a probe that tests the probe.**
pub struct ScriptedTransport {
    replies: std::collections::HashMap<String, DohResponse>,
    /// ⛔ Every request line that was sent, ⛔ in order. ⛔ **A test asserts on
    /// this**: ⛔ **an empty list means the stage never asked**, ⛔ and ⛔ a
    /// `Doh` stage that reported `ok` having asked nothing would be the exact
    /// defect `????` exists to prevent.
    pub asked: std::sync::Mutex<Vec<String>>,
}

impl ScriptedTransport {
    pub fn new() -> Self {
        Self {
            replies: std::collections::HashMap::new(),
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// ⛔ **Answer `name` with this body.** ⛔ The key is the record `name` the
    /// body will carry, ⛔ **because a body whose records name something else is
    /// not an answer to the question that was asked** ⛔ — ⛔ and that case is one
    /// of the plants.
    pub fn reply(mut self, name: &str, status: u16, body: &str) -> Self {
        self.replies.insert(
            name.to_ascii_lowercase(),
            DohResponse { status, body: body.to_string() },
        );
        self
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Default for ScriptedTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DohTransport for ScriptedTransport {
    fn send(
        &self,
        _endpoint: &DohEndpoint,
        request_line: &str,
        _headers: &[(String, String)],
        _budget: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<DohResponse, String>> + Send + '_>> {
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request_line.to_string());
        // ⛔ **The scripted answer is keyed on the wire question, decoded** ⛔ —
        // ⛔ **so the base64url encoder is exercised on every plant** and ⛔
        // ⛔ **an encoder that is subtly wrong produces a question nobody
        // answers**, ⛔ which is ⛔ **the plant that would then pass by
        // asserting an empty answer.**
        let question = decode_question(request_line).unwrap_or_default();
        let reply = self
            .replies
            .get(&question.0.to_ascii_lowercase())
            .cloned()
            .unwrap_or(DohResponse { status: 200, body: "{\"Status\":3}".to_string() });
        Box::pin(async move { Ok(reply) })
    }
}

/// ⛔ **The `(name, qtype)` inside a request line, decoded from the wire.** ⛔
/// ⛔ **This is a test and probe helper, not a parser**, and ⛔ **it returning
/// `None` for a line it cannot read is the honest answer** ⛔ — ⛔ **a
/// request podssh cannot read back is a request worth failing a plant on.**
pub fn decode_question(request_line: &str) -> Option<(String, &'static str)> {
    let after = request_line.split_once("dns=")?.1;
    let encoded = after.split(' ').next()?;
    let bytes = base64url_decode(encoded)?;
    // ⛔ 12 bytes of header, then labels, then a zero byte, then two bytes of
    // type and two of class.
    let mut at = 12usize;
    let mut name = String::new();
    loop {
        let len = *bytes.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        let label = bytes.get(at..at + len)?;
        at += len;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
    }
    let qtype = u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]);
    Some((name, if qtype == 28 { TYPE_AAAA } else { TYPE_A }))
}
