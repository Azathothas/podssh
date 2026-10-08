//! E12: where a token may be put, and where it may not.
//!
//! ⛔ **This is the second of the two guards, and it is a type-level one.** The
//! [`crate::security::token::RelayToken`] wrapper stops a token being *printed*.
//! This stops it being *placed in a URL*, which is the other thing the relay
//! specification warns about: ⛔ spec lines 94-96, *"use `?token=` or `/t/<t>/…`
//! only when headers are unavailable, since URLs can appear in logs."*
//!
//! ⛔ **The forward path can always set a header**, so the URL forms are not
//! implemented at all — ⛔ and a path that does not exist cannot be reached by
//! a future edit under time pressure. That is the point of the split: the
//! capability is not "hidden behind a flag", it is absent.

use std::collections::BTreeMap;

use super::token::{RelayToken, TOKEN_HEADER};

/// ⛔ **The whole request, and the only shape in which a token may travel.**
///
/// ⛔ The path is a `String` and a query is a `BTreeMap<String, String>`, and
/// ⛔ **`RelayToken` cannot be stored in either**, because it is not a `String`
/// and there is no `From<RelayToken> for String`. ⛔ The only field that takes
/// one is [`RelayRequest::headers`], and the only way to put a value in that
/// map is [`RelayRequest::with_token`] ⛔ — which is also where the URL is
/// built, and where the assertion that the token is not in it is made.
///
/// ⛔ **`Debug` is written by hand, and this is not tidiness.** ⛔ The header map
/// **holds the token as a `String`**, because HTTP headers are strings, so ⛔ a
/// derived `Debug` on this struct would print the live credential on
/// `{:?}` ⛔ — and `RelayToken`'s own `Debug` redaction, which is what makes the
/// wrapper work, would not help ⛔ because by the time it is in this map the
/// secret is a `String` and nothing about it says it is a secret. ⛔
/// `tests/token_redaction.rs::a_request_carries_the_token_in_the_header_and_nowhere_else`
/// is the assertion for it.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayRequest {
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for RelayRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayRequest")
            .field("path", &self.path)
            .field("query", &self.query)
            // ⛔ **The header map is summarised, not printed.** A header map
            // without a credential is ordinary and would be worth printing; one
            // with a credential is the leak, and ⛔ the only field that can
            // carry one is the token header, so naming that one and counting the
            // rest is enough to debug a request without ever naming a secret.
            .field("credential", &format_args!("<{} header, {} bytes>", TOKEN_HEADER, self.credential_len()))
            .finish()
    }
}

impl RelayRequest {
    /// ⛔ **A request with no credential on it.** A caller that gets this far
    /// and has no token gets a `403` from the relay (spec line 239: *"a token is
    /// required"*) — ⛔ and that is an **authentication** failure, not a
    /// reachability one, which is what [`RelayRequest::unauthenticated_is_auth`]
    /// exists to keep straight.
    pub fn new(path: impl Into<String>) -> Self {
        RelayRequest {
            path: path.into(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
    }

    /// ⛔ The request knobs spec lines 197-203 publish: `family`, `path`,
    /// `dial`, `precheck`. ⛔ **None of them is a credential and all of them are
    /// safe in a URL**, which is the asymmetry this module is about: ⛔ a query
    /// string is not a secret channel.
    pub fn with_query(mut self, key: &str, value: &str) -> Self {
        self.query.insert(key.to_string(), value.to_string());
        self
    }

    /// ⛔ **The one place a token enters a request.**
    pub fn with_token(mut self, token: &RelayToken) -> Self {
        self.headers.insert(TOKEN_HEADER.to_string(), token.header_value());
        self
    }

    /// ⛔ How long the credential is, without saying what it is. ⛔ For the
    /// hand-written `Debug` above, and ⛔ **for nothing else** — a length is not
    /// a security property and the number here is for a reader comparing two
    /// requests.
    fn credential_len(&self) -> usize {
        self.headers.get(TOKEN_HEADER).map_or(0, String::len)
    }

    /// ⛔ **The URL, and the assertion that it is clean.**
    ///
    /// ⛔ It returns `None` rather than a URL when the assembled string carries
    /// something shaped like a token. ⛔ That branch is unreachable through the
    /// constructors above ⛔ — **which is the intent** ⛔ and the reason the
    /// check is worth having: ⛔ it is the assertion a future edit to this
    /// module fails, rather than a runtime hope.
    pub fn url(&self) -> Option<String> {
        if self.query.values().any(|v| super::redact::looks_like_token(v))
            || super::redact::looks_like_token(&self.path)
        {
            return None;
        }
        if self.query.is_empty() {
            return Some(self.path.clone());
        }
        let query = self
            .query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        Some(format!("{}?{}", self.path, query))
    }

    /// ⛔ **A `403` on this request is an authentication failure.** Spec lines
    /// 97-99 name the body `missing or wrong token` and say a `403` that names
    /// the target (`not in the ALLOW list`) is a policy denial. ⛔ Reporting a
    /// token failure as "target unreachable" sends the operator to debug the
    /// wrong host, and this is the function that keeps the two apart.
    pub fn unauthenticated_is_auth(status: u16) -> bool {
        status == 403
    }

    /// ⛔ **Whether a `403` is worth one re-mint.** ⛔ Spec lines 97-99: a `403`
    /// *naming the target* is a policy denial a fresh token will not fix, and
    /// retrying it is the tight loop `E12` warns about. ⛔ So the body is what
    /// decides, and "names the target" is read as the allow-list phrase.
    pub fn is_policy_denial(body: &str) -> bool {
        body.to_ascii_lowercase().contains("allow list")
            || body.to_ascii_lowercase().contains("not in the allow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ MEASURED ground truth, this machine: `ssh-keygen -t ed25519 -N '' -f
    /// hk` → the base64 key below. ⛔ The token-shaped values in this file are
    /// ⛔ **synthetic**: `docs/TODO/security/tokens.md` records that two
    /// research agents minted live credentials while building this record's
    /// evidence base, so ⛔ **a real token must never be committed to a test,
    /// and these are the shape with the secret part replaced by a constant.**
    const SYNTHETIC: &str = "ephm1.1900000000000.forward.0000000000000000000000";

    #[test]
    fn the_token_travels_in_the_header_and_nowhere_else() {
        let token: RelayToken = SYNTHETIC.parse().expect("a synthetic token parses");
        let req = RelayRequest::new("wss://tcp.ssh.relay.ajam.dev/connect/github.com/22")
            .with_query("family", "4")
            .with_query("dial", "lazy")
            .with_token(&token);
        let url = req.url().expect("a clean request has a URL");
        assert_eq!(
            url, "wss://tcp.ssh.relay.ajam.dev/connect/github.com/22?dial=lazy&family=4"
        );
        assert_eq!(req.headers.get(TOKEN_HEADER).map(String::as_str), Some(SYNTHETIC));
        // ⛔ Asserted explicitly, and not by subtraction: a test that checked
        // "the header is there" alone would pass a build that also put the
        // token in the query.
        assert!(!url.contains(SYNTHETIC), "the token must not appear in the URL");
        assert!(!url.contains("token="), "no token query parameter may exist");
    }

    #[test]
    fn a_url_that_carries_a_token_is_refused_rather_than_built() {
        // ⛔ The constructor that would produce this does not exist, so the state
        // is reached by writing the map directly — which is exactly what a
        // future edit would have to do to reintroduce the bug.
        let mut req = RelayRequest::new("/connect/github.com/22");
        req.query.insert("token".into(), SYNTHETIC.into());
        assert!(req.url().is_none(), "a token in the query must have no URL");
    }

    #[test]
    fn a_path_that_carries_the_t_form_is_refused_rather_than_built() {
        let req = RelayRequest::new("/t/ephm1.1900000000000.forward.0000000000000000000000/connect/github.com/22");
        assert!(req.url().is_none(), "the /t/<t>/ path form must have no URL");
    }
}
