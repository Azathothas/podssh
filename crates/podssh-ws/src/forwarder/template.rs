//! A forwarder's template (T-369): a `ws://` or `wss://` URL with `{host}`
//! and `{port}` once each, which the target fills in, or with neither, and
//! then the target goes in a first frame of JSON. The placeholders go in the
//! path or the query, never in the authority: a forwarder is reached by its
//! own name, and only the forwarder dials the target.

use crate::names::check_target;
use crate::url::WsUrl;

/// The placeholder of the target's host.
pub const HOST: &str = "{host}";
/// The placeholder of the target's port.
pub const PORT: &str = "{port}";

/// Where a forwarder takes its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// In the URL, as Mudlet's Worker takes `?host=H&port=P`.
    Query,
    /// In a first text frame, `{"Host":HOST,"Port":PORT}`, which the
    /// forwarder answers with `{"status":"ok"}` before the target's bytes,
    /// as ssheasy's proxy does.
    Frame,
}

/// A template, checked: its text as the user wrote it, its form, and the
/// URL with no query, which podssh's lines show.
#[derive(Clone, PartialEq, Eq)]
pub struct Template {
    text: String,
    form: Form,
    shown: String,
}

// The query is not shown: it may hold the service's own secret.
impl std::fmt::Debug for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Template").field("shown", &self.shown).field("form", &self.form).finish()
    }
}

impl Template {
    /// A template as the user wrote it. Refused: another scheme, a fragment,
    /// a placeholder in the authority, a brace that is no placeholder, one
    /// placeholder without the other or either twice, and each URL that
    /// [`WsUrl::parse`] refuses. The text itself is never in a refusal.
    pub fn parse(text: &str) -> Result<Template, String> {
        let text = text.trim();
        let lower = text.get(..6).unwrap_or(text).to_ascii_lowercase();
        let rest = if lower.starts_with("wss://") {
            &text[6..]
        } else if lower.starts_with("ws://") {
            &text[5..]
        } else {
            return Err(format!(
                "a forwarder's template is a ws:// or wss:// URL, with {HOST} and {PORT} once each, or with neither"
            ));
        };
        if text.contains('#') {
            return Err("a forwarder's template has no fragment, which is never sent".into());
        }
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        if authority.contains(['{', '}']) {
            return Err(format!(
                "{HOST} and {PORT} go in the path or the query: a forwarder is reached by its own name"
            ));
        }
        if text.replace(HOST, "").replace(PORT, "").contains(['{', '}']) {
            return Err(format!("a forwarder's template takes {HOST} and {PORT}, and no other brace"));
        }
        let (hosts, ports) = (text.matches(HOST).count(), text.matches(PORT).count());
        let form = match (hosts, ports) {
            (1, 1) => Form::Query,
            (0, 0) => Form::Frame,
            _ => {
                return Err(format!(
                    "a forwarder's template has {HOST} and {PORT} once each, or neither: this one has {HOST} \
                     {hosts} times and {PORT} {ports} times"
                ))
            }
        };
        // The URL as it goes out, the placeholders as they are: each byte
        // that would break the request is refused here, before a dial.
        let url = WsUrl::parse(text).map_err(|why| format!("a forwarder's template: {why}"))?;
        Ok(Template { text: text.to_string(), form, shown: url.shown() })
    }

    pub fn form(&self) -> Form {
        self.form
    }

    /// The forwarder in podssh's lines: the URL with no query.
    pub fn shown(&self) -> &str {
        &self.shown
    }

    /// The URL for `host:port`. The host is checked as each target of the
    /// relay is ([`check_target`]), before it goes in, and then its bytes
    /// but a letter, a digit, `.`, `-` and `_` are percent-encoded (the `:`
    /// of an IPv6 address): a name with `&`, `/`, `?` or a space would add
    /// a parameter or a path of its own.
    pub fn fill(&self, host: &str, port: u16) -> Result<WsUrl, String> {
        check_target(host).map_err(|why| format!("the target cannot go to a forwarder: {why}"))?;
        if port == 0 {
            return Err("the target cannot go to a forwarder: port 0 is not a port".into());
        }
        let text = match self.form {
            Form::Query => self.text.replacen(HOST, &encoded(host), 1).replacen(PORT, &port.to_string(), 1),
            Form::Frame => self.text.clone(),
        };
        WsUrl::parse(&text).map_err(|why| format!("the target cannot go to a forwarder: {why}"))
    }

    /// The first frame of the frame form, which podssh writes itself:
    /// `{"Host":HOST,"Port":PORT}`, the port a number, as ssheasy's proxy
    /// reads it. `None` in the query form.
    pub fn first_frame(&self, host: &str, port: u16) -> Option<String> {
        (self.form == Form::Frame).then(|| serde_json::json!({ "Host": host, "Port": port }).to_string())
    }
}

/// `host` for a URL: a letter, a digit, `.`, `-` and `_` as they are, and
/// each other byte as `%XX`.
fn encoded(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for b in host.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_with_both_placeholders_takes_the_target_in_its_url() {
        let t = Template::parse("wss://web-proxy.mudlet.org/?host={host}&port={port}").unwrap();
        assert_eq!((t.form(), t.shown()), (Form::Query, "wss://web-proxy.mudlet.org/"));
        let url = t.fill("github.com", 22).unwrap();
        assert_eq!((url.tls, url.host.as_str(), url.port), (true, "web-proxy.mudlet.org", 443));
        assert_eq!(url.target, "/?host=github.com&port=22");
        // An IPv6 target is encoded; a path form takes it too.
        let path = Template::parse("WS://f.example:8080/connect/{host}/{port}").unwrap();
        assert_eq!(path.shown(), "ws://f.example:8080/connect/{host}/{port}");
        assert_eq!(path.fill("2001:db8::1", 443).unwrap().target, "/connect/2001%3Adb8%3A%3A1/443");
        assert_eq!(path.first_frame("h", 1), None);
    }

    #[test]
    fn a_template_with_neither_sends_the_target_in_a_first_frame() {
        let t = Template::parse("wss://ssheasy.com/p").unwrap();
        assert_eq!((t.form(), t.shown()), (Form::Frame, "wss://ssheasy.com/p"));
        assert_eq!(t.fill("github.com", 22).unwrap().target, "/p");
        assert_eq!(t.first_frame("github.com", 22).unwrap(), r#"{"Host":"github.com","Port":22}"#);
    }

    #[test]
    fn a_template_that_is_not_one_is_refused_and_not_shown() {
        for bad in [
            "https://f.example/?host={host}&port={port}",
            "wss://f.example/?host={host}",
            "wss://f.example/?port={port}",
            "wss://f.example/{port}?host={host}&port={port}",
            "wss://f.example/{host}/{host}?port={port}",
            "wss://{host}:{port}/",
            "wss://f.example:{port}/{host}",
            "wss://f.example/?host={Host}&port={port}",
            "wss://f.example/?host={host}&port={port}#x",
            "wss://f.example/?host={host}&port={port}&k=a b",
            "wss://user:SECRET@f.example/p",
            "wss://f.example/p\r\nX-Relay-Token: t",
        ] {
            let refused = Template::parse(bad).unwrap_err();
            assert!(!refused.contains("SECRET") && !refused.contains("f.example"), "{bad:?}: {refused}");
        }
        let twice = Template::parse("wss://f.example/{port}?host={host}&port={port}").unwrap_err();
        assert!(twice.contains("{port} 2 times"), "{twice}");
    }

    /// The host is checked before it goes in: `&` would add a parameter of
    /// its own (planted: the check removed, this test fails).
    #[test]
    fn a_target_that_would_change_the_url_is_refused_before_it_goes_in() {
        let t = Template::parse("wss://f.example/?host={host}&port={port}").unwrap();
        for bad in ["a&b", "a&port=25", "a/b", "a?b", "a b", "a#b", "", "-x"] {
            let refused = t.fill(bad, 22).unwrap_err();
            assert!(refused.starts_with("the target cannot go to a forwarder"), "{bad:?}: {refused}");
        }
        assert!(t.fill("github.com", 0).is_err());
        let frame = Template::parse("wss://ssheasy.com/p").unwrap();
        assert!(frame.fill("a&b", 22).is_err(), "the frame form checks it too");
    }

    #[test]
    fn the_debug_form_shows_no_query() {
        let t = Template::parse("wss://f.example/p?key=SECRET&host={host}&port={port}").unwrap();
        let shown = format!("{t:?}");
        assert!(shown.contains("wss://f.example/p") && !shown.contains("SECRET"), "{shown}");
    }
}
