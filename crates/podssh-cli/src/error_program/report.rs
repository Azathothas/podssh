//! The report that the program of `PODSSH_ERROR_PROGRAM` gets (T-195): one
//! JSON object with the form's number, podssh's version, the system, the
//! command, the exit code, podssh's last messages, and the relay host with
//! its close. Never a token, a proxy URL or its password, a key, the
//! environment, the command line as typed, or a byte of a session: the
//! messages are podssh's own (`podssh_ssh::said`), and each goes through
//! [`mask`], which hides each value of a credential variable and the user
//! and password of each URL, and drops the controls of a terminal, as the
//! lines of `podssh doctor` do.

use serde_json::{json, Value};

/// The number of the report's form.
pub const SCHEMA: u32 = 1;

/// What stands in place of a hidden value.
pub const HIDDEN: &str = "<hidden>";

/// The variables that hold a credential: their values never go into a
/// report, nor into the program's environment.
pub const CREDENTIALS: &[&str] = &[
    podssh_relay::token::TOKEN_ENV,
    crate::ssh::cloudflare::CLIENT_ID_ENV,
    crate::ssh::cloudflare::CLIENT_SECRET_ENV,
    crate::ssh::cloudflare::TOKEN_ENV,
];

/// The variables of a proxy, whose URL may hold a user and a password.
const PROXIES: &[&str] = &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY"];

/// A shorter value is not hidden on its own: it would hide common words.
const SHORTEST: usize = 3;

/// The report of a run of `verb` that exits with `code`, after podssh said
/// `said`.
pub fn object(verb: Option<&str>, code: i32, said: &[String]) -> Value {
    let secrets = secrets(|name| std::env::var(name).ok());
    let messages: Vec<String> = said.iter().map(|line| mask(line, &secrets)).collect();
    json!({
        "schema": SCHEMA,
        "podssh": crate::help::version(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "verb": verb,
        "exit": code,
        "messages": messages,
        "relay": relay(&secrets),
    })
}

/// The relay host of the run and the relay's close, when the run had one:
/// from the record of the SSH client, else from `podssh proxy`'s.
fn relay(secrets: &[String]) -> Value {
    let facts = podssh_ssh::outcome::record().facts;
    let seen = match facts.relay_host {
        Some(host) => {
            let (code, reason) = facts.relay_close.unwrap_or_default();
            Some((host, code, reason))
        }
        None => crate::session_log::relay_seen().map(|(host, code)| (host, code, String::new())),
    };
    let Some((host, code, reason)) = seen else { return Value::Null };
    let reason = mask(&reason, secrets);
    json!({ "host": host, "close_code": code, "reason": (!reason.is_empty()).then_some(reason) })
}

/// The values that a report never holds, longest first, so that a part
/// never breaks a whole: each credential variable's value, and each proxy
/// variable's URL with its `user:password`, its user and its password.
pub fn secrets(var: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = Vec::new();
    for name in CREDENTIALS {
        out.extend(var(name));
    }
    for name in PROXIES {
        let Some(url) = var(name) else { continue };
        let rest = url.split_once("://").map_or(url.as_str(), |(_, rest)| rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if let Some((user_info, _)) = authority.rsplit_once('@') {
            out.push(user_info.to_string());
            out.extend(user_info.split(':').map(str::to_string));
        }
        out.push(url);
    }
    let mut out: Vec<String> = out.into_iter().map(|s| s.trim().to_string()).filter(|s| s.len() >= SHORTEST).collect();
    out.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    out.dedup();
    out
}

/// `line` as a report holds it: each of `secrets` and the `user:password@`
/// of each URL hidden, and no control character.
pub fn mask(line: &str, secrets: &[String]) -> String {
    let mut text = line.to_string();
    for secret in secrets {
        text = text.replace(secret.as_str(), HIDDEN);
    }
    podssh_ws::text::one_line(&without_user_info(&text))
}

/// `text` with the user and password of each URL in it hidden: what comes
/// before the last `@` of the part after `://`.
fn without_user_info(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail.find(|c: char| c.is_whitespace() || "/?#\"'<>".contains(c)).unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(sign) => {
                out.push_str(HIDDEN);
                out.push_str(&authority[sign..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}
