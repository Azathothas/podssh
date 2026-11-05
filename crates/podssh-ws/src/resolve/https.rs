//! A name's HTTPS record (RFC 9460, type 65), read for its `ech` parameter
//! (key 5): the ECHConfigList that Encrypted Client Hello seals the name with
//! (T-642). From either form of DNS over HTTPS: the JSON API's `data`, in
//! RFC 9460's presentation form, as Cloudflare's and Google's write it (read
//! 2026-11-05), or in RFC 3597's generic form (`\# LEN HEX`); and RFC 8484's
//! wire form. Each length is checked before what it covers is read, as
//! `wire.rs` checks its own.
//!
//! The question goes to the same resolvers, in the same order and through the
//! same proxy as the dialer's fallback (`doh_srv`): only when ECH was asked
//! for, and once for each name and TTL (`crate::ech`).

use std::time::Duration;

use base64::Engine as _;
use tokio::time::Instant;

use super::{dns_safe, h2, read, way, wire, Doh, Form, Miss, DOH_EACH, DOH_RESOLVERS, MAX_ANSWER, NXDOMAIN};
use crate::dial::ProxyChoice;
use crate::http;
use crate::tls::{self, Trust};

/// The key of the `ech` parameter (RFC 9460, section 14.3.2).
pub const ECH_KEY: u16 = 5;

/// The longest list taken: a list of a few configs is a few hundred bytes.
pub const MAX_LIST: usize = 4096;

const CUT: &str = "an HTTPS record ends before a length that it gives";
const LIST_CUT: &str = "an ech parameter's ECHConfigList is not as long as its lengths say";

/// What a name's record gives Encrypted Client Hello: the ECHConfigList,
/// its own length first, as rustls takes it, and the record's TTL in seconds,
/// where the answer gave one.
pub use pod_tls::ech::Published;

/// The list of a JSON answer: the record of the lowest priority that holds
/// one; `None` where no record of type 65 holds one (none at all, an alias,
/// no `ech`, or one with no bytes). A record that does not read is an error
/// only where no other gave a list.
pub fn from_json(body: &[u8]) -> Result<Option<Published>, String> {
    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|_| "not a DNS JSON answer".to_string())?;
    // The resolver's status, as `answers` reads it for the other types.
    match doc.get("Status").and_then(|s| s.as_u64()) {
        Some(0) => {}
        Some(3) => return Err(NXDOMAIN.to_string()),
        other => {
            return Err(format!("DNS status {}", other.map(|s| s.to_string()).unwrap_or_else(|| "missing".into())))
        }
    }
    let mut found = Vec::new();
    let mut broken = None;
    for answer in doc.get("Answer").and_then(|a| a.as_array()).into_iter().flatten() {
        if answer.get("type").and_then(|t| t.as_u64()) != Some(u64::from(wire::HTTPS)) {
            continue;
        }
        let Some(data) = answer.get("data").and_then(|d| d.as_str()) else { continue };
        let ttl = answer.get("TTL").and_then(|t| t.as_u64()).and_then(|t| u32::try_from(t).ok());
        match from_text(data) {
            Ok(Some((priority, list))) => found.push((priority, list, ttl)),
            Ok(None) => {}
            Err(why) => {
                broken.get_or_insert(why);
            }
        }
    }
    pick(found, broken)
}

/// The list of a wire answer to the question of type 65 for `name`, as
/// [`from_json`] picks it.
pub fn from_wire(msg: &[u8], name: &str) -> Result<Option<Published>, String> {
    let mut found = Vec::new();
    let mut broken = None;
    for (start, len, ttl) in wire::records_kept(msg, name, wire::HTTPS)? {
        match from_rdata(&msg[start..start + len]) {
            Ok(Some((priority, list))) => found.push((priority, list, Some(ttl))),
            Ok(None) => {}
            Err(why) => {
                broken.get_or_insert(why);
            }
        }
    }
    pick(found, broken)
}

/// The record of the lowest priority (RFC 9460's order of preference), or why
/// none came.
fn pick(found: Vec<(u16, Vec<u8>, Option<u32>)>, broken: Option<String>) -> Result<Option<Published>, String> {
    match found.into_iter().min_by_key(|(priority, _, _)| *priority) {
        Some((_, list, ttl)) => Ok(Some(Published { list, ttl })),
        None => broken.map_or(Ok(None), Err),
    }
}

/// The priority and the list of one record's data in the wire form (RFC 9460,
/// section 2.2): `None` for an alias (priority 0), which holds no parameter,
/// and for a record with no `ech` or one with no bytes.
pub fn from_rdata(rdata: &[u8]) -> Result<Option<(u16, Vec<u8>)>, String> {
    let fixed = rdata.get(..2).ok_or(CUT)?;
    let priority = u16::from_be_bytes([fixed[0], fixed[1]]);
    let mut at = skip_target(rdata, 2)?;
    if priority == 0 {
        return Ok(None);
    }
    let (mut last, mut ech) = (None, None);
    while at < rdata.len() {
        let fixed = rdata.get(at..at + 4).ok_or(CUT)?;
        let key = u16::from_be_bytes([fixed[0], fixed[1]]);
        let len = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
        let value = rdata.get(at + 4..at + 4 + len).ok_or(CUT)?;
        // Section 2.2: a client takes a record whose keys do not rise as
        // malformed, a key twice among them.
        if last.is_some_and(|before| key <= before) {
            return Err("an HTTPS record's parameters are not in increasing order".into());
        }
        last = Some(key);
        if key == ECH_KEY {
            ech = Some(value);
        }
        at += 4 + len;
    }
    match ech {
        None | Some([]) => Ok(None),
        Some(list) => {
            check_list(list)?;
            Ok(Some((priority, list.to_vec())))
        }
    }
}

/// The offset after the target's name, which is never compressed (section
/// 2.2): labels of 63 bytes at most, to the root's zero byte.
fn skip_target(rdata: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        match *rdata.get(at).ok_or(CUT)? {
            0 => return Ok(at + 1),
            len @ 1..=63 => at += 1 + usize::from(len),
            _ => return Err("an HTTPS record's target is compressed, or no name".into()),
        }
    }
}

/// The lengths of an ECHConfigList (the ECH draft, section 4): the list's
/// own, then each ECHConfig's version and length, each within the list.
/// Each config's contents are rustls's to read.
pub fn check_list(list: &[u8]) -> Result<(), String> {
    if list.len() > MAX_LIST {
        return Err(format!("an ech parameter is larger than {MAX_LIST} bytes"));
    }
    let total = list.get(..2).ok_or(LIST_CUT)?;
    let total = usize::from(u16::from_be_bytes([total[0], total[1]]));
    if total == 0 || total != list.len() - 2 {
        return Err(LIST_CUT.into());
    }
    let mut at = 2;
    while at < list.len() {
        let fixed = list.get(at..at + 4).ok_or(LIST_CUT)?;
        let len = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
        if list.len() - (at + 4) < len {
            return Err(LIST_CUT.into());
        }
        at += 4 + len;
    }
    Ok(())
}

/// One record's `data` of the JSON form: the presentation form, `PRIORITY
/// TARGET KEY=VALUE...`, with `ech` in base64; or the generic form.
fn from_text(data: &str) -> Result<Option<(u16, Vec<u8>)>, String> {
    let data = data.trim();
    if let Some(generic) = data.strip_prefix("\\#") {
        return from_rdata(&generic_bytes(generic)?);
    }
    let tokens = tokens(data);
    let priority: u16 = tokens.first().and_then(|p| p.parse().ok()).ok_or("an HTTPS record's data has no priority")?;
    if tokens.len() < 2 {
        return Err("an HTTPS record's data has no target".into());
    }
    if priority == 0 {
        return Ok(None);
    }
    for token in &tokens[2..] {
        let (key, value) = token.split_once('=').unwrap_or((token.as_str(), ""));
        if !key.eq_ignore_ascii_case("ech") {
            continue;
        }
        let value = value.trim_matches('"');
        if value.is_empty() {
            return Ok(None);
        }
        let list = base64::engine::general_purpose::STANDARD
            .decode(value)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
            .map_err(|_| "an HTTPS record's ech is not base64".to_string())?;
        check_list(&list)?;
        return Ok(Some((priority, list)));
    }
    Ok(None)
}

/// The words of the presentation form, split at white space outside quotes.
fn tokens(data: &str) -> Vec<String> {
    let (mut out, mut word, mut quoted, mut escaped) = (Vec::new(), String::new(), false, false);
    for c in data.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_ascii_whitespace() && !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
                continue;
            }
            _ => {}
        }
        word.push(c);
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// RFC 3597's `\# LEN HEX...`: the data's bytes, as long as LEN says.
fn generic_bytes(rest: &str) -> Result<Vec<u8>, String> {
    let mut parts = rest.split_ascii_whitespace();
    let len: usize =
        parts.next().and_then(|n| n.parse().ok()).ok_or("an HTTPS record in RFC 3597's form has no length")?;
    let hex: String = parts.collect();
    let digit = |c: u8| (c as char).to_digit(16).ok_or("an HTTPS record in RFC 3597's form holds no hex");
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => Ok((digit(*high)? * 16 + digit(*low)?) as u8),
            _ => Err("an HTTPS record in RFC 3597's form has an odd count of digits"),
        })
        .collect::<Result<Vec<u8>, &str>>()?;
    if bytes.len() != len {
        return Err("an HTTPS record in RFC 3597's form is not as long as it says".into());
    }
    Ok(bytes)
}

/// The list that `name` publishes, from the [`DOH_RESOLVERS`] in turn,
/// through `proxy` when one is set, as [`super::doh_srv`] asks: `None` where
/// the first resolver that answers gives none.
pub async fn doh_https(name: &str, proxy: &ProxyChoice, deadline: Instant) -> Result<Option<Published>, String> {
    doh_https_with(DOH_RESOLVERS, name, &Trust::Default, proxy, deadline).await
}

/// [`doh_https`] over a given list of resolvers, whose certificates `trust`
/// verifies: a stand-in's, in a test.
pub async fn doh_https_with(
    resolvers: &[Doh],
    name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    deadline: Instant,
) -> Result<Option<Published>, String> {
    let name = name.trim_end_matches('.');
    if !dns_safe(name) {
        return Err(format!("{name:?} is not a name to ask a resolver for"));
    }
    let mut reasons = Vec::new();
    let mut asked: Vec<&str> = Vec::new();
    for resolver in resolvers {
        'hosts: for host in resolver.hosts(proxy, &asked) {
            asked.push(host);
            for form in resolver.forms() {
                let left = deadline.saturating_duration_since(Instant::now()).min(DOH_EACH);
                if left.is_zero() {
                    reasons.push("out of time".to_string());
                    return Err(reasons.join("; "));
                }
                match https_at(resolver, host, form, name, trust, proxy, left).await {
                    Ok(found) => return Ok(found),
                    Err(Miss::Said(e)) if e == NXDOMAIN => return Err(format!("{host}: {e}")),
                    Err(Miss::Form(e)) => reasons.push(format!("{host} ({}): {e}", form.words())),
                    Err(Miss::Way(e, _)) => {
                        reasons.push(format!("{host}: {e}"));
                        continue 'hosts;
                    }
                    Err(Miss::Said(e)) => {
                        reasons.push(format!("{host}: {e}"));
                        break 'hosts;
                    }
                }
            }
        }
    }
    Err(if reasons.is_empty() { "no resolver answered".into() } else { reasons.join("; ") })
}

/// One question for the HTTPS record of `name` in `form`, to `host`, the
/// resolver's name or address.
async fn https_at(
    resolver: &Doh,
    host: &str,
    form: Form,
    name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    left: Duration,
) -> Result<Option<Published>, Miss> {
    let target = resolver.target(form, name, "HTTPS").map_err(way)?;
    let answer = if resolver.http2 {
        let config = tls::config_for(trust).map_err(|e| way(e.to_string()))?;
        h2::get_via(&config, host, &target, form.accept(), MAX_ANSWER, proxy, left).await
    } else {
        get_plain(host, &target, form.accept(), trust, proxy, left).await
    };
    read(&answer.map_err(way)?, |body| match form {
        Form::Json => from_json(body),
        Form::Wire => from_wire(body, name),
    })
}

/// A GET of HTTP/1.1 with a plain hello: the read for a name's list is no
/// connection of `crate::ech`'s, so that it never waits on a read of its own.
async fn get_plain(
    host: &str,
    target: &str,
    accept: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    left: Duration,
) -> Result<http::Response, String> {
    let ask = async {
        let tcp = crate::dial::dial(host, 443, proxy, left).await.map_err(|e| e.to_string())?;
        let mut tls = crate::tls_wrap::tls_over(tcp, host, trust, left).await.map_err(|e| e.to_string())?;
        http::exchange(&mut tls, "GET", host, target, &[("Accept", accept)], b"", MAX_ANSWER)
            .await
            .map_err(|e| e.to_string())
    };
    tokio::time::timeout(left, ask).await.map_err(|_| format!("no answer within {} s", left.as_secs()))?
}

#[cfg(test)]
#[path = "https_tests.rs"]
mod tests;
