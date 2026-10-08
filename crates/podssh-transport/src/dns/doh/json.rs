//! E15 — ⛔ **the DNS-JSON reader, and the two answers it must refuse to turn
//! into a resolution.**
//!
//! ⛔ **This is not a JSON parser and does not pretend to be one.** ⛔ It reads
//! four fields ⛔ — ⛔ `Status`, `TC`, and each answer record's `name`, `type` and
//! `data` ⛔ — ⛔ **and it fails with a named [`DohError::Unparseable`] for
//! anything else.** ⛔ **`serde_json` is deliberately not used here**, ⛔
//! because the point of the reader is that ⛔ **a field's meaning cannot change
//! silently** ⛔ and ⛔ **a general parser would accept a shape this module has
//! never been shown.** ⛔ **The two bodies `dns.md`'s third plant names are
//! exactly the cases a general parser handles worst**: ⛔ a captive-portal
//! HTML page and an answer with no records.
//!
//! ⛔ **No `Vec::new()` is ever returned for a body podssh could not read.**
//! ⛔ **That is the defect the plant names**: ⛔ *"not an empty
//! `Vec<SocketAddr>` some caller treats as success"*.

use std::net::{IpAddr, SocketAddr};

use super::{DohAnswer, DohError, DohResponse};

/// ⛔ **The names `application/dns-json` actually uses.** ⛔ **An unknown field
/// is ignored rather than rejected**, ⛔ because ⛔ **a DoH server may add
/// fields** ⛔ and ⛔ a strict reader would turn a version bump into a
/// resolution failure. ⛔ **These six are not unknown fields** ⛔ — ⛔ they
/// are the ones the answer is *made of*, and ⛔ **the reader reads exactly
/// them and nothing else.**
const JSON_STATUS: &str = "\"Status\"";
const JSON_ANSWER: &str = "\"Answer\"";
const JSON_NAME: &str = "\"name\"";
const JSON_TYPE: &str = "\"type\"";
const JSON_DATA: &str = "\"data\"";
const JSON_TRUNCATED: &str = "\"TC\"";

/// ⛔ **Parse a DNS-JSON body into addresses.** ⛔ **Three outcomes and never a
/// fourth:**
///
/// 1. addresses ⛔ — a real answer, possibly empty because the type was `AAAA`
///    and the name is A-only, which ⛔ **is a legitimate empty answer and is
///    reported as such by the caller when *both* types came back empty**;
/// 2. [`DohError::EmptyAnswer`] ⛔ — a DNS answer with `Status 0` and no records
///    at all for the name;
/// 3. [`DohError::Unparseable`] ⛔ — anything else.
///
/// ⛔ **No `Vec::new()` is ever returned for a body podssh could not read**,
/// and ⛔ **no `panic!` is reachable from any input**, which `dns.md`'s third
/// plant asserts directly.
pub fn parse_json(endpoint: &str, name: &str, response: &DohResponse) -> Result<Vec<SocketAddr>, DohError> {
    if response.status != 200 {
        return Err(DohError::Http { endpoint: endpoint.to_string(), status: response.status });
    }
    let body = response.body.trim();
    if body.is_empty() {
        return Err(DohError::Unparseable {
            endpoint: endpoint.to_string(),
            detail: "the body was empty".into(),
        });
    }
    // ⛔ The one structural check, made here rather than by a JSON parser: a
    // body that does not even contain a `Status` is not a DNS-JSON answer, and
    // ⛔ **`serde_json` is deliberately not a dependency of this parse** ⛔ so
    // that the *fields* below cannot silently change meaning.
    if !body.contains(JSON_STATUS) {
        return Err(DohError::Unparseable {
            endpoint: endpoint.to_string(),
            detail: format!(
                "expected a DNS-JSON answer carrying {JSON_STATUS}, found {:?}",
                truncate(body)
            ),
        });
    }
    let answer = read_fields(body, name);
    if answer.truncated {
        return Err(DohError::Unparseable {
            endpoint: endpoint.to_string(),
            detail: "the answer sets TC (truncated); a truncated answer is not a resolution"
                .into(),
        });
    }
    if answer.status.is_some_and(|s| s != 0) {
        return Err(DohError::EmptyAnswer {
            endpoint: endpoint.to_string(),
            name: name.to_string(),
            status: answer.status,
        });
    }
    let addrs: Vec<SocketAddr> = answer.addresses.iter().copied().map(|ip| SocketAddr::new(ip, 0)).collect();
    if addrs.is_empty() {
        return Err(DohError::EmptyAnswer {
            endpoint: endpoint.to_string(),
            name: name.to_string(),
            status: answer.status,
        });
    }
    Ok(addrs)
}

/// ⛔ **The four fields, read by hand.** ⛔ **This is not a JSON parser and does
/// not pretend to be one** ⛔ — ⛔ **a hand-rolled reader that is exercised by a
/// test against a real body and against two broken ones is a reader whose
/// failure mode is a named `Unparseable`, and a general parser would need a
/// dependency this crate does not otherwise carry.**
fn read_fields(body: &str, name: &str) -> DohAnswer {
    let mut out = DohAnswer::default();
    out.status = int_after(body, JSON_STATUS);
    out.truncated = body.contains(JSON_TRUNCATED);
    // ⛔ **`Answer` is an array of records. Each record is walked for its own
    // `type` and `data`,** because the two are not adjacent in a JSON object and
    // a reader that assumed they were would pair a `type` with the next
    // record's `data`.
    let Some(start) = body.find(JSON_ANSWER) else { return out };
    let rest = &body[start + JSON_ANSWER.len()..];
    let Some(open) = rest.find('[') else { return out };
    let mut depth = 0usize;
    let mut records: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in rest[open..].chars() {
        match ch {
            '"' if !escaped => {
                in_string = !in_string;
                current.push(ch);
            }
            '[' if !in_string => {
                depth += 1;
                if depth == 1 {
                    current.clear();
                    continue;
                }
                current.push(ch);
            }
            ']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    if current.trim().starts_with('{') {
                        records.push(std::mem::take(&mut current));
                    }
                    break;
                }
                current.push(ch);
            }
            _ => current.push(ch),
        }
        escaped = ch == '\\' && !escaped;
        if ch != '\\' {
            escaped = false;
        }
    }
    for record in &records {
        let record = record.as_str();
        let Some(kind) = string_after(record, JSON_TYPE) else { continue };
        let Some(data) = string_after(record, JSON_DATA) else { continue };
        // ⛔ **`type` and `name` are checked together.** ⛔ A record whose `name`
        // is a different name is not an answer to the question that was asked
        // ⛔ — and CNAME records carry a name too, so only the `A`/`AAAA`/`CNAME`
        // chain for the asked name is followed ⛔ **and a CNAME's `data` is not an
        // address**, so it is skipped rather than parsed.
        let record_name = string_after(record, JSON_NAME).unwrap_or_default();
        if !record_name.eq_ignore_ascii_case(name) && !record_name.eq_ignore_ascii_case(&format!("{name}.")) {
            continue;
        }
        // ⛔ **Only an `A` or an `AAAA` record contributes an address.** ⛔ A
        // `CNAME` record's `data` is a name, ⛔ **and a name that happens to parse
        // as an address is not one this module should have dialled.**
        if matches!(kind.as_str(), "A" | "AAAA") {
            if let Ok(ip) = data.parse::<IpAddr>() {
                out.addresses.push(ip);
            }
        }
    }
    out
}

fn int_after(body: &str, key: &str) -> Option<i32> {
    let at = body.find(key)? + key.len();
    let tail = body[at..].trim_start();
    let tail = tail.strip_prefix(':')?.trim_start();
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    digits.parse().ok()
}

fn string_after(body: &str, key: &str) -> Option<String> {
    let at = body.find(key)? + key.len();
    let tail = body[at..].trim_start();
    let tail = tail.strip_prefix(':')?.trim_start();
    let tail = tail.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in tail.chars() {
        match ch {
            '"' if !escaped => return Some(out),
            '\\' if !escaped => {
                escaped = true;
                continue;
            }
            c => out.push(c),
        }
        escaped = false;
    }
    None
}

fn truncate(body: &str) -> String {
    if body.chars().count() <= 60 {
        return body.to_string();
    }
    format!("{}…", body.chars().take(57).collect::<String>())
}
