//! The verdicts of the probes (T-325), from what each measured: a line that
//! names the property, with its size or its time, and where it was
//! measured. A path that holds a stream is a fact that podssh works with, so
//! each verdict that measured is `ok`; one that could not tell is `????`.

use std::time::Duration;

use podssh_ws::Verdict;
use serde_json::{json, Value};

use super::http::{End, Timed};
use super::prints;

/// The most bytes that the probe of the cap sends in one body.
pub(super) const CAP_MAX: u64 = 8 << 20;
/// The first body of the probe of the cap; each next one is twice as big.
pub(super) const CAP_FIRST: u64 = 64 << 10;

/// What the server says that it does itself (`limits.probe` of its
/// `/relays.json`), so that what is met below it is the path's; for a
/// server that says nothing, podssh's own bounds.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Own {
    /// The server named its limits, as podssh's relay role does.
    pub(super) named: bool,
    pub(super) body_max: u64,
    /// The server takes a body whole before it reads it.
    pub(super) body_whole: bool,
    /// The server ends an answer that goes quiet for so long.
    pub(super) quiet_max: Option<Duration>,
    /// What stands in front of the role and is its own: a quick tunnel's node.
    pub(super) behind: Option<String>,
}

impl Own {
    /// A server that names no limits.
    pub(super) fn unnamed() -> Own {
        Own { named: false, body_max: CAP_MAX, body_whole: false, quiet_max: None, behind: None }
    }

    /// The limits of an answer of `/relays.json`, when it names them.
    pub(super) fn of(answer: &Timed) -> Own {
        let doc = match answer.head {
            Some((200, _)) => serde_json::from_slice::<Value>(&answer.body).ok(),
            _ => None,
        };
        let Some(probe) = doc.as_ref().map(|d| &d["limits"]["probe"]).filter(|p| p.is_object()) else {
            return Own::unnamed();
        };
        Own {
            named: true,
            body_max: probe["body_max_bytes"].as_u64().unwrap_or(CAP_MAX).clamp(1, CAP_MAX),
            body_whole: probe["body"] == "whole",
            quiet_max: probe["quiet_max_ms"].as_u64().map(Duration::from_millis),
            behind: probe["behind"].as_str().map(podssh_ws::text::one_line),
        }
    }
}

/// `1 MiB`, `64 KiB` or `100 bytes`.
pub(super) fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 && b % (1 << 20) == 0 => format!("{} MiB", b >> 20),
        b if b >= 1 << 10 && b % (1 << 10) == 0 => format!("{} KiB", b >> 10),
        b => format!("{b} bytes"),
    }
}

/// `2.0 s`.
pub(super) fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// The line of the server: who it is, and the limits that are its own.
pub(super) fn server_line(at: &str, own: &Own) -> String {
    if !own.named {
        return format!(
            "{at}: it answers, and its /relays.json names no limits of the probes: podssh's own bound holds, \
             bodies to {}, and go-httpbin's paths are asked as podssh's relay role serves them",
            size(own.body_max)
        );
    }
    let quiet = own.quiet_max.map(|q| format!(", and ends an answer quiet for {}", secs(q))).unwrap_or_default();
    let body = if own.body_whole { "takes a body whole" } else { "reads a body as it comes" };
    match &own.behind {
        Some(behind) => format!(
            "{at}: podssh's relay role behind {behind}, which {body}, {} at most{quiet}: these are said as its own",
            size(own.body_max)
        ),
        None => format!("{at}: podssh's relay role, which {body}, {} at most{quiet}", size(own.body_max)),
    }
}

/// Why an answer tells nothing of the probe of `path`, if it does not.
fn untold(at: &str, path: &str, answer: &Timed) -> Option<String> {
    match (&answer.head, &answer.end) {
        (None, End::Cut { at: when, why }) => Some(format!("{at}{path}: no answer, {why} after {}", secs(*when))),
        (None, _) => Some(format!("{at}{path}: no answer within the probe's bound")),
        (Some((status @ (400 | 404 | 405 | 411), reason)), _) => Some(format!(
            "{at}{path} answered {status} {reason}: the server serves no such probe (podssh relay serve does)"
        )),
        _ => None,
    }
}

/// The probe of a response: `bytes` sent over `over`, the first at once.
/// It streams when they came over most of that time, and is held when they
/// came at once.
pub(super) fn response(at: &str, over: Duration, bytes: u64, answer: &Timed) -> Verdict {
    if let Some(why) = untold(at, "/drip", answer) {
        return Verdict::Unknown { why };
    }
    let lead = format!("{at}/drip: a response of {bytes} bytes sent over {}", secs(over));
    let (first, last) = match (&answer.end, answer.body_span()) {
        (End::Whole(_), Some(span)) if answer.body_bytes() >= bytes => span,
        (End::Cut { at: when, why }, _) => {
            return Verdict::Unknown { why: format!("{lead} was cut after {} ({why})", secs(*when)) }
        }
        _ => return Verdict::Unknown { why: format!("{lead} did not come whole within the probe's bound") },
    };
    let seen = last.saturating_sub(first);
    let detail = if seen >= over.mul_f64(0.6) {
        format!(
            "{lead} came over {}, its first byte after {}: the path passes a response as it comes",
            secs(seen),
            secs(first)
        )
    } else if seen <= over.mul_f64(0.2) {
        format!("{lead} came at once, after {}: something on the path holds a response until its end", secs(last))
    } else {
        let parts = answer.reads.len();
        format!("{lead} came in {parts} reads over {}: something on the path holds a response in parts", secs(seen))
    };
    Verdict::Ok { detail }
}

/// The numbers of the probe of a response, for `--json`.
pub(super) fn response_numbers(over: Duration, answer: &Timed) -> Value {
    let span = answer.body_span();
    json!({
        "sent_ms": ms(over),
        "head_ms": answer.head_at.map(ms),
        "first_ms": span.map(|(first, _)| ms(first)),
        "last_ms": span.map(|(_, last)| ms(last)),
        "bytes": answer.body_bytes(),
        "reads": answer.reads.len(),
    })
}

/// The parts of a body as the server said they came: `(from, to)` each.
fn parts_of(answer: &Timed) -> Option<Vec<(Duration, Duration)>> {
    let doc: Value = serde_json::from_slice(&answer.body).ok()?;
    let parts = doc["parts"].as_array()?;
    let at = |p: &Value, key: &str| p[key].as_u64().map(Duration::from_millis);
    let parts: Option<Vec<_>> = parts.iter().map(|p| Some((at(p, "from_ms")?, at(p, "to_ms")?))).collect();
    parts.filter(|p| !p.is_empty())
}

/// The probe of a request's body: `pieces` sent over `over`. The server
/// says when each part came; it streams when they came over most of that
/// time, and is held when they came at once.
pub(super) fn body(at: &str, over: Duration, pieces: usize, answer: &Timed, own: &Own) -> Verdict {
    if let Some(why) = untold(at, "/anything", answer) {
        return Verdict::Unknown { why };
    }
    let lead = format!("{at}/anything: a body of {pieces} pieces sent over {}", secs(over));
    let Some(parts) = parts_of(answer).filter(|_| answer.head.as_ref().is_some_and(|(s, _)| *s == 200)) else {
        let status = answer.head.as_ref().map(|(s, r)| format!("{s} {r}")).unwrap_or_default();
        return Verdict::Unknown {
            why: format!(
                "{lead}: the answer ({status}) says not when each part came (go-httpbin's /anything echoes the \
                 body; podssh's relay role says each part's time)"
            ),
        };
    };
    let (from, to) = (parts[0].0, parts[parts.len() - 1].1);
    let seen = to.saturating_sub(from);
    let detail = if seen >= over.mul_f64(0.6) {
        format!("{lead} came to the server over {}: the path passes a request's body as it comes", secs(seen))
    } else if seen <= over.mul_f64(0.2) && own.body_whole {
        let who = own.behind.as_deref().unwrap_or("the server");
        format!("{lead} came to the server at once: {who} takes a body whole, so the path's own way is not seen here")
    } else if seen <= over.mul_f64(0.2) {
        format!(
            "{lead} came to the server at once, {} after its head: something on the path holds a request's body \
             until its end",
            secs(from)
        )
    } else {
        let n = parts.len();
        format!("{lead} came to the server in {n} parts over {}: something on the path passes it in parts", secs(seen))
    };
    Verdict::Ok { detail }
}

/// What the server, and the path to it, did with one body of the cap's.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Outcome {
    Passed,
    Refused { status: u16, reason: String },
    /// The connection ended, or failed, with no answer.
    Cut(String),
    /// No answer within the probe's bound.
    Waited,
}

/// The sizes of the probe of the cap: from [`CAP_FIRST`], twice as big each
/// time, to `max`, which is the last.
pub(super) fn sizes(max: u64) -> Vec<u64> {
    let mut sizes = Vec::new();
    let mut next = CAP_FIRST;
    while next < max {
        sizes.push(next);
        next *= 2;
    }
    sizes.push(max);
    sizes
}

/// The outcome of one body of the cap's, by its answer.
pub(super) fn outcome(answer: &Timed) -> Outcome {
    match (&answer.head, &answer.end) {
        (Some((200..=299, _)), _) => Outcome::Passed,
        (Some((status, reason)), _) => Outcome::Refused { status: *status, reason: reason.clone() },
        (None, End::Cut { why, .. }) => Outcome::Cut(why.clone()),
        (None, _) => Outcome::Waited,
    }
}

/// The probe of the cap, from the outcome of each body that it sent, in
/// order: the last that passed and the first that did not.
pub(super) fn cap(at: &str, steps: &[(u64, Outcome)], own: &Own) -> Verdict {
    let passed = steps.iter().take_while(|(_, o)| *o == Outcome::Passed).last().map(|(size, _)| *size);
    let first = steps.first().map_or(CAP_FIRST, |(size, _)| *size);
    let took = passed.map(|p| format!("a body of {} passed, and ", size(p))).unwrap_or_default();
    // A server that names no limits may refuse a body itself.
    let who = match own.named {
        true => "something on the path",
        false => "something on the path, or the server, which names no limits,",
    };
    let detail = match steps.iter().find(|(_, o)| *o != Outcome::Passed) {
        None => {
            let last = passed.unwrap_or(first);
            let whose = match (own.named, &own.behind) {
                (true, Some(behind)) => format!(", the cap of {behind} in front of the server"),
                (true, None) => ", the server's own cap".to_string(),
                (false, _) => ", the most that this probe sends".to_string(),
            };
            format!(
                "{at}/anything: each body from {} to {} passed{whose}: nothing on the path refuses a body of up to {}",
                size(first),
                size(last),
                size(last)
            )
        }
        Some((refused, Outcome::Refused { status, reason })) => {
            let looks = prints::looks_like(&prints::cap(passed, *refused, *status));
            format!(
                "{at}/anything: {took}one of {} got {status} {reason}: {who} refuses a body of {}{looks}",
                size(*refused),
                size(*refused)
            )
        }
        Some((refused, Outcome::Cut(why))) => format!(
            "{at}/anything: {took}one of {} was cut with no answer ({why}): {who} ends a body of {}",
            size(*refused),
            size(*refused)
        ),
        Some((refused, _)) => {
            return Verdict::Unknown {
                why: format!(
                    "{at}/anything: {took}one of {} had no answer within the probe's bound: the path is too slow \
                     for this probe to tell its cap",
                    size(*refused)
                ),
            }
        }
    };
    Verdict::Ok { detail }
}

/// The numbers of the probe of the cap, for `--json`.
pub(super) fn cap_numbers(steps: &[(u64, Outcome)]) -> Value {
    let passed = steps.iter().take_while(|(_, o)| *o == Outcome::Passed).last().map(|(size, _)| *size);
    let refused = steps.iter().find(|(_, o)| *o != Outcome::Passed);
    let status = match refused {
        Some((_, Outcome::Refused { status, .. })) => Some(*status),
        _ => None,
    };
    json!({ "passed_bytes": passed, "refused_bytes": refused.map(|(size, _)| *size), "status": status })
}

/// The probe of a quiet stream: a response whose first byte comes at once
/// and its second `hold` later. It ends whole when nothing on the path ends
/// a stream quiet for so long.
pub(super) fn quiet(at: &str, hold: Duration, answer: &Timed, own: &Own) -> Verdict {
    let lead = format!("{at}/drip: a response quiet for {} after its first byte", secs(hold));
    let after = answer.body_span().map_or(answer.head_at.unwrap_or_default(), |(first, _)| first);
    let detail = match (&answer.head, &answer.end) {
        (Some((200, _)), End::Whole(end)) if answer.body_bytes() >= 2 => {
            format!("{lead} came whole after {}: nothing on the path ends a stream quiet for that long", secs(*end))
        }
        (Some((200, _)), End::Cut { at: when, why }) => {
            let quiet = when.saturating_sub(after);
            let who = ender(quiet, None, own);
            format!("{lead} ended {} after it, with no end of its body ({why}): {who}", secs(quiet))
        }
        (Some((status @ (408 | 502 | 503 | 504 | 520..=524), reason)), _) => {
            let when = answer.head_at.unwrap_or_default();
            format!(
                "{at}/drip: the path answered {status} {reason} after {}, in place of the server's response: {}",
                secs(when),
                ender(when, Some(*status), own)
            )
        }
        (None, End::Cut { at: when, why }) => format!(
            "{at}/drip: the connection ended after {} with no answer ({why}): {}",
            secs(*when),
            ender(*when, None, own)
        ),
        _ => {
            let why = untold(at, "/drip", answer)
                .unwrap_or_else(|| format!("{lead}: no end within the probe's bound of {}", secs(hold)));
            return Verdict::Unknown { why };
        }
    };
    Verdict::Ok { detail }
}

/// Who ends a stream quiet for `quiet`: the server itself, when it says that
/// it ends one so, else something on the path, with what it looks like.
fn ender(quiet: Duration, status: Option<u16>, own: &Own) -> String {
    let near = |limit: Duration| ms(quiet).abs_diff(ms(limit)) <= 2_000;
    match (own.quiet_max.filter(|q| near(*q)), &own.behind) {
        (Some(_), Some(behind)) => {
            format!("{behind} in front of the server ends an answer quiet so long, its own limit")
        }
        (Some(_), None) => "the server ends an answer quiet so long, its own limit".to_string(),
        (None, _) => format!(
            "something on the path ends a stream quiet for about {}{}",
            secs(quiet),
            prints::looks_like(&prints::quiet(quiet, status))
        ),
    }
}

/// The numbers of the probe of a quiet stream, for `--json`.
pub(super) fn quiet_numbers(hold: Duration, answer: &Timed) -> Value {
    let ended = match &answer.end {
        End::Cut { at, .. } => Some(ms(*at)),
        _ => None,
    };
    json!({ "hold_ms": ms(hold), "ended_ms": ended, "status": answer.head.as_ref().map(|(s, _)| *s) })
}

/// How the quiet socket of the default relay ended: `None` when it held,
/// else when and how; `Err` when it could not be opened.
pub(super) type SocketEnd = Result<Option<(Duration, String)>, String>;

/// The quiet socket of the default relay's reverse road, held `hold` after
/// its hello: `ended` when it ended first, and how.
pub(super) fn socket(at: &str, hold: Duration, ended: &SocketEnd) -> Verdict {
    let lead = format!("a socket of the reverse road at {at}, quiet after the relay's hello");
    let detail = match ended {
        Ok(None) => format!("{lead}, stayed open {}: nothing on the path ends a quiet stream that soon", secs(hold)),
        Ok(Some((when, why))) => format!(
            "{lead}, ended after {} ({why}): something on the path ends a quiet stream after about {}{}, or the \
             relay dropped it, as it has dropped a node's socket with no Close before; a second run tells them apart",
            secs(*when),
            secs(*when),
            prints::looks_like(&prints::quiet(*when, None))
        ),
        Err(why) => return Verdict::Unknown { why: format!("{lead}: {why}") },
    };
    Verdict::Ok { detail }
}

/// The numbers of the quiet socket, for `--json`.
pub(super) fn socket_numbers(hold: Duration, ended: &SocketEnd) -> Value {
    let ended = match ended {
        Ok(Some((at, _))) => Some(ms(*at)),
        _ => None,
    };
    json!({ "hold_ms": ms(hold), "ended_ms": ended, "status": Value::Null })
}

#[cfg(test)]
#[path = "judge_tests.rs"]
mod tests;
