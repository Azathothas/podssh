//! What a proxy's `407` asks for (T-320). RFC 9110, section 11.7.1: the
//! answer carries `Proxy-Authenticate` with each scheme that the proxy takes.
//! podssh sends Basic only, from the user and password of the proxy URL, as
//! Go, wget, requests and reqwest do; an NTLM or Negotiate proxy refuses it,
//! and the message must say why rather than only that it refused.

/// The schemes of each `Proxy-Authenticate` of a response head, in order,
/// each once. A header can hold more than one challenge, apart at commas,
/// with parameters after a scheme (`Basic realm="corp", NTLM`): a part is a
/// scheme when its first word is a token with no `=` after it.
pub(crate) fn schemes(head: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("proxy-authenticate") {
            continue;
        }
        for part in outside_quotes(value) {
            let part = part.trim_start();
            let word = part.split([' ', '=']).next().unwrap_or("");
            let is_token =
                !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c));
            let is_param = part[word.len()..].trim_start().starts_with('=');
            if is_token && !is_param && !found.iter().any(|s| s.eq_ignore_ascii_case(word)) && found.len() < 8 {
                found.push(word.to_string());
            }
        }
    }
    found
}

/// The parts of a header's value apart at commas that are not inside a
/// quoted string: `realm="a, b"` stays one part.
fn outside_quotes(value: &str) -> Vec<&str> {
    let (mut parts, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// The reason of a `407`, with what the proxy asks for and what podssh can
/// give: `sent_basic` is whether the URL's user and password went with it.
pub(crate) fn explain(reason: &str, head: &str, sent_basic: bool) -> String {
    let asks = schemes(head);
    if asks.is_empty() {
        return reason.to_string();
    }
    let list = match asks.as_slice() {
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => unreachable!(),
    };
    let takes_basic = asks.iter().any(|s| s.eq_ignore_ascii_case("basic"));
    let what = match (takes_basic, sent_basic) {
        (true, true) => "and refused the user and password of the proxy URL (Basic)".to_string(),
        (true, false) => {
            "and podssh sent none: put them in the proxy URL, http://USER:PASSWORD@HOST:PORT (Basic)".to_string()
        }
        (false, _) => "and podssh sends Basic only, from the user and password of the proxy URL".to_string(),
    };
    format!("{reason}; it asks for {list}, {what}")
}
