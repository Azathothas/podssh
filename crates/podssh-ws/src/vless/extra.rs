//! The `extra` of an XHTTP link: JSON of Xray-core's `xhttpSettings`. The
//! keys that podssh follows are taken, the ones that only pace or pool
//! Xray-core's own client or tune the server are passed over, and each other
//! key (a placement of the padding, the session or the data, another method,
//! separate downloads) is refused by its name unless it holds its default, as
//! the server would wait for bytes where podssh does not put them.

use serde_json::Value;

use super::link::Mode;

/// The default range of the padding's length (`xpadding.go`,
/// `GetNormalizedXPaddingBytes`), which the server also accepts.
pub const PADDING: (u32, u32) = (100, 1000);
/// The default largest POST of packet-up (`config.go`,
/// `GetNormalizedScMaxEachPostBytes`).
pub const MAX_POST: usize = 1_000_000;

/// The keys that change nothing that podssh sends.
const PASSED_OVER: &[&str] = &[
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
    "xmux",
    "noSSEHeader",
    "serverMaxHeaderBytes",
];

/// What podssh takes from `extra`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extra {
    /// Headers that each request carries.
    pub headers: Vec<(String, String)>,
    /// The range of the padding's length.
    pub padding: (u32, u32),
    /// No `Content-Type: application/grpc` on a streamed upload.
    pub no_grpc_header: bool,
    /// The largest body of one POST of packet-up.
    pub max_post: usize,
    /// A mode that `extra` names.
    pub mode: Option<Mode>,
}

impl Default for Extra {
    fn default() -> Extra {
        Extra { headers: Vec::new(), padding: PADDING, no_grpc_header: false, max_post: MAX_POST, mode: None }
    }
}

impl Extra {
    pub fn parse(json: &str) -> Result<Extra, String> {
        let doc: Value = serde_json::from_str(json).map_err(|_| "extra is not JSON".to_string())?;
        let Value::Object(map) = doc else { return Err("extra is not a JSON object".into()) };
        let mut extra = Extra::default();
        for (key, value) in &map {
            match key.as_str() {
                "headers" => extra.headers = headers(value)?,
                "xPaddingBytes" => extra.padding = range(value).ok_or("extra's xPaddingBytes is no range")?,
                "noGRPCHeader" => extra.no_grpc_header = value.as_bool().unwrap_or(false),
                "scMaxEachPostBytes" => {
                    // The lower bound: the server refuses a POST above its own.
                    let (from, _) = range(value).ok_or("extra's scMaxEachPostBytes is no range")?;
                    extra.max_post = (from as usize).clamp(1024, MAX_POST * 16);
                }
                "mode" => extra.mode = value.as_str().map(super::link::mode_of).transpose()?,
                "host" | "path" => {}
                passed if PASSED_OVER.contains(&passed) => {}
                other if is_default(other, value) => {}
                other => return Err(format!("extra's {other} is not followed: podssh speaks XHTTP's defaults there")),
            }
        }
        if extra.padding.0 == 0 || extra.padding.0 > extra.padding.1 || extra.padding.1 > 8000 {
            return Err("extra's xPaddingBytes is no range of 1 to 8000".into());
        }
        Ok(extra)
    }
}

/// A key whose value is its default: false, empty, or the default word.
fn is_default(key: &str, value: &Value) -> bool {
    let word = value.as_str().map(str::to_ascii_lowercase);
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::String(s) if s.is_empty() => true,
        _ => match key {
            "sessionPlacement" | "seqPlacement" => word.as_deref() == Some("path"),
            "uplinkDataPlacement" => word.as_deref() == Some("body"),
            "uplinkHTTPMethod" => word.as_deref() == Some("post"),
            _ => false,
        },
    }
}

/// Xray-core's range: a number, `"A-B"`, `"A"`, or `{"from":A,"to":B}`.
fn range(value: &Value) -> Option<(u32, u32)> {
    let num = |v: &Value| v.as_u64().and_then(|n| u32::try_from(n).ok());
    match value {
        Value::Number(_) => num(value).map(|n| (n, n)),
        Value::String(s) => {
            let (a, b) = s.split_once('-').unwrap_or((s, s));
            Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
        }
        Value::Object(o) => Some((num(o.get("from")?)?, num(o.get("to")?)?)),
        _ => None,
    }
}

/// Header names of a token's characters, values with no control character,
/// and never `Host`, which the link's `host` gives.
fn headers(value: &Value) -> Result<Vec<(String, String)>, String> {
    let Value::Object(map) = value else { return Err("extra's headers is not a JSON object".into()) };
    let mut out = Vec::new();
    for (name, value) in map {
        let value = value.as_str().ok_or("a header of extra is not a string")?;
        let token = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b));
        if !token || value.chars().any(char::is_control) {
            return Err("a header of extra has a name or a value that a request cannot carry".into());
        }
        if !name.eq_ignore_ascii_case("host") {
            out.push((name.clone(), value.to_string()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keys_that_podssh_follows_are_taken_and_the_others_named() {
        let extra = Extra::parse(
            r#"{"headers":{"X-Key":"v"},"xPaddingBytes":"200-300","noGRPCHeader":true,
                "scMaxEachPostBytes":{"from":500000,"to":800000},"xmux":{"maxConcurrency":"16-32"},
                "mode":"stream-one","xPaddingObfsMode":false,"sessionPlacement":"path"}"#,
        )
        .unwrap();
        assert_eq!(extra.headers, vec![("X-Key".to_string(), "v".to_string())]);
        assert_eq!((extra.padding, extra.no_grpc_header, extra.max_post), ((200, 300), true, 500_000));
        assert_eq!(extra.mode, Some(Mode::StreamOne));
        assert_eq!(Extra::parse("{}").unwrap(), Extra::default());
        for (json, word) in [
            (r#"{"xPaddingObfsMode":true}"#, "xPaddingObfsMode"),
            (r#"{"uplinkDataPlacement":"header"}"#, "uplinkDataPlacement"),
            (r#"{"downloadSettings":{"address":"x"}}"#, "downloadSettings"),
        ] {
            let why = Extra::parse(json).unwrap_err();
            assert!(why.contains(word) && why.contains("not followed"), "{why}");
        }
        assert!(Extra::parse("[1]").is_err());
        assert!(Extra::parse(r#"{"xPaddingBytes":"9-1"}"#).is_err());
        assert!(Extra::parse(r#"{"headers":{"X":"a\r\nb"}}"#).is_err());
        assert_eq!(range(&serde_json::json!(64)), Some((64, 64)));
    }
}
