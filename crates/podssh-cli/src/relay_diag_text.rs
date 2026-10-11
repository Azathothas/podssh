//! The lines of `podssh relay info` and `trace` (T-058), from the relay's
//! JSON. A field that the relay leaves out is left out of its line, so a
//! relay with other fields still gives what it has. Each text from the relay
//! is cleaned to one line first: a target's banner comes from anywhere.

use podssh_ws::dial::authority;
use serde_json::Value;

fn text(v: &Value) -> Option<String> {
    v.as_str().map(podssh_ws::text::one_line).filter(|s| !s.is_empty())
}

/// Milliseconds in the largest unit that divides them: `12 h`, `3 min`.
fn duration(ms: u64) -> String {
    match ms {
        0 => "0 s".into(),
        ms if ms % 3_600_000 == 0 => format!("{} h", ms / 3_600_000),
        ms if ms % 60_000 == 0 => format!("{} min", ms / 60_000),
        ms if ms % 1000 == 0 => format!("{} s", ms / 1000),
        ms => format!("{ms} ms"),
    }
}

/// Bytes in the largest unit that divides them: `64 MiB`, `256 KiB`.
fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 && b % (1 << 20) == 0 => format!("{} MiB", b >> 20),
        b if b >= 1 << 10 && b % (1 << 10) == 0 => format!("{} KiB", b >> 10),
        b => format!("{b} bytes"),
    }
}

/// The relay and its edge, the URL for the target when one was given, the
/// pool best first, the limits and the relay's note.
pub fn info_lines(host: &str, doc: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let service = text(&doc["service"]).unwrap_or_else(|| "(no service)".into());
    let version = text(&doc["version"]).unwrap_or_else(|| "(no version)".into());
    let mut first = format!("relay {host}: {service} {version}");
    if let Some(edge) = text(&doc["you"]["edge_colo"]) {
        first.push_str(&format!("; this host reaches it at edge {edge}"));
        if let Some(bucket) = text(&doc["you"]["bucket"]) {
            first.push_str(&format!(" (bucket {bucket})"));
        }
    }
    lines.push(first);
    let target = &doc["target"];
    let port = target["port"].as_u64().and_then(|p| u16::try_from(p).ok());
    if let (Some(name), Some(port)) = (text(&target["host"]), port) {
        let connect = text(&doc["connect"]).unwrap_or_else(|| "(no URL)".into());
        lines.push(format!("for {}: {connect}", authority(&name, port)));
    }
    if let Some(pool) = doc["pool"].as_array() {
        lines.push(format!("pool, best first: {} hosts", pool.len()));
        for entry in pool {
            let rank = entry["rank"].as_u64().map(|r| r.to_string()).unwrap_or_else(|| "-".into());
            let name = text(&entry["name"]).unwrap_or_else(|| "-".into());
            let at = text(&entry["host"]).unwrap_or_else(|| "-".into());
            let region = text(&entry["region"]).unwrap_or_else(|| "-".into());
            let score = entry["score_ms"].as_u64().map(|v| format!("{v} ms")).unwrap_or_else(|| "-".into());
            lines.push(format!("  {rank:>3}  {name:<24} {at:<42} {region:<26} {score}"));
        }
    }
    let limits = &doc["limits"];
    let mut parts = Vec::new();
    for (key, label) in
        [("connect_timeout_ms", "connect"), ("idle_timeout_ms", "idle"), ("max_session_ms", "a session")]
    {
        if let Some(ms) = limits[key].as_u64() {
            parts.push(format!("{label} {}", duration(ms)));
        }
    }
    for (key, label) in [("max_session_bytes", "a session"), ("max_frame_bytes", "a frame")] {
        if let Some(bytes) = limits[key].as_u64() {
            parts.push(format!("{label} {}", size(bytes)));
        }
    }
    for (key, label) in [("udp", "UDP"), ("inbound_tcp", "inbound TCP"), ("port_25", "port 25")] {
        if let Some(value) = text(&limits[key]) {
            parts.push(format!("{label} {value}"));
        }
    }
    if !parts.is_empty() {
        lines.push(format!("limits: {}", parts.join(", ")));
    }
    if let Some(note) = text(&doc["policy"]["note"]) {
        lines.push(format!("note: {note}"));
    }
    lines
}

/// The verdict on the target with what the relay saw, and its banner.
pub fn trace_lines(host: &str, wanted: &str, doc: &Value) -> Vec<String> {
    let found = &doc["target"];
    let about = match (text(&doc["relay"]["version"]), text(&doc["request"]["edge_colo"])) {
        (Some(version), Some(edge)) => format!(" ({version}, edge {edge})"),
        (Some(version), None) => format!(" ({version})"),
        (None, Some(edge)) => format!(" (edge {edge})"),
        (None, None) => String::new(),
    };
    let head = format!("trace {wanted} through {host}{about}");
    if let Some(error) = text(&found["error"]) {
        return vec![format!("{head}: the relay did not dial it: {error}")];
    }
    if !found.is_object() {
        return vec![format!("{head}: the relay's answer has no target")];
    }
    let mut facts = Vec::new();
    if let Some(road) = text(&found["road"]) {
        facts.push(format!("road {road}"));
    }
    if let Some(dialed) = text(&found["dialed"]) {
        let family = text(&found["address_family"]).or_else(|| found["address_family"].as_u64().map(|f| f.to_string()));
        facts.push(match family {
            Some(family) => format!("dialed {dialed} (IPv{family})"),
            None => format!("dialed {dialed}"),
        });
    }
    if let Some(ms) = found["connect_ms"].as_u64() {
        facts.push(format!("connect {ms} ms"));
    }
    if let Some(ms) = found["first_byte_ms"].as_u64() {
        facts.push(format!("first byte {ms} ms"));
    }
    if let Some(bytes) = found["bytes_seen"].as_u64() {
        facts.push(format!("{bytes} bytes seen"));
    }
    let verdict = text(&found["verdict"]).unwrap_or_else(|| "(no verdict)".into());
    let mut lines = vec![match facts.is_empty() {
        true => format!("{head}: {verdict}"),
        false => format!("{head}: {verdict}; {}", facts.join(", ")),
    }];
    if let Some(banner) = text(&found["banner"]) {
        lines.push(format!("banner: {banner}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn units_are_the_largest_that_divide() {
        assert_eq!(duration(43_200_000), "12 h");
        assert_eq!(duration(180_000), "3 min");
        assert_eq!(duration(10_000), "10 s");
        assert_eq!(duration(1500), "1500 ms");
        assert_eq!(size(67_108_864), "64 MiB");
        assert_eq!(size(262_144), "256 KiB");
        assert_eq!(size(1000), "1000 bytes");
    }

    /// The shape that the live relay answered on 2026-10-11, with the caller's
    /// fields left out.
    #[test]
    fn a_trace_names_the_verdict_and_cleans_the_banner() {
        let doc = json!({
            "relay": { "version": "2026-10-03-r2" }, "request": { "edge_colo": "KTM" },
            "target": { "host": "github.com", "port": 22, "ok": true, "road": "vpc", "dialed": "192.0.2.7",
                "address_family": "4", "connect_ms": 4, "first_byte_ms": 648, "bytes_seen": 17, "verdict": "live",
                "banner": "SSH-2.0-x\u{1b}[31m" },
        });
        let lines = trace_lines("relay.example", "github.com:22", &doc);
        assert_eq!(
            lines[0],
            "trace github.com:22 through relay.example (2026-10-03-r2, edge KTM): live; road vpc, dialed 192.0.2.7 \
             (IPv4), connect 4 ms, first byte 648 ms, 17 bytes seen"
        );
        assert_eq!(lines[1], "banner: SSH-2.0-x[31m", "the escape byte is dropped");
        let refused = json!({ "target": { "error": "10.0.0.1 is in a blocked address range" } });
        let lines = trace_lines("relay.example", "10.0.0.1:22", &refused);
        assert_eq!(lines, ["trace 10.0.0.1:22 through relay.example: the relay did not dial it: 10.0.0.1 is in a blocked address range"]);
    }
}
