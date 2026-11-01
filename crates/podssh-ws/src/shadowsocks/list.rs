//! A subscription's list, as a provider serves it at its URL: lines of
//! `ss://` URIs, the same lines in base64 (as most lists are served), or
//! SIP008's JSON (`{"version":1,"servers":[...]}`). Lines of other schemes
//! (`vmess://`, `trojan://`) are counted and passed over, as podssh speaks
//! none of them; an `ss://` line that cannot go is refused with its number,
//! never its text.

use super::uri::{base64_bytes, plugin_name, plugin_refusal, tag_of};
use super::{Method, Node};

/// The nodes of a list, in its order, each once; why each other `ss://`
/// line or server was refused; and how many lines of other schemes it had.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listed {
    pub nodes: Vec<Node>,
    pub refused: Vec<String>,
    pub others: usize,
}

impl Listed {
    /// A node, once: the same server and key under two tags is one.
    fn add(&mut self, node: Node) {
        if !self.nodes.iter().any(|kept| kept.same_server(&node)) {
            self.nodes.push(node);
        }
    }
}

/// The list in `body`, in whichever of the three forms it comes.
pub fn subscription(body: &[u8]) -> Result<Listed, String> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err("the list is empty".into());
    }
    if text.starts_with('{') {
        return sip008(text);
    }
    if text.contains("://") {
        return Ok(lines(text));
    }
    let form = "the list is neither lines of ss://, nor base64 of them, nor SIP008's JSON";
    let decoded = base64_bytes(text).ok_or(form)?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| form.to_string())?;
    if !decoded.contains("://") {
        return Err(form.into());
    }
    Ok(lines(decoded))
}

fn lines(text: &str) -> Listed {
    let mut listed = Listed::default();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.get(..5).is_some_and(|scheme| scheme.eq_ignore_ascii_case("ss://")) {
            listed.others += 1;
            continue;
        }
        match Node::parse(line) {
            Ok(node) => listed.add(node),
            Err(why) => listed.refused.push(format!("line {}: {why}", i + 1)),
        }
    }
    listed
}

/// SIP008: each server's `server`, `server_port`, `method` and `password`,
/// its `remarks` as its tag; one with a `plugin` is refused.
fn sip008(text: &str) -> Result<Listed, String> {
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "the list starts with { and is not JSON".to_string())?;
    let servers =
        doc.get("servers").and_then(|s| s.as_array()).ok_or("the list's JSON has no servers, as SIP008 gives them")?;
    let mut listed = Listed::default();
    for (i, server) in servers.iter().enumerate() {
        match sip008_node(server) {
            Ok(node) => listed.add(node),
            Err(why) => listed.refused.push(format!("server {}: {why}", i + 1)),
        }
    }
    Ok(listed)
}

fn sip008_node(server: &serde_json::Value) -> Result<Node, String> {
    let text = |key: &str| server.get(key).and_then(|v| v.as_str());
    if let Some(plugin) = text("plugin").filter(|p| !p.trim().is_empty()) {
        return Err(plugin_refusal(&plugin_name(plugin)));
    }
    let method = Method::parse(text("method").ok_or("it has no method")?)?;
    let password = text("password").ok_or("it has no password")?;
    let host = text("server").ok_or("it has no server")?;
    let port = server.get("server_port").and_then(|p| p.as_u64()).and_then(|p| u16::try_from(p).ok());
    let mut node = Node::new(method, password, host, port.ok_or("it has no server_port")?)?;
    node.tag = text("remarks").map(tag_of).filter(|t| !t.is_empty());
    Ok(node)
}
