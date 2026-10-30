//! mRemoteNG's connections (T-327): the XML of `confCons.xml`, or of an
//! export of it. Each `Node` of `Type="Connection"` is a session, in the
//! folders of the `Container` nodes above it; `Protocol="SSH2"` makes a
//! block, SSH1 and each other protocol a comment. A field that a node
//! inherits (`InheritUsername="True"`) comes from the nearest container
//! above it that has its own, as mRemoteNG takes it. `SSHTunnelConnectionName`
//! names the connection that a session goes through: its `ProxyJump`. Each
//! password is encrypted with the user's master password: each is counted,
//! never decrypted. A file encrypted whole (`FullFileEncryption`) is refused
//! by name, as nothing of it reads without that password.

use std::collections::BTreeMap;

use super::sessions::{decode, Read, Session};
use super::Input;

/// The attributes that hold a secret, encrypted.
const SECRETS: [&str; 3] = ["Password", "VNCProxyPassword", "RDGatewayPassword"];
/// PuTTY's own template, which says nothing of a session.
const DEFAULT_PUTTY: &str = "Default Settings";
/// The most tunnels that a jump follows, past which a loop is assumed.
const MOST_HOPS: usize = 8;

/// The connections of each input.
pub fn read(inputs: &[Input]) -> Result<Read, String> {
    let mut read = Read::default();
    for input in inputs {
        let text = decode(&input.bytes);
        let doc = roxmltree::Document::parse(&text)
            .map_err(|e| format!("{}: not the XML of mRemoteNG's connections: {e}", input.name))?;
        let root = doc.root_element();
        if root.tag_name().name() != "Connections" {
            return Err(format!("{}: no Connections element, so no connections of mRemoteNG", input.name));
        }
        if root.attribute("FullFileEncryption").is_some_and(truth) {
            return Err(format!(
                "{}: the file is encrypted whole (FullFileEncryption), which only mRemoteNG's master password \
                 opens: in mRemoteNG, turn that off and save, or export the connections, and import that file",
                input.name
            ));
        }
        let mut nodes = Vec::new();
        walk(root, &[], &BTreeMap::new(), &mut nodes);
        read.secrets += root
            .descendants()
            .filter(|n| n.has_tag_name("Node"))
            .map(|n| SECRETS.iter().filter(|a| n.attribute(**a).is_some_and(|v| !v.is_empty())).count())
            .sum::<usize>();
        let by_name: BTreeMap<&str, &Resolved> = nodes.iter().map(|n| (n.name.as_str(), n)).collect();
        read.sessions.extend(nodes.iter().filter(|n| n.connection).map(|n| session(n, &by_name)));
    }
    Ok(read)
}

/// A node with each field as mRemoteNG takes it, its inheritance done.
#[derive(Debug, Clone, Default)]
struct Resolved {
    name: String,
    folders: Vec<String>,
    connection: bool,
    /// A `Type` that is neither a connection nor a container.
    other: Option<String>,
    fields: BTreeMap<&'static str, String>,
}

/// The fields of a session that a node can inherit, and the host, which it
/// cannot.
const FIELDS: [&str; 5] = ["Protocol", "Port", "Username", "PuttySession", "SSHTunnelConnectionName"];

/// `True` as mRemoteNG writes it: `True` up to 2.7, `true` since.
fn truth(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

/// Each `Node` under `parent`, in `folders`, whose container's fields are
/// `above`.
fn walk(
    parent: roxmltree::Node<'_, '_>,
    folders: &[String],
    above: &BTreeMap<&'static str, String>,
    out: &mut Vec<Resolved>,
) {
    for node in parent.children().filter(|n| n.has_tag_name("Node")) {
        let name = node.attribute("Name").unwrap_or_default().to_string();
        let kind = node.attribute("Type").unwrap_or_default();
        let mut fields = BTreeMap::new();
        for field in FIELDS {
            let inherits = node.attribute(format!("Inherit{field}").as_str()).is_some_and(truth);
            let value = if inherits { above.get(field).cloned() } else { node.attribute(field).map(str::to_string) };
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                fields.insert(field, value);
            }
        }
        if let Some(host) = node.attribute("Hostname").filter(|h| !h.is_empty()) {
            fields.insert("Hostname", host.to_string());
        }
        if node.attribute("SSHOptions").is_some_and(|o| !o.is_empty()) {
            fields.insert("SSHOptions", String::new());
        }
        let resolved = Resolved {
            name: name.clone(),
            folders: folders.to_vec(),
            connection: kind == "Connection",
            other: (!matches!(kind, "Connection" | "Container")).then(|| kind.to_string()),
            fields: fields.clone(),
        };
        if resolved.other.is_some() {
            // Named, never dropped silently: a comment of its own.
            out.push(Resolved { connection: true, ..resolved });
        } else {
            out.push(resolved);
        }
        if kind == "Container" {
            let mut inner = folders.to_vec();
            inner.push(name);
            walk(node, &inner, &fields, out);
        }
    }
}

/// The session of a connection; `by_name` finds the connection of a tunnel.
fn session(n: &Resolved, by_name: &BTreeMap<&str, &Resolved>) -> Session {
    let folder = (!n.folders.is_empty()).then(|| n.folders.join("/"));
    let mut s = Session { label: n.name.clone(), folder, ..Session::default() };
    if let Some(kind) = &n.other {
        s.not_ssh = Some(format!("a node of type {kind}"));
        return s;
    }
    let get = |field: &str| n.fields.get(field).map(String::as_str);
    let protocol = get("Protocol").unwrap_or("RDP");
    match protocol {
        "SSH2" => {}
        "SSH1" => {
            s.not_ssh = Some("SSH1, the first version of SSH, which podssh does not speak".to_string());
            return s;
        }
        other => {
            s.not_ssh = Some(other.to_string());
            return s;
        }
    }
    s.host = get("Hostname").map(str::to_string);
    s.port = get("Port").map(str::to_string);
    s.user = get("Username").map(str::to_string);
    if let Some(putty) = get("PuttySession").filter(|p| *p != DEFAULT_PUTTY) {
        s.notes.push(format!("the PuTTY session {putty} holds more of its settings, which are not imported"));
    }
    if n.fields.contains_key("SSHOptions") {
        s.notes.push("SSHOptions is not imported: PuTTY's options can hold a secret".to_string());
    }
    if let Some(tunnel) = get("SSHTunnelConnectionName") {
        match jump(tunnel, by_name) {
            Ok(jump) => s.jump = Some(jump),
            Err(why) => s.notes.push(format!("its tunnel {tunnel} is not imported: {why}")),
        }
    }
    s
}

/// The `ProxyJump` of a tunnel through the connection `first`: its hops,
/// the farthest first, as `ProxyJump` takes them.
fn jump(first: &str, by_name: &BTreeMap<&str, &Resolved>) -> Result<String, String> {
    let mut hops = Vec::new();
    let mut name = first;
    loop {
        if hops.len() == MOST_HOPS {
            return Err(format!("more than {MOST_HOPS} tunnels, one through the other"));
        }
        let Some(n) = by_name.get(name) else { return Err("no connection of the file has that name".into()) };
        let field = |f: &str| n.fields.get(f).map(String::as_str);
        if field("Protocol") != Some("SSH2") || n.other.is_some() {
            return Err(format!("{name} is not an SSH connection"));
        }
        let Some(host) = field("Hostname") else { return Err(format!("{name} has no host")) };
        let user = field("Username").map(|u| format!("{u}@")).unwrap_or_default();
        let port = field("Port").filter(|p| *p != "22").map(|p| format!(":{p}")).unwrap_or_default();
        hops.push(format!("{user}{host}{port}"));
        match field("SSHTunnelConnectionName") {
            Some(next) => name = next,
            None => break,
        }
    }
    hops.reverse();
    Ok(hops.join(","))
}

#[cfg(test)]
#[path = "mremoteng_tests.rs"]
mod tests;
