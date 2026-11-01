//! A server's key as an `ss://` URI (SIP002): `ss://USERINFO@HOST:PORT`,
//! then `/?plugin=...` and `#TAG` when they are given. USERINFO is
//! `method:password` in base64url, with or without padding, or
//! percent-encoded with its `:` as it is. The older form, the whole
//! `method:password@host:port` in base64, is read too: many lists still
//! serve it. A URI holds a password, so no message here quotes it: each
//! says what is wrong, never the text.

use std::fmt;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::Method;

/// The most characters of a tag that podssh keeps: a name in its lines.
const TAG_CHARS: usize = 64;

/// A Shadowsocks server, its method and its password.
#[derive(Clone, PartialEq, Eq)]
pub struct Node {
    pub method: Method,
    password: Zeroizing<String>,
    /// A name or an address, an IPv6 one with no brackets.
    pub host: String,
    pub port: u16,
    /// The key's own name for the server, after `#`.
    pub tag: Option<String>,
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("method", &self.method)
            .field("password", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tag", &self.tag)
            .finish()
    }
}

impl Node {
    /// A server by its parts, its host checked as a target of the relay is.
    pub fn new(method: Method, password: &str, host: &str, port: u16) -> Result<Node, String> {
        if password.is_empty() {
            return Err("its password is empty".into());
        }
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        crate::names::check_target(host)?;
        if port == 0 {
            return Err("its port is 0".into());
        }
        let password = Zeroizing::new(password.to_string());
        Ok(Node { method, password, host: host.to_string(), port, tag: None })
    }

    /// An `ss://` URI. A plugin is refused, as it is another program that
    /// podssh does not start, and so is Shadowsocks 2022.
    pub fn parse(text: &str) -> Result<Node, String> {
        let text = text.trim();
        let rest = match text.get(..5) {
            Some(scheme) if scheme.eq_ignore_ascii_case("ss://") => &text[5..],
            _ => return Err("it is not an ss:// URI".into()),
        };
        let (rest, tag) = match rest.split_once('#') {
            Some((rest, tag)) => (rest, Some(tag)),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        if let Some(plugin) = query.and_then(plugin_of) {
            return Err(plugin_refusal(&plugin));
        }
        let rest = rest.trim_end_matches('/');
        let (method, password, host, port) = match rest.rsplit_once('@') {
            Some((userinfo, authority)) => {
                let (method, password) = userinfo_of(userinfo)?;
                let (host, port) = authority_of(authority)?;
                (method, password, host, port)
            }
            None => older(rest)?,
        };
        let mut node = Node::new(Method::parse(&method)?, &password, &host, port)?;
        node.tag = tag.map(tag_of).filter(|t| !t.is_empty());
        Ok(node)
    }

    /// The server in a line: `ss://HOST:PORT`, and its tag in parentheses.
    /// Never its password.
    pub fn shown(&self) -> String {
        let at = crate::dial::authority(&self.host, self.port);
        match &self.tag {
            Some(tag) => format!("ss://{at} ({tag})"),
            None => format!("ss://{at}"),
        }
    }

    /// Whether `other` is this server with this key, whatever its tag.
    pub fn same_server(&self, other: &Node) -> bool {
        (self.method, &self.password, &self.host, self.port) == (other.method, &other.password, &other.host, other.port)
    }

    /// The master key of its password and method.
    pub fn master_key(&self) -> Zeroizing<Vec<u8>> {
        super::master_key(self.password.as_bytes(), self.method.key_len())
    }

    /// The server as an `ss://` URI, its user part in base64url as SIP002
    /// recommends: for a private file, never for a message.
    pub fn to_uri(&self) -> Zeroizing<String> {
        let userinfo = Zeroizing::new(format!("{}:{}", self.method.name(), self.password.as_str()));
        let encoded = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(userinfo.as_bytes()));
        let tag = self.tag.as_deref().map(|t| format!("#{}", percent_encode(t))).unwrap_or_default();
        let at = crate::dial::authority(&self.host, self.port);
        Zeroizing::new(format!("ss://{}@{at}{tag}", encoded.as_str()))
    }
}

/// `method` and `password` of a user part: percent-encoded when it holds
/// the `:` as it is, else base64.
fn userinfo_of(userinfo: &str) -> Result<(String, Zeroizing<String>), String> {
    let plain = if userinfo.contains(':') {
        Zeroizing::new(percent_decode(userinfo).ok_or("its user part is not percent-encoded text")?)
    } else {
        base64_text(userinfo).ok_or("its user part is neither base64 nor method:password")?
    };
    let (method, password) = plain.split_once(':').ok_or("its user part has no method:password")?;
    Ok((method.to_string(), Zeroizing::new(password.to_string())))
}

/// The older form: `method:password@host:port`, all of it in base64.
fn older(encoded: &str) -> Result<(String, Zeroizing<String>, String, u16), String> {
    let plain = base64_text(encoded).ok_or("it is neither ss://USERINFO@HOST:PORT nor the older ss://BASE64 form")?;
    let (userinfo, authority) = plain.rsplit_once('@').ok_or("its base64 holds no method:password@host:port")?;
    let (method, password) = userinfo.split_once(':').ok_or("its base64 holds no method:password")?;
    let (host, port) = authority_of(authority)?;
    Ok((method.to_string(), Zeroizing::new(password.to_string()), host, port))
}

/// `HOST:PORT` or `[IPV6]:PORT`; the port is required.
fn authority_of(text: &str) -> Result<(String, u16), String> {
    let (host, port) = match text.strip_prefix('[') {
        Some(inner) => {
            let (host, after) = inner.split_once(']').ok_or("its host has a [ and no ]")?;
            (host, after.strip_prefix(':').ok_or("it gives no port")?)
        }
        None => text.rsplit_once(':').ok_or("it gives no port")?,
    };
    let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or("its port is not a port")?;
    Ok((host.to_string(), port))
}

/// Base64 text, in either alphabet, with or without padding.
pub(super) fn base64_text(encoded: &str) -> Option<Zeroizing<String>> {
    let bytes = base64_bytes(encoded)?;
    String::from_utf8(bytes.to_vec()).ok().map(Zeroizing::new)
}

/// Base64 bytes, in either alphabet, with or without padding, white space
/// left out.
pub(super) fn base64_bytes(encoded: &str) -> Option<Zeroizing<Vec<u8>>> {
    let url: Zeroizing<String> = Zeroizing::new(
        encoded
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                other => other,
            })
            .collect(),
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT.decode(url.as_bytes()).ok().map(Zeroizing::new)
}

/// The plugin that a query names, if any, as [`plugin_name`] gives it.
fn plugin_of(query: &str) -> Option<String> {
    let value = query.split('&').find_map(|pair| pair.strip_prefix("plugin="))?;
    let value = percent_decode(value).unwrap_or_else(|| "?".to_string());
    (!value.trim().is_empty()).then(|| plugin_name(&value))
}

/// A plugin's program, from its value `NAME;OPTIONS`: its name when it has
/// the shape of one, else empty, as the options may hold a secret.
pub(super) fn plugin_name(value: &str) -> String {
    let name = value.split(';').next().unwrap_or_default().trim();
    let shaped = (1..=40).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if shaped {
        name.to_string()
    } else {
        String::new()
    }
}

/// The refusal of a key that names a plugin, by its name when it has one.
pub(super) fn plugin_refusal(name: &str) -> String {
    let named = if name.is_empty() { "a plugin".to_string() } else { format!("the plugin {name}") };
    format!(
        "it names {named}, another program, which podssh does not start: ask the server's operator for a key with \
         no plugin"
    )
}

/// A tag as a line can show it: decoded, on one line, and short.
pub(super) fn tag_of(raw: &str) -> String {
    let decoded = percent_decode(raw).unwrap_or_else(|| raw.to_string());
    let line = crate::text::one_line(&decoded);
    match line.char_indices().nth(TAG_CHARS) {
        Some((at, _)) => line[..at].trim().to_string(),
        None => line.trim().to_string(),
    }
}

/// `%XX` escapes decoded; `None` for an escape cut short or not hex, or
/// bytes that are not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out.to_vec()).ok()
}

/// Each byte but RFC 3986's unreserved ones as a `%` escape.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
