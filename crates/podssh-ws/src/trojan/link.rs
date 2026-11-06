//! A Trojan server as its share link names it, the form that Xray-core's
//! clients and panels give out beside `vless://`:
//! `trojan://PASSWORD@HOST:PORT?security=tls&sni=&type=tcp|ws&host=&path=#NAME`.
//! The password is the credential: the link is read from a private file, and
//! nothing that podssh shows holds it or its hash. A setting that changes the
//! bytes in a way that podssh does not follow (a flow, REALITY, a transport
//! other than TLS alone or a WebSocket) is refused by its name, never
//! ignored. `fp` and `alpn` shape the ClientHello alone, which a Trojan
//! server does not read: podssh's own TLS goes, and they are not refused.

use std::fmt;

use sha2::{Digest, Sha224};

/// The password of a Trojan user, kept as the hex of its SHA-224, the 56
/// bytes that each request begins with; the password itself is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Password([u8; 56]);

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl Password {
    /// `hex(SHA224(password))`, in lower case as trojan-gfw writes and reads
    /// it (`src/core/config.cpp`, `SHA224`): a server compares the bytes.
    pub fn new(password: &str) -> Result<Password, String> {
        if password.is_empty() {
            return Err("the password is empty".into());
        }
        let digest = Sha224::digest(password.as_bytes());
        let mut hex = [0u8; 56];
        for (i, byte) in digest.iter().enumerate() {
            hex[2 * i] = HEX[usize::from(byte >> 4)];
            hex[2 * i + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Ok(Password(hex))
    }

    pub fn hex(&self) -> &[u8; 56] {
        &self.0
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// What carries the Trojan stream, inside TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS alone: the request is the first bytes of the TLS stream.
    Tls,
    /// A WebSocket over TLS, its binary messages the stream (trojan-go's
    /// `websocket`, Xray-core's `ws`).
    Ws,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Tls => "TLS",
            Transport::Ws => "a WebSocket over TLS",
        }
    }
}

/// A server of the file: where TCP goes, what TLS checks, what HTTP names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub password: Password,
    /// The address that TCP dials, through `HTTPS_PROXY` when it is set.
    pub host: String,
    pub port: u16,
    /// The name that TLS asks for and checks: `sni`, else `host`, else HOST.
    pub sni: String,
    /// `Host` of a WebSocket's upgrade: `host`, else `sni`, else HOST.
    pub authority: String,
    /// The WebSocket's path, from `/`, and its query.
    pub path: String,
    pub transport: Transport,
    /// The link's fragment, its name in a panel.
    pub name: Option<String>,
}

impl Server {
    /// `trojan://HOST:PORT`, and the path of a WebSocket, with no password.
    pub fn shown(&self) -> String {
        let at = crate::dial::authority(&self.host, self.port);
        match self.transport {
            Transport::Tls => format!("trojan://{at}"),
            Transport::Ws => format!("trojan://{at}{}", self.path.split('?').next().unwrap_or("/")),
        }
    }

    /// A share link. A refusal names the setting, never the password.
    pub fn parse(link: &str) -> Result<Server, String> {
        let link = link.trim();
        let rest = match link.get(..9) {
            Some(scheme) if scheme.eq_ignore_ascii_case("trojan://") => &link[9..],
            _ => return Err("a line is trojan://PASSWORD@HOST:PORT?security=tls&type=tcp|ws&...".into()),
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) => (rest, crate::proxy::percent_decode(name).ok().map(|n| crate::text::one_line(&n))),
            None => (rest, None),
        };
        let (before, query) = rest.split_once('?').unwrap_or((rest, ""));
        let before = before.trim_end_matches('/');
        let (password, hostport) = before.rsplit_once('@').ok_or("the link has no PASSWORD@ before its host")?;
        let password = crate::proxy::percent_decode(password).map_err(|_| "the password is not percent-encoded")?;
        let password = Password::new(&password)?;
        let (host, port) = crate::dial::split_host_port(hostport)?;
        if host.is_empty() {
            return Err("the link names no host".into());
        }
        crate::dial::check_name(&host).map_err(|e| e.to_string())?;
        // Trojan's own port is 443: a link with none means it.
        let port = port.unwrap_or(443);
        if port == 0 {
            return Err("port 0 is no port".into());
        }
        let params = Params::parse(query)?;
        params.refuse_unspoken()?;
        let transport = match params.get("type").unwrap_or("tcp").to_ascii_lowercase().as_str() {
            "tcp" | "" => Transport::Tls,
            "ws" | "websocket" => Transport::Ws,
            other => {
                return Err(format!(
                    "type={other} is not spoken: podssh carries Trojan over TLS (type=tcp) and over a WebSocket \
                     (type=ws)"
                ))
            }
        };
        // A Trojan server is its TLS: with none, the password crosses in the
        // clear, and no server of the protocol serves that.
        match params.get("security").unwrap_or("tls").to_ascii_lowercase().as_str() {
            "tls" | "" => {}
            "none" => {
                return Err("security=none is refused: Trojan is TLS, and the password would cross in clear".into())
            }
            "reality" => return Err("security=reality is not spoken: it borrows another site's TLS".into()),
            other => return Err(format!("security={other} is not spoken: tls")),
        }
        let sni = params.get("sni").or(params.get("peer")).or(params.get("host")).unwrap_or(host.as_str());
        let sni = sni.to_string();
        let authority = match params.get("host").or(params.get("sni")) {
            Some(name) => name.to_string(),
            None if port == 443 && host.contains(':') => format!("[{host}]"),
            None if port == 443 => host.clone(),
            None => crate::dial::authority(&host, port),
        };
        // A header's value: no CR, LF or space may break the request.
        crate::dial::check_name(&authority).map_err(|e| format!("host: {e}"))?;
        let path = path(params.get("path").unwrap_or("/"))?;
        Ok(Server { password, host, port, sni, authority, path, transport, name })
    }
}

/// The WebSocket's path as the request carries it; early data (`ed`) is not
/// sent, as the server reads it only when it comes.
fn path(path: &str) -> Result<String, String> {
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    let query: Vec<&str> = query.split('&').filter(|kv| !kv.is_empty() && !kv.starts_with("ed=")).collect();
    let full = if query.is_empty() { path.to_string() } else { format!("{path}?{}", query.join("&")) };
    crate::url::request_target(&full).map_err(|why| format!("path: {why}"))
}

/// The link's query, each value percent-decoded.
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(query: &str) -> Result<Params, String> {
        let mut out = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = crate::proxy::percent_decode(&value.replace('+', " "))
                .map_err(|_| format!("the value of {key} is not percent-encoded"))?;
            out.push((key.to_ascii_lowercase(), value));
        }
        Ok(Params(out))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// The settings whose bytes or whose trust podssh does not take.
    fn refuse_unspoken(&self) -> Result<(), String> {
        if let Some(flow) = self.get("flow").filter(|f| !f.is_empty()) {
            return Err(format!("flow={flow} is not spoken: podssh's Trojan has no flow"));
        }
        if self.get("pbk").is_some() {
            return Err("pbk names REALITY, which is not spoken".into());
        }
        // A certificate that is not checked is a server that anybody can be.
        let insecure =
            ["allowinsecure", "insecure"].iter().filter_map(|k| self.get(k)).any(|v| v == "1" || v == "true");
        if insecure {
            return Err(
                "allowInsecure is refused: podssh checks the server's certificate; --ca-file names a CA of yours"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
