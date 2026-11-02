//! A VLESS server as its share link names it, the form that Xray-core's
//! clients and panels give out (XTLS/Xray-core discussion 716):
//! `vless://ID@HOST:PORT?type=ws|xhttp&security=tls|none&sni=&host=&path=&mode=#NAME`.
//! The ID is the credential: the link is read from a private file, and
//! nothing that podssh shows holds it. A setting that changes the bytes in
//! a way that podssh does not follow (a flow, REALITY, VLESS's encryption, an
//! XHTTP placement) is refused by its name, never ignored.

use std::fmt;

use super::extra::Extra;

/// The ID of a VLESS user, the 16 bytes that each request carries.
#[derive(Clone, PartialEq, Eq)]
pub struct Id([u8; 16]);

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Id(<redacted>)")
    }
}

impl Id {
    /// As Xray-core reads one (`common/uuid/uuid.go`, `ParseString`): 32
    /// hex digits in the groups 8-4-4-4-12, the dashes optional; or a word
    /// of 1 to 30 bytes, which is UUIDv5 of it under the zero namespace.
    pub fn parse(text: &str) -> Result<Id, String> {
        let len = text.len();
        if !(32..=36).contains(&len) {
            if len == 0 || len > 30 {
                return Err("the ID is no UUID, and no word of 1 to 30 bytes".into());
            }
            let digest = <sha1::Sha1 as sha1::Digest>::digest([&[0u8; 16][..], text.as_bytes()].concat());
            let mut id = [0u8; 16];
            id.copy_from_slice(&digest[..16]);
            id[6] = (id[6] & 0x0f) | (5 << 4);
            id[8] = (id[8] & 0x3f) | 0x80;
            return Ok(Id(id));
        }
        let mut id = [0u8; 16];
        let mut rest = text.as_bytes();
        let mut at = 0;
        for group in [8usize, 4, 4, 4, 12] {
            if rest.first() == Some(&b'-') {
                rest = &rest[1..];
            }
            if rest.len() < group {
                return Err("the ID is no UUID: a group is short".into());
            }
            for pair in rest[..group].chunks(2) {
                // Hex digits alone: from_str_radix would take a sign too.
                let digits = pair.iter().all(u8::is_ascii_hexdigit).then_some(pair);
                let hex = digits.and_then(|p| std::str::from_utf8(p).ok()).and_then(|p| u8::from_str_radix(p, 16).ok());
                id[at] = hex.ok_or("the ID is no UUID: a digit is not hexadecimal")?;
                at += 1;
            }
            rest = &rest[group..];
        }
        if !rest.is_empty() {
            return Err("the ID is no UUID: text after its last group".into());
        }
        Ok(Id(id))
    }

    pub fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// XHTTP's modes (`transport/internet/splithttp/dialer.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Xray-core's client takes packet-up for TLS with no REALITY; podssh
    /// does too, and `doctor` tries each.
    Auto,
    /// One streamed GET down, and a numbered POST for each chunk up.
    PacketUp,
    /// One streamed GET down, and one streamed POST up.
    StreamUp,
    /// One POST whose body goes up and whose answer comes down.
    StreamOne,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::PacketUp => "packet-up",
            Mode::StreamUp => "stream-up",
            Mode::StreamOne => "stream-one",
        }
    }

    /// The mode that a run takes for this one.
    pub fn chosen(self) -> Mode {
        match self {
            Mode::Auto => Mode::PacketUp,
            other => other,
        }
    }
}

/// What carries the VLESS stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A WebSocket, its binary messages the stream.
    Ws,
    /// XHTTP (SplitHTTP), over HTTP/2.
    Xhttp(Mode),
}

impl Transport {
    pub fn name(self) -> String {
        match self {
            Transport::Ws => "a WebSocket".into(),
            Transport::Xhttp(mode) => format!("XHTTP {}", mode.chosen().name()),
        }
    }
}

/// A server of the file: where TCP goes, what TLS checks, what HTTP names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub id: Id,
    /// The address that TCP dials, through `HTTPS_PROXY` when it is set.
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The name that TLS asks for and checks: `sni`, else `host`, else HOST.
    pub sni: String,
    /// `Host` and `:authority`: `host`, else `sni`, else HOST.
    pub authority: String,
    /// The path, from `/`, and its query, as the request carries them.
    pub path: String,
    pub transport: Transport,
    /// The protocols offered by ALPN to XHTTP's TLS.
    pub alpn: Vec<Vec<u8>>,
    pub extra: Extra,
    /// The link's fragment, its name in a panel.
    pub name: Option<String>,
}

impl Server {
    /// `vless://HOST:PORT/PATH`, with no ID and no query.
    pub fn shown(&self) -> String {
        let path = self.path.split('?').next().unwrap_or("/");
        format!("vless://{}{path}", crate::dial::authority(&self.host, self.port))
    }

    /// A share link. A refusal names the setting, never the ID.
    pub fn parse(link: &str) -> Result<Server, String> {
        let link = link.trim();
        let rest = match link.get(..8) {
            Some(scheme) if scheme.eq_ignore_ascii_case("vless://") => &link[8..],
            _ => return Err("a line is vless://ID@HOST:PORT?type=ws|xhttp&...".into()),
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) => (rest, crate::proxy::percent_decode(name).ok().map(|n| crate::text::one_line(&n))),
            None => (rest, None),
        };
        let (before, query) = rest.split_once('?').unwrap_or((rest, ""));
        let before = before.trim_end_matches('/');
        let (id, hostport) = before.rsplit_once('@').ok_or("the link has no ID@ before its host")?;
        let id = crate::proxy::percent_decode(id).map_err(|_| "the ID is not percent-encoded".to_string())?;
        let id = Id::parse(&id)?;
        let (host, port) = crate::dial::split_host_port(hostport)?;
        if host.is_empty() {
            return Err("the link names no host".into());
        }
        crate::dial::check_name(&host).map_err(|e| e.to_string())?;
        let port = port.ok_or("the link names no port")?;
        if port == 0 {
            return Err("port 0 is no port".into());
        }
        let params = Params::parse(query)?;
        params.refuse_unspoken()?;
        let transport = match params.get("type").unwrap_or("tcp").to_ascii_lowercase().as_str() {
            "ws" | "websocket" => Transport::Ws,
            "xhttp" | "splithttp" => Transport::Xhttp(mode_of(params.get("mode").unwrap_or("auto"))?),
            other => {
                return Err(format!(
                    "type={other} is not spoken: podssh carries VLESS over type=ws and type=xhttp, which pass where \
                     HTTPS does"
                ))
            }
        };
        let tls = match params.get("security").unwrap_or("none").to_ascii_lowercase().as_str() {
            "tls" => true,
            "none" | "" => false,
            "reality" => return Err("security=reality is not spoken: it borrows another site's TLS".into()),
            other => return Err(format!("security={other} is not spoken: tls or none")),
        };
        let sni = params.get("sni").or(params.get("host")).unwrap_or(host.as_str()).to_string();
        // The scheme's own port goes unnamed, as a browser's Host has it.
        let own_port = if tls { 443 } else { 80 };
        let authority = match params.get("host").or(params.get("sni")) {
            Some(name) => name.to_string(),
            None if port == own_port && host.contains(':') => format!("[{host}]"),
            None if port == own_port => host.clone(),
            None => crate::dial::authority(&host, port),
        };
        // A header's value: no CR, LF or space may break the request.
        crate::dial::check_name(&authority).map_err(|e| format!("host: {e}"))?;
        let path = path(params.get("path").unwrap_or("/"), transport)?;
        let alpn = match params.get("alpn") {
            Some(list) => list.split(',').map(|p| p.trim().as_bytes().to_vec()).filter(|p| !p.is_empty()).collect(),
            None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        let extra = match params.get("extra") {
            Some(json) if transport != Transport::Ws => Extra::parse(json)?,
            _ => Extra::default(),
        };
        let transport = match (transport, extra.mode) {
            (Transport::Xhttp(Mode::Auto), Some(mode)) => Transport::Xhttp(mode),
            (t, _) => t,
        };
        Ok(Server { id, host, port, tls, sni, authority, path, transport, alpn, extra, name })
    }
}

pub(super) fn mode_of(word: &str) -> Result<Mode, String> {
    match word.to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(Mode::Auto),
        "packet-up" => Ok(Mode::PacketUp),
        "stream-up" => Ok(Mode::StreamUp),
        "stream-one" => Ok(Mode::StreamOne),
        other => Err(format!("mode={other} is no mode of XHTTP: auto, packet-up, stream-up or stream-one")),
    }
}

/// The path as the request carries it. A WebSocket's `ed` (early data in
/// a header, which the server reads only when it is sent) is not sent; XHTTP's
/// path ends with `/`, as `GetNormalizedPath` makes it (`config.go`).
fn path(path: &str, transport: Transport) -> Result<String, String> {
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    let query: Vec<&str> = query.split('&').filter(|kv| !kv.is_empty() && !kv.starts_with("ed=")).collect();
    let path = match transport {
        Transport::Xhttp(_) if !path.ends_with('/') => format!("{path}/"),
        _ => path.to_string(),
    };
    let full = if query.is_empty() { path } else { format!("{path}?{}", query.join("&")) };
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

    /// The settings whose bytes podssh does not make.
    fn refuse_unspoken(&self) -> Result<(), String> {
        if let Some(flow) = self.get("flow").filter(|f| !f.is_empty()) {
            return Err(format!("flow={flow} is not spoken: podssh's VLESS has no flow"));
        }
        if self.get("encryption").is_some_and(|e| !e.is_empty() && !e.eq_ignore_ascii_case("none")) {
            return Err("encryption is not spoken: podssh's VLESS takes encryption=none".into());
        }
        if self.get("pbk").is_some() {
            return Err("pbk names REALITY, which is not spoken".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from its parts: a scanner of secrets takes a whole link with an
    // ID for a credential.
    fn link(rest: &str) -> String {
        ["vless://550e8400-e29b-41d4", "-a716-446655440000@", rest].concat()
    }

    #[test]
    fn an_id_is_a_uuid_with_or_without_dashes_or_a_word_mapped_as_xray_maps_it() {
        let dashed = Id::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(dashed, Id::parse("550e8400e29b41d4a716446655440000").unwrap());
        assert_eq!(dashed.bytes()[..4], [0x55, 0x0e, 0x84, 0x00]);
        // UUIDv5 of the word under the zero namespace: version 5, RFC 4122's variant.
        let word = Id::parse("podssh").unwrap();
        assert_eq!((word.bytes()[6] >> 4, word.bytes()[8] >> 6), (5, 2));
        assert_ne!(word, Id::parse("podssh2").unwrap());
        let long = "x".repeat(31);
        let bad_hex = "550e8400-e29b-41d4-a716-44665544000g";
        for bad in ["", bad_hex, &long, "550e8400-e29b-41d4-a716-4466554400001"] {
            assert!(Id::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(format!("{dashed:?}"), "Id(<redacted>)");
    }

    #[test]
    fn a_link_gives_the_dial_the_tls_name_the_host_the_path_and_the_transport() {
        let ws = "203.0.113.9:443?type=ws&security=tls&sni=v.example&host=cdn.example&path=%2Fws";
        let ws = Server::parse(&link(ws)).unwrap();
        assert_eq!((ws.host.as_str(), ws.port, ws.tls), ("203.0.113.9", 443, true));
        assert_eq!((ws.sni.as_str(), ws.authority.as_str(), ws.path.as_str()), ("v.example", "cdn.example", "/ws"));
        assert_eq!(ws.transport, Transport::Ws);
        assert_eq!(ws.shown(), "vless://203.0.113.9:443/ws");
        assert!(!format!("{ws:?}").contains("550e8400"), "{ws:?}");
        let xh = "v.example:8443?type=xhttp&security=tls&path=xh&mode=stream-one#My%20server";
        let xh = Server::parse(&link(xh)).unwrap();
        assert_eq!((xh.sni.as_str(), xh.authority.as_str()), ("v.example", "v.example:8443"));
        assert_eq!((xh.path.as_str(), xh.transport), ("/xh/", Transport::Xhttp(Mode::StreamOne)));
        assert_eq!(xh.name.as_deref(), Some("My server"));
        let plain = Server::parse(&link("[2001:db8::1]:80?type=splithttp&encryption=none")).unwrap();
        assert_eq!((plain.tls, plain.authority.as_str()), (false, "[2001:db8::1]"));
        assert_eq!(plain.transport, Transport::Xhttp(Mode::Auto));
        assert_eq!(plain.transport.name(), "XHTTP packet-up");
        let early = Server::parse(&link("h.example:443?type=ws&path=%2Fp%3Fed%3D2048%26k%3Dv")).unwrap();
        assert_eq!(early.path, "/p?k=v", "early data is not sent");
        let extra = Server::parse(&link("h.example:443?type=xhttp&extra=%7B%22mode%22%3A%22stream-up%22%7D")).unwrap();
        assert_eq!(extra.transport, Transport::Xhttp(Mode::StreamUp));
    }

    #[test]
    fn a_setting_that_podssh_does_not_follow_is_refused_by_its_name_never_with_the_id() {
        for (rest, words) in [
            ("h.example:443?type=tcp&security=tls", "type=tcp"),
            ("h.example:443", "type=tcp"),
            ("h.example:443?type=ws&security=reality&pbk=x", "pbk"),
            ("h.example:443?type=ws&flow=xtls-rprx-vision", "flow=xtls-rprx-vision"),
            ("h.example:443?type=ws&encryption=mlkem768x25519plus.native.0rtt", "encryption"),
            ("h.example:443?type=xhttp&mode=packet-down", "mode=packet-down"),
            ("h.example?type=ws", "no port"),
            ("h.example:0?type=ws", "port 0"),
            ("h.example:443?type=ws&host=a%0d%0ab", "host"),
            ("h.example:443?type=ws&path=%2Fa%20b", "path"),
        ] {
            let why = Server::parse(&link(rest)).unwrap_err();
            assert!(why.contains(words), "{rest}: {why}");
            assert!(!why.contains("550e8400"), "{why}");
        }
        assert!(Server::parse("vmess://abc").unwrap_err().contains("vless://"));
        assert!(Server::parse("vless://h.example:443?type=ws").unwrap_err().contains("ID@"));
    }
}
