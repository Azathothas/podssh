//! WebTunnel (T-385), as lyrebird's client speaks it to the WebTunnel
//! server 0.0.7: a connection to the bridge's `url=` (or to `addr=`), TLS
//! for `servername=` or the URL's host when the URL is `https://`, then one
//! `GET` of the URL's secret path with `Connection: upgrade` and
//! `Upgrade: websocket` and no key, and, on `101 Switching Protocols` with
//! those two headers, raw bytes both ways: no WebSocket frames.
//!
//! TLS is checked as each road's (`tls.rs`), with no bypass. `cert=`, a hash
//! chained over the certificates that the server sent, is a second check
//! after that one, never in its place: lyrebird's makes it a reason to skip
//! the chain's check, which podssh does not, so a bridge whose certificate
//! no root signs is refused. `sni-imitation=` and `cert-domain=` check a
//! name other than the one sent, which the verifier here does not do, and
//! are refused. `utls=` and `ver=` are read and left.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

use crate::pt::{get, host_port, HttpUrl, Reach};
use crate::url::Stream;

/// The longest answer head read.
const MAX_HEAD: usize = 16 * 1024;

/// A bridge's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub url: HttpUrl,
    /// `addr=`: where the connection goes, in place of the URL's host.
    pub addr: Option<(String, u16)>,
    /// `servername=`: the names that TLS may send, one of them each time.
    pub server_names: Vec<String>,
    /// `cert=`: the hash of the certificates, checked after TLS's own check.
    pub pin: Option<[u8; 32]>,
}

impl Args {
    /// The arguments of a bridge line, or why they are not WebTunnel's.
    pub fn parse(settings: &[(String, String)]) -> Result<Args, String> {
        let url = HttpUrl::parse(get(settings, "url").ok_or("a webtunnel bridge line needs url=")?)?;
        for refused in ["sni-imitation", "cert-domain"] {
            if get(settings, refused).is_some() {
                return Err(format!(
                    "{refused}= checks a name other than the one that TLS sends, and podssh checks the certificate \
                     for the name that it sends"
                ));
            }
        }
        let addr = match get(settings, "addr") {
            None => None,
            Some(text) => match host_port(text, 0).map_err(|why| format!("addr={text}: {why}"))? {
                (_, 0) => return Err(format!("addr={text}: a port is needed")),
                pair => Some(pair),
            },
        };
        let mut server_names = Vec::new();
        for name in get(settings, "servername").unwrap_or_default().split(',').map(str::trim) {
            if !name.is_empty() {
                crate::names::check_host(name).map_err(|why| format!("servername={name}: {why}"))?;
                server_names.push(name.to_string());
            }
        }
        let pin = match get(settings, "cert") {
            None => None,
            Some(text) => Some(pin_of(text)?),
        };
        Ok(Args { url, addr, server_names, pin })
    }

    /// The URL with no path, for a line: the path is the bridge's secret.
    pub fn shown(&self) -> String {
        format!("{}://{}/", if self.url.tls { "https" } else { "http" }, self.url.authority)
    }

    /// Where the connection goes.
    pub fn dial(&self) -> (String, u16) {
        self.addr.clone().unwrap_or_else(|| (self.url.host.clone(), self.url.port))
    }

    /// The name that TLS sends and checks: one of `servername=`, else the
    /// URL's host.
    pub fn server_name(&self) -> String {
        match self.server_names.len() {
            0 => self.url.host.clone(),
            n => self.server_names[random_below(n)].clone(),
        }
    }
}

/// `cert=`: the base64 of a hash of 32 bytes.
fn pin_of(text: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| "cert= is not base64 of a hash of 32 bytes".to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "cert= is not base64 of a hash of 32 bytes".to_string())
}

/// A number below `n`, 0 with no random source: a choice among names that
/// each pass the check.
fn random_below(n: usize) -> usize {
    let mut bytes = [0u8; 8];
    use rustls::crypto::SecureRandom as _;
    match crate::crypto::random::OsRandom.fill(&mut bytes) {
        Ok(()) if n > 0 => (u64::from_le_bytes(bytes) % n as u64) as usize,
        _ => 0,
    }
}

/// The hash of `chain`, as WebTunnel's `GenerateCertChainHash`: SHA-256 of
/// the first certificate, then of the hash so far and the SHA-256 of each
/// next one.
pub fn chain_hash<C: AsRef<[u8]>>(chain: &[C]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hash: Option<[u8; 32]> = None;
    for cert in chain {
        let own: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        hash = Some(match hash {
            None => own,
            Some(so_far) => Sha256::new().chain_update(so_far).chain_update(own).finalize().into(),
        });
    }
    hash.unwrap_or_default()
}

/// The upgrade, as Go writes lyrebird's request: the path with no query,
/// `Host` the URL's host with no port, Go's `User-Agent`, then the two
/// headers in Go's order. The agent is Go's so that the request is the one
/// that every WebTunnel client sends.
pub fn request(args: &Args) -> String {
    let host = if args.url.host.contains(':') { format!("[{}]", args.url.host) } else { args.url.host.clone() };
    format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\nConnection: upgrade\r\n\
         Upgrade: websocket\r\n\r\n",
        args.url.path()
    )
}

/// Whether `head` is the answer that lyrebird takes: the status line's
/// `101 Switching Protocols`, `Upgrade: websocket` and
/// `Connection: upgrade`, in any case.
pub fn check_answer(head: &str) -> Result<(), String> {
    let (status, reason, headers) = crate::http::parse_head(head)?;
    if status != 101 || reason != "Switching Protocols" {
        return Err(format!("the bridge answered {status} {reason}, not 101 Switching Protocols"));
    }
    let value = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.to_ascii_lowercase());
    match (value("upgrade").as_deref(), value("connection").as_deref()) {
        (Some("websocket"), Some("upgrade")) => Ok(()),
        _ => Err("the bridge's 101 lacks Upgrade: websocket and Connection: upgrade".into()),
    }
}

/// A stream to the bridge for `args`: the connection, TLS and its pin, the
/// upgrade and its 101, each within the reach's wait.
pub async fn open(args: &Args, reach: &Reach) -> Result<Stream, String> {
    let (host, port) = args.dial();
    let name = args.server_name();
    let mut stream = crate::pt::open(&host, port, args.url.tls, &name, reach).await?;
    if let (Some(pin), Stream::Tls(tls)) = (&args.pin, &stream) {
        let chain = tls.get_ref().1.peer_certificates().unwrap_or_default();
        if chain_hash(chain) != *pin {
            return Err(format!("{name}'s certificates are not the ones that cert= pins"));
        }
    }
    let upgraded = async {
        stream.write_all(request(args).as_bytes()).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let head = read_head(&mut stream).await?;
        check_answer(&head)
    };
    let answered = tokio::time::timeout(reach.wait, upgraded).await;
    match answered {
        Ok(Ok(())) => Ok(stream),
        Ok(Err(why)) => Err(format!("the upgrade at {}: {why}", args.shown())),
        Err(_) => Err(format!("the upgrade at {}: no answer within {} s", args.shown(), reach.wait.as_secs())),
    }
}

/// The answer's head, read a byte at a time so that no byte after it, the
/// first of the bridge's own, is taken.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String, String> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > MAX_HEAD {
            return Err(format!("no end of the answer's head within {} KiB", MAX_HEAD / 1024));
        }
        match stream.read(&mut byte).await {
            Ok(0) => return Err("the connection closed before the answer".into()),
            Ok(_) => head.push(byte[0]),
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_line_gives_its_url_address_names_and_pin() {
        use base64::Engine as _;
        let pin = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let line = [("url", "https://bridge.test/a1b2?q=1"), ("addr", "192.0.2.3:8443"), ("ver", "0.0.7")];
        let mut pairs = line.to_vec();
        pairs.extend([("servername", "front.test"), ("cert", pin.as_str()), ("utls", "none")]);
        let args = Args::parse(&settings(&pairs)).unwrap();
        assert_eq!(args.dial(), ("192.0.2.3".to_string(), 8443));
        assert_eq!(args.server_name(), "front.test");
        assert_eq!(args.pin, Some([7u8; 32]));
        assert_eq!(args.shown(), "https://bridge.test/");
        let plain = Args::parse(&settings(&[("url", "http://192.0.2.4:15000/s3cret")])).unwrap();
        assert_eq!((plain.dial(), plain.server_name()), (("192.0.2.4".to_string(), 15000), "192.0.2.4".to_string()));
    }

    #[test]
    fn the_request_is_lyrebird_s_with_no_key() {
        let args = Args::parse(&settings(&[("url", "https://bridge.test:8443/a1b2?q=1")])).unwrap();
        assert_eq!(
            request(&args),
            "GET /a1b2 HTTP/1.1\r\nHost: bridge.test\r\nUser-Agent: Go-http-client/1.1\r\n\
             Connection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
    }

    #[test]
    fn only_lyrebird_s_101_is_taken() {
        let good = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n";
        assert_eq!(check_answer(good), Ok(()));
        for bad in [
            "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            "HTTP/1.1 101 Web Socket Protocol Handshake\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n",
        ] {
            assert!(check_answer(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_line_that_asks_another_check_or_lacks_a_url_is_refused() {
        for bad in [
            settings(&[("addr", "192.0.2.3:443")]),
            settings(&[("url", "https://b.test/x"), ("sni-imitation", "other.test")]),
            settings(&[("url", "https://b.test/x"), ("cert-domain", "other.test")]),
            settings(&[("url", "https://b.test/x"), ("cert", "not base64!")]),
            settings(&[("url", "https://b.test/x"), ("cert", "AAAA")]),
            settings(&[("url", "https://b.test/x"), ("addr", "192.0.2.3")]),
        ] {
            assert!(Args::parse(&bad).is_err(), "{bad:?}");
        }
    }

    /// The hash of one certificate is its SHA-256; of two, SHA-256 of the
    /// first's hash and the second's, as `pin.go` chains them.
    #[test]
    fn the_chain_s_hash_is_chained_as_webtunnel_s() {
        use sha2::{Digest as _, Sha256};
        let (a, b) = (b"first".as_slice(), b"second".as_slice());
        let one: [u8; 32] = Sha256::digest(a).into();
        assert_eq!(chain_hash(&[a]), one);
        let mut both = one.to_vec();
        both.extend_from_slice(&Sha256::digest(b));
        let two: [u8; 32] = Sha256::digest(&both).into();
        assert_eq!(chain_hash(&[a, b]), two);
    }
}
