//! `http-listen:` (T-367): `podssh pipe` as an HTTP CONNECT proxy, for a
//! program that knows only `HTTPS_PROXY`. Each client is one tunnel. Its
//! request is read within 16 KiB and 30 s; then, in this order, come its
//! credentials when `--proxy-auth-file` names some (407), its method, which
//! is CONNECT alone (405), and its target, checked as each target is (400):
//! who may ask before what is asked, and nothing is dialed for a request
//! that is refused. Then the template's road opens with that target, and
//! only once it is open does the client hear 200, so that it learns whether
//! its target was reached, as the SOCKS side of `-D` does; a road that did
//! not open gives 403, 502 or 504 (`gateway`). A refusal closes the
//! connection.

use std::io::Write;
use std::rc::Rc;
use std::time::Duration;

use podssh_ws::http::request::{self, Request, RequestError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::address::Address;
use super::credentials::{Credentials, FLAG};
use super::listen::Listener;
use super::pump::{self, End};
use super::remote::Settings;
use super::web::Template;
use crate::relay_settings::Refusal;

/// The time that a client has to send its request.
const REQUEST_LIMIT: Duration = Duration::from_secs(30);
/// How long a refused client's bytes are read before its connection closes:
/// a close with bytes unread is a reset, which can lose the answer.
const LINGER: Duration = Duration::from_secs(2);
/// The tunnels at once. A program behind a proxy opens several connections
/// at a time (npm 15, pip 10): at the 8 of `--keep-listening`, the rest
/// would wait for one to end.
pub const AT_ONCE: usize = 32;
/// The challenge of a 407 (RFC 7617).
const CHALLENGE: &str = "Basic realm=\"podssh\", charset=\"UTF-8\"";

/// What the proxy does with each request.
pub struct Proxy {
    pub template: Template,
    pub credentials: Option<Credentials>,
    /// `-q`: no line for each CONNECT.
    pub quiet: bool,
}

/// The credentials of `--proxy-auth-file`, read before anything binds. The
/// flag is for `http-listen:` alone (64), and a proxy on an address that is
/// not loopback needs it (64): scanners find an open proxy, and each of its
/// clients would spend this host's road.
pub fn credentials(addresses: [&Address; 2], file: Option<&str>) -> Result<Option<Credentials>, Refusal> {
    let proxy = addresses.iter().find_map(|a| match a {
        Address::HttpListen(at) => Some(&**at),
        _ => None,
    });
    match (proxy, file) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(Refusal::usage(format!("{FLAG} is for http-listen:, the side that answers CONNECT"))),
        (Some(_), Some(file)) => Credentials::read(file).map(Some),
        (Some(Address::TcpListen { host, port }), None) if !loopback(host) => {
            let at = podssh_ws::dial::authority(host, *port);
            Err(Refusal::usage(format!(
                "http-listen:{at}: other hosts reach a proxy on an address that is not loopback, and each of its \
                 requests would spend this host's road: name the credentials of its clients with {FLAG} FILE"
            )))
        }
        (Some(_), None) => Ok(None),
    }
}

fn loopback(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The line that tells how a program reaches the proxy: never a credential.
pub fn reach_line(listener: &Listener, at: &Address, credentials: Option<&Credentials>) -> String {
    match (listener.local_addr(), at) {
        (Some(addr), _) => {
            let user = if credentials.is_some() { "USER:PASSWORD@" } else { "" };
            let line = format!("an HTTP CONNECT proxy: a program reaches it with HTTPS_PROXY=http://{user}{addr}");
            match credentials {
                Some(credentials) => format!("{line}, a line of {} for USER:PASSWORD", credentials.file),
                None => line,
            }
        }
        (None, Address::UnixListen(path)) => format!("an HTTP CONNECT proxy on the socket {path}"),
        (None, _) => "an HTTP CONNECT proxy".into(),
    }
}

/// A request that is refused: its answer, when a client is there to read
/// one, and podssh's line. `ws-listen:` refuses with it too (T-368).
pub(super) struct Refused {
    pub(super) answer: Option<Vec<u8>>,
    pub(super) line: String,
}

pub(super) fn refuse(status: u16, words: &str, headers: &[(&str, &str)], line: String) -> Refused {
    Refused { answer: Some(request::refusal(status, words, headers)), line: format!("{line}: answered {status}") }
}

/// A client's request head, within 16 KiB and 30 s, and the bytes after it.
pub(super) async fn read_head(client: &mut End) -> Result<(Request, Vec<u8>), Refused> {
    let read = tokio::time::timeout(REQUEST_LIMIT, request::read_request(&mut client.read, Vec::new())).await;
    match read {
        Err(_) => Err(refuse(408, "no request came within 30 s", &[], "no request within 30 s".into())),
        Ok(Err(RequestError::Gone(why))) => {
            Err(Refused { answer: None, line: format!("left before its request ended: {why}") })
        }
        Ok(Err(e)) => Err(refuse(e.status().unwrap_or(400), &e.to_string(), &[], e.to_string())),
        Ok(Ok(read)) => Ok(read),
    }
}

/// One client: its request, then its tunnel; its lines on stderr after
/// `client N`.
pub async fn client(n: u64, mut client: End, proxy: Rc<Proxy>, settings: Rc<Settings>, listener_is_a: bool) {
    let prefix = format!("podssh pipe: client {n}");
    let mut err = std::io::stderr();
    let (address, shown, rest) = match asked(&mut client, &proxy).await {
        Ok(asked) => asked,
        Err(refused) => {
            if let Some(answer) = refused.answer {
                close_after(&mut client, &answer).await;
            }
            let _ = writeln!(err, "{prefix}: {}", refused.line);
            return;
        }
    };
    if !proxy.quiet {
        let _ = writeln!(err, "{prefix}: CONNECT {shown}");
    }
    let mut lines = Vec::new();
    let mut keep = |line: &str| lines.push(line.to_string());
    let opened = super::gateway::reach(&address, &settings, &mut keep).await;
    for line in &lines {
        let _ = writeln!(err, "{prefix}: {line}");
    }
    let mut other = match opened {
        Ok(end) => end,
        Err(unreached) => {
            close_after(&mut client, &request::refusal(unreached.status, &unreached.reason, &[])).await;
            let (code, status, phrase) = (unreached.code, unreached.status, request::reason(unreached.status));
            let _ = writeln!(err, "{prefix}: ended with {code}, and the client heard {status} {phrase}");
            return;
        }
    };
    // The answer, then the bytes that the client sent after its request.
    let answered = async {
        client.write.write_all(&request::established()).await?;
        client.write.flush().await?;
        if !rest.is_empty() {
            other.write.write_all(&rest).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    if answered.await.is_err() {
        abandon(other).await;
        let _ = writeln!(err, "{prefix}: the client left before its tunnel opened");
        return;
    }
    let (a, b) = if listener_is_a { (client, other) } else { (other, client) };
    let code = super::report(pump::pump(a, b).await, &prefix, &mut err).await;
    if code != 0 {
        let _ = writeln!(err, "{prefix}: ended with {code}");
    }
}

/// The road that a client's request asks for: the template filled in, the
/// target as shown, and the bytes after the request, which are the
/// tunnel's.
async fn asked(client: &mut End, proxy: &Proxy) -> Result<(Address, String, Vec<u8>), Refused> {
    let (head, rest) = read_head(client).await?;
    if let Some(credentials) = &proxy.credentials {
        if !credentials.admit(head.header("proxy-authorization")) {
            let line = format!("a request with no credentials of {}, or wrong ones", credentials.file);
            let headers = [("Proxy-Authenticate", CHALLENGE)];
            return Err(refuse(407, "this proxy needs a USER:PASSWORD of its file", &headers, line));
        }
    }
    if head.method != "CONNECT" {
        let line = format!("{} is not CONNECT", head.method);
        let words = "this proxy takes CONNECT HOST:PORT alone, as HTTPS_PROXY asks it";
        return Err(refuse(405, words, &[("Allow", "CONNECT")], line));
    }
    if head.has("transfer-encoding") || head.header("content-length").is_some_and(|v| v != "0") {
        return Err(refuse(400, "a CONNECT has no content", &[], "a CONNECT with content".into()));
    }
    let target = &head.target;
    let (host, port) =
        request::connect_target(target).map_err(|why| refuse(400, &why, &[], format!("CONNECT {target}: {why}")))?;
    let address = proxy.template.fill(&host, port).map_err(|r| refuse(400, &r.message, &[], r.message.clone()))?;
    Ok((address, podssh_ws::dial::authority(&host, port), rest))
}

/// Send `answer`, then end the connection: the write half first, then the
/// client's bytes read for a while, so that a close with bytes unread does
/// not reset the answer away.
pub(super) async fn close_after(client: &mut End, answer: &[u8]) {
    let sent = async {
        client.write.write_all(answer).await?;
        client.write.flush().await?;
        client.write.shutdown().await
    };
    if tokio::time::timeout(LINGER, sent).await.is_err() {
        return;
    }
    let mut sink = [0u8; 4096];
    let drained = async { while client.read.read(&mut sink).await.is_ok_and(|n| n > 0) {} };
    let _ = tokio::time::timeout(LINGER, drained).await;
}

/// Close a road that no client takes, as at any end.
pub(super) async fn abandon(end: End) {
    let End { read, write, ending, .. } = end;
    drop((read, write));
    if let Some(ending) = ending {
        let _ = ending.finish().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str) -> Address {
        Address::HttpListen(Box::new(Address::TcpListen { host: host.into(), port: 3128 }))
    }

    #[test]
    fn a_proxy_off_loopback_needs_credentials_and_the_flag_needs_a_proxy() {
        let template = Address::Template(Template::Relay);
        assert!(credentials([&tcp("127.0.0.1"), &template], None).unwrap().is_none());
        assert!(credentials([&template, &tcp("::1")], None).unwrap().is_none());
        for open in ["0.0.0.0", "::", "192.0.2.7"] {
            let refusal = credentials([&tcp(open), &template], None).unwrap_err();
            assert_eq!(refusal.code, 64, "{open}");
            assert!(refusal.message.contains(FLAG), "{}", refusal.message);
        }
        let socket = Address::HttpListen(Box::new(Address::UnixListen("/tmp/p.sock".into())));
        assert!(credentials([&socket, &template], None).unwrap().is_none(), "a socket is this user's alone");
        let refusal = credentials([&Address::Stdio, &Address::Tcp { host: "a".into(), port: 1 }], Some("f"));
        assert_eq!(refusal.unwrap_err().code, 64);
        assert_eq!(credentials([&tcp("0.0.0.0"), &template], Some("/no/such/file")).unwrap_err().code, 78);
    }

    async fn answer_to(head: &str, proxy: &Proxy) -> (Result<(Address, String, Vec<u8>), String>, String) {
        let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(ours);
        let mut end = End::plain(Box::new(read), Box::new(write));
        theirs.write_all(head.as_bytes()).await.unwrap();
        let asked = asked(&mut end, proxy).await;
        let asked = match asked {
            Ok(asked) => Ok(asked),
            Err(refused) => {
                if let Some(answer) = &refused.answer {
                    end.write.write_all(answer).await.unwrap();
                }
                Err(refused.line)
            }
        };
        drop(end);
        let mut said = String::new();
        theirs.read_to_string(&mut said).await.unwrap();
        (asked, said)
    }

    /// The order of the checks: the credentials, then the method, then the
    /// target; each refusal says why, and only a good request has a road.
    #[tokio::test]
    async fn who_may_ask_comes_before_what_is_asked() {
        let file = "tester:a long secret\n";
        let credentials = Some(Credentials::parse(file, "creds").unwrap());
        let proxy = Proxy { template: Template::Tcp, credentials, quiet: true };
        let (asked, said) = answer_to("GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n", &proxy).await;
        assert!(asked.is_err() && said.starts_with("HTTP/1.1 407 "), "{said}");
        assert!(said.contains("Proxy-Authenticate: Basic realm=\"podssh\""), "{said}");
        let token = "Proxy-Authorization: Basic dGVzdGVyOmEgbG9uZyBzZWNyZXQ=\r\n";
        let (_, said) = answer_to(&format!("GET http://example.org/ HTTP/1.1\r\n{token}\r\n"), &proxy).await;
        assert!(said.starts_with("HTTP/1.1 405 ") && said.contains("Allow: CONNECT\r\n"), "{said}");
        let (_, said) = answer_to(&format!("CONNECT example.org HTTP/1.1\r\n{token}\r\n"), &proxy).await;
        assert!(said.starts_with("HTTP/1.1 400 "), "{said}");
        let head = format!("CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n{token}\r\n\x16\x03");
        let (asked, said) = answer_to(&head, &proxy).await;
        let (address, shown, rest) = asked.unwrap();
        assert_eq!(address, Address::Tcp { host: "example.org".into(), port: 443 });
        assert_eq!((shown.as_str(), rest.as_slice(), said.as_str()), ("example.org:443", &b"\x16\x03"[..], ""));
        let wrong = "Proxy-Authorization: Basic dGVzdGVyOndyb25n\r\n";
        let (_, said) = answer_to(&format!("CONNECT example.org:443 HTTP/1.1\r\n{wrong}\r\n"), &proxy).await;
        assert!(said.starts_with("HTTP/1.1 407 "), "{said}");
    }
}
