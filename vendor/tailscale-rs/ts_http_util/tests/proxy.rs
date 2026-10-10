//! Increment 2 (E39): the CONNECT proxy dialer, against a fake proxy.
//!
//! `configure` is process-global, so the async tests serialize on `SERIAL`:
//! two tests configuring concurrently dial each other's fake proxy (RST on
//! Windows loopback). Each async test also resets the global on exit.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ts_http_util::proxy::{ProxyConfig, applies, configure, connect, dial};

/// ⛔ Each async test holds this for its whole body. `configure` sets
/// one global dialer; without the guard, neighbours interleave configure and
/// `connect` and read each other's listeners. An async lock, as each test
/// holds it across its awaits; a test that panics poisons nothing (podssh's
/// patch 0020).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

/// A fake proxy: records CONNECT authorities, answers per `respond`, then
/// echoes bytes both ways. Returns the port and the seen-authorities log.
async fn fake_proxy(
    respond: &'static str,
    require_auth: Option<&'static str>,
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let authority = text
            .lines()
            .next()
            .unwrap_or("")
            .strip_prefix("CONNECT ")
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        seen_task.lock().unwrap().push(authority);
        if let Some(want) = require_auth {
            let ok = text.contains(&format!("Proxy-Authorization: {want}"));
            let reply = if ok { respond } else { "HTTP/1.1 407 Proxy Auth Required\r\n\r\n" };
            stream.write_all(reply.as_bytes()).await.unwrap();
            if !ok {
                return;
            }
        } else {
            stream.write_all(respond.as_bytes()).await.unwrap();
        }
        if !respond.starts_with("HTTP/1.1 2") {
            return;
        }
        // Echo: whatever the client sends after the handshake comes back.
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });
    (port, seen)
}

fn config(port: u16) -> ProxyConfig {
    ProxyConfig::from_url(&format!("http://127.0.0.1:{port}")).unwrap()
}

/// ⛔ **The plant is the shape of this test.** If `connect` dialled direct
/// instead of CONNECTing, the fake records zero authorities and the echo
/// never happens: the assertion on the count fails, and so does the echo.
#[tokio::test]
async fn connect_issues_one_connect_and_echoes_bytes() {
    let _serial = serial().await;
    let (port, seen) = fake_proxy("HTTP/1.1 200 Connection Established\r\n\r\n", None).await;
    configure(Some(config(port)));
    let _reset = ResetOnDrop;

    let mut stream = connect("relay.example", 443).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");

    assert_eq!(*seen.lock().unwrap(), vec!["relay.example:443".to_string()]);
}

/// A 403 names the policy: status and reason travel in the error, and no
/// fallback dial follows it (the fallback would hang where direct is dropped).
#[tokio::test]
async fn a_proxy_refusal_is_a_named_error_not_a_fallback() {
    let _serial = serial().await;
    let (port, seen) =
        fake_proxy("HTTP/1.1 403 Forbidden\r\n\r\n", None).await;
    configure(Some(config(port)));
    let _reset = ResetOnDrop;

    let err = connect("example.com", 22).await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("example.com:22"), "{text}");
    // Exactly one attempt: no silent direct fallback after the refusal.
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// Without credentials the proxy answers 407; with them, 200.
#[tokio::test]
async fn proxy_authorization_is_sent_when_configured() {
    let _serial = serial().await;
    let (port, _) = fake_proxy(
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        Some("Basic dXNlcjpwYXNz"),
    )
    .await;
    // No credentials: 407.
    configure(Some(config(port)));
    let err = connect("relay.example", 443).await.unwrap_err();
    assert!(err.to_string().contains("407"), "{err}");

    // With credentials: 200 and an echo.
    let (port, _) = fake_proxy(
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        Some("Basic dXNlcjpwYXNz"),
    )
    .await;
    configure(Some(
        ProxyConfig::from_url(&format!("http://user:pass@127.0.0.1:{port}")).unwrap(),
    ));
    let mut stream = connect("relay.example", 443).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    let mut back = [0u8; 2];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ok");
    configure(None);
}

/// A proxy that never finishes its head is an error, not a hang and not an
/// allocation: the 16 KiB bound fires.
#[tokio::test]
async fn an_endless_response_head_is_refused_at_the_bound() {
    let _serial = serial().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        // 32 KiB of headers, no blank line, then silence.
        let filler = vec![b'X'; 32 * 1024];
        stream.write_all(b"HTTP/1.1 200 OK\r\nX-Filler: ").await.unwrap();
        stream.write_all(&filler).await.unwrap();
        futures::future::pending::<()>().await;
    });
    configure(Some(config(port)));
    let _reset = ResetOnDrop;

    let err = connect("relay.example", 443).await.unwrap_err();
    assert!(err.to_string().contains("16"), "{err}");
}

/// URL parsing: credentials, default port, and refusals.
#[test]
fn proxy_urls_parse_and_bad_ones_are_refused() {
    let config =
        ProxyConfig::from_url("http://user:pass@proxy.example:3128").unwrap();
    assert_eq!(config.host, "proxy.example");
    assert_eq!(config.port, 3128);

    let config = ProxyConfig::from_url("http://proxy.example").unwrap();
    assert_eq!(config.port, 8080);

    // podssh's patch 0017: an IPv6 proxy is dialled by its address.
    let config = ProxyConfig::from_url("http://[::1]:3128").unwrap();
    assert_eq!((config.host.as_str(), config.port), ("::1", 3128));

    assert!(ProxyConfig::from_url("socks5://proxy.example:1080").is_err());
    assert!(ProxyConfig::from_url("http://:3128").is_err());
    assert!(ProxyConfig::from_url("not a url").is_err());
}

/// podssh's patch 0017: the user name and the password reach the proxy as
/// typed, not as the URL escapes them.
#[tokio::test]
async fn escaped_credentials_reach_the_proxy_decoded() {
    let _serial = serial().await;
    // `us@er:p:s s`, in Base64.
    let (port, _) = fake_proxy(
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        Some("Basic dXNAZXI6cDpzIHM="),
    )
    .await;
    configure(Some(
        ProxyConfig::from_url(&format!("http://us%40er:p%3As%20s@127.0.0.1:{port}")).unwrap(),
    ));
    let _reset = ResetOnDrop;
    let mut stream = connect("relay.example", 443).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    let mut back = [0u8; 2];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ok");
}

/// podssh's patch 0017: a host on the `no_proxy` list goes direct, through
/// [`dial`], and the other hosts go through the proxy.
#[tokio::test]
async fn a_host_on_the_no_proxy_list_is_dialled_direct() {
    let _serial = serial().await;
    let (port, seen) = fake_proxy("HTTP/1.1 200 Connection Established\r\n\r\n", None).await;
    let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let direct_port = direct.local_addr().unwrap().port();
    configure(Some(config(port).with_no_proxy("example.org, 127.0.0.1:9")));
    let _reset = ResetOnDrop;

    assert!(!applies("127.0.0.1"));
    assert!(!applies("www.EXAMPLE.org"));
    assert!(applies("relay.example"));
    let (dialled, accepted) = tokio::join!(dial("127.0.0.1", direct_port), direct.accept());
    dialled.unwrap();
    accepted.unwrap();
    assert!(seen.lock().unwrap().is_empty(), "the proxy was asked");
}

/// podssh's patch 0017: no refusal quotes the URL, which may hold a
/// password, and the Debug form hides the credentials.
#[test]
fn no_message_shows_the_credentials() {
    for url in [
        "socks5://user:secret@proxy.example:1080",
        "http://user:secret@",
        "http://user:%zz@proxy.example:3128",
    ] {
        let why = ProxyConfig::from_url(url).unwrap_err();
        assert!(!why.contains("secret") && !why.contains("%zz"), "{why}");
    }
    let config = ProxyConfig::from_url("http://user:secret@proxy.example:3128").unwrap();
    let shown = format!("{config:?}");
    assert!(
        !shown.contains("secret") && !shown.contains("dXNlcjpzZWNyZXQ"),
        "{shown}"
    );
}

/// Resets the global when the test returns, pass or fail, so no proxy leaks
/// into a neighbour test on another thread.
struct ResetOnDrop;
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        configure(None);
    }
}
