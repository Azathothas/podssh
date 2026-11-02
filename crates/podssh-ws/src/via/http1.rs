//! HTTP/1.1's CONNECT inside the second proxy's TLS (RFC 9110, section
//! 9.3.6): the request with the credentials, then the answer's head read a
//! byte at a time, so that no byte of the target's is taken with it. A 2xx
//! makes the TLS stream the tunnel.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::Via;
use crate::dial::{self, DialError};

/// The longest answer's head that is read before giving up.
const MAX_HEAD: usize = 16 * 1024;

/// CONNECT `target` on `tls`, within `timeout`: the stream, now the
/// tunnel, or the proxy's refusal.
pub(super) async fn connect<S>(mut tls: S, via: &Via, target: &str, timeout: Duration) -> Result<S, DialError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = request(via, target);
    let exchange = async {
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;
        read_head(&mut tls).await
    };
    let shown = via.shown();
    let head = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| DialError::Timeout { step: format!("the CONNECT exchange with {shown}"), after: timeout })?
        .map_err(|e| DialError::ProxyProtocol { proxy: shown.clone(), detail: e.to_string() })?;
    let (status, reason) =
        dial::parse_status_line(&head).map_err(|detail| DialError::ProxyProtocol { proxy: shown, detail })?;
    if (200..300).contains(&status) {
        return Ok(tls);
    }
    Err(super::refused(via, target, status, reason, &head))
}

/// The request's bytes; they hold the credentials, so they are wiped.
fn request(via: &Via, target: &str) -> Zeroizing<String> {
    let mut request = Zeroizing::new(format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: podssh/{}\r\n",
        env!("CARGO_PKG_VERSION")
    ));
    if let Some(value) = via.authorization() {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

/// The answer's head, through its empty line and not a byte further.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the connection closed before the answer's head ended",
            ));
        }
        head.push(byte[0]);
        if head.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no end of the answer's head within {MAX_HEAD} bytes"),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request names the target twice, and Basic only with a password.
    #[test]
    fn the_request_names_the_target_and_carries_basic_only_with_credentials() {
        let bare = Via::parse("https://proxy.example").unwrap();
        let text = request(&bare, "h.example:22");
        assert!(text.starts_with("CONNECT h.example:22 HTTP/1.1\r\nHost: h.example:22\r\n"), "{}", text.as_str());
        assert!(text.ends_with("\r\n\r\n") && !text.contains("Proxy-Authorization"));
        let with = Via::parse("https://alice@proxy.example").unwrap().with_credentials("s3cret\n").unwrap();
        use base64::Engine as _;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
        assert!(request(&with, "[::1]:22").contains(&format!("Proxy-Authorization: Basic {basic}\r\n")));
    }

    /// A head ends at its empty line, and the bytes after it stay.
    #[tokio::test]
    async fn the_head_is_read_to_its_empty_line_and_no_further() {
        let (mut ours, mut theirs) = tokio::io::duplex(1024);
        theirs.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-x\r\n").await.unwrap();
        let head = read_head(&mut ours).await.unwrap();
        assert_eq!(head, "HTTP/1.1 200 Connection established\r\n\r\n");
        let mut rest = [0u8; 11];
        ours.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"SSH-2.0-x\r\n");
    }
}
