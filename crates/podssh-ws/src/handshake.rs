//! The RFC 6455 opening handshake.
//!
//! ⛔ **The token travels in the `X-Relay-Token` header and never in the URL.**
//! Spec line 95 says *"URLs can appear in logs"*, and a URL is the one part of
//! a request that every proxy, every access log and every `Referer` header
//! records by default. The path podssh builds therefore has no query string
//! at all, and there is no function in this module that accepts a URL
//! containing one.
//!
//! ⛔ **No subprotocol is offered.** Spec line 207 says "no subprotocol", and
//! `sec-websocket-protocol` is omitted from the request rather than sent empty:
//! an empty value and an absent header are different on the wire, and a relay
//! that compares strings would see the empty one.

use base64::Engine as _;
use rustls::crypto::SecureRandom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::WsError;

/// ⛔ RFC 6455 §4.1: 16 random bytes, base64-encoded. The value exists only to
/// prove the response is not a cached file, and it is checked on the way back.
pub fn generate_key() -> Result<String, WsError> {
    generate_key_from(&crate::crypto::random::OsRandom)
}

/// [`generate_key`] from `random`, so that a test can plant a source that fails.
pub fn generate_key_from(random: &dyn SecureRandom) -> Result<String, WsError> {
    let mut bytes = [0u8; 16];
    random
        .fill(&mut bytes)
        .map_err(|e| WsError::Handshake(format!("no entropy for Sec-WebSocket-Key: {e:?}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// ⛔ **The request is built as a byte string, not handed to a URL parser.**
/// There is no query string to escape, and building the request directly means
/// there is no code path in which a token could be appended to one.
pub fn build_request(host_header: &str, path: &str, token: &str, key: &str) -> Vec<u8> {
    let mut req = String::with_capacity(512);
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    // ⛔ The token, in a header. See the module comment.
    req.push_str(&format!("X-Relay-Token: {token}\r\n"));
    // ⛔ **No `Sec-WebSocket-Protocol` line.** See the module comment.
    req.push_str("\r\n");
    req.into_bytes()
}

/// ⛔ **`Sec-WebSocket-Accept` is `base64(SHA1(key + GUID))`.** RFC 6455 §4.2.2
/// step 5.4. It is the one place a SHA-1 is *required* in modern TLS, and it
/// is not a security decision — it proves the response came from a server that
/// read the request rather than from a cache.
///
/// ⛔ **`sha2` has no SHA-1.** Implementing the compression function here is
/// twenty lines, and the alternative — pulling a crate in for a value that
/// RFC 6455 fixes as a constant operation — is worse than writing it, because
/// the function is fully determined by the RFC and can be asserted against the
/// worked example in §1.3.
pub fn accept_key(client_key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = String::with_capacity(client_key.len() + GUID.len());
    input.push_str(client_key);
    input.push_str(GUID);
    base64::engine::general_purpose::STANDARD.encode(sha1(input.as_bytes()))
}

/// ⛔ **A SHA-1 that is only ever used for `accept_key`.** It is named for what
/// it is so that no other caller can reach it by accident.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// ⛔ **Bounded, because a peer that never sends `\r\n\r\n` must not hang the
/// client.** RFC 6455 §4.2.1 caps the handshake response; anything larger is a
/// protocol violation rather than a slow network.
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

/// Read the response and check the status, the `Upgrade`, and the `Accept`.
///
/// ⛔ **Returns the bytes that arrived behind the header terminator.** The read
/// is not line-oriented and a server may write the `101` and its first frame in
/// one segment: the relay dials the target *before* the upgrade, so the target's
/// first bytes can be sitting in the same read. ⛔ A function that returned
/// `Result<(), _>` dropped them — the frame parser then starts mid-frame and
/// every later frame is garbage.
pub async fn read_response<S>(stream: &mut S, expected_key: &str) -> Result<Vec<u8>, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(WsError::Upgrade {
                status: 0,
                why: "the relay closed the connection before completing the upgrade".into(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            check_response(&head, expected_key)?;
            return Ok(buf.split_off(end));
        }
        if buf.len() > MAX_HANDSHAKE_RESPONSE {
            return Err(WsError::Upgrade {
                status: 0,
                why: format!("no header terminator within {MAX_HANDSHAKE_RESPONSE} bytes"),
            });
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// ⛔ **Every check below is one whose absence the relay can observe.**
///
/// ⛔ **The `426` and `403` distinction is load-bearing.** E03's `Decision`
/// section records that a verifier measured a valid token with no upgrade
/// returning `426` while the same path with no token returned `403` — so
/// authentication is checked *before* the upgrade, and the two failures are
/// distinguishable. That is only true if the status is reported rather than
/// collapsed into "upgrade failed".
pub fn check_response(head: &str, expected_key: &str) -> Result<(), WsError> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| WsError::Upgrade {
            status: 0,
            why: format!("no status code in {status_line:?}"),
        })?;

    if status != 101 {
        return Err(WsError::Upgrade { status, why: head.to_string() });
    }

    let mut upgrade_ok = false;
    let mut accept: Option<String> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "upgrade" if value.eq_ignore_ascii_case("websocket") => upgrade_ok = true,
            "sec-websocket-accept" => accept = Some(value.to_string()),
            _ => {}
        }
    }
    if !upgrade_ok {
        return Err(WsError::Upgrade {
            status,
            why: "101 without Upgrade: websocket".into(),
        });
    }
    // ⛔ **The accept value is compared, not merely present.** Checking that
    // the header exists proves nothing: any cache can echo it.
    let expected = accept_key(expected_key);
    match accept {
        Some(v) if v == expected => Ok(()),
        Some(v) => Err(WsError::Upgrade {
            status,
            why: format!("Sec-WebSocket-Accept was {v:?}, expected {expected:?}"),
        }),
        None => Err(WsError::Upgrade {
            status,
            why: "101 without Sec-WebSocket-Accept".into(),
        }),
    }
}

/// ⛔ **Write the request and read the response, in that order.** Split so a
/// test can drive `check_response` without a socket.
///
/// ⛔ The second value is what arrived after the header terminator, and the
/// caller must feed it into the frame reader before its first socket read.
pub async fn handshake<S>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    token: &str,
) -> Result<([u8; 4], Vec<u8>), WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = generate_key()?;
    let request = build_request(host_header, path, token, &key);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let pending = read_response(stream, &key).await?;
    Ok((masking_key()?, pending))
}

/// ⛔ **A fresh key per frame, from the OS.** RFC 6455 §5.3 requires a key per
/// frame, not per connection.
///
/// ⛔ **It is a `Result`, not a panic.** There is no "send it unmasked"
/// fallback — RFC 6455 §5.3 is a MUST and a client with no entropy cannot
/// speak the protocol — but a client that cannot get entropy is a *runtime
/// error to report*, and a panic here would take down a session over a
/// condition the caller could have diagnosed. This is the same rule as the
/// third plant: a clean error, never a panic.
pub fn masking_key() -> Result<[u8; 4], WsError> {
    masking_key_from(&crate::crypto::random::OsRandom)
}

/// [`masking_key`] from `random`, so that a test can plant a source that fails.
pub fn masking_key_from(random: &dyn SecureRandom) -> Result<[u8; 4], WsError> {
    let mut key = [0u8; 4];
    random
        .fill(&mut key)
        .map_err(|e| WsError::Frame(format!("no OS entropy for a masking key: {e:?}")))?;
    Ok(key)
}
