//! The X client of the test's server (T-037).

use russh::server;

/// An X client's first packet on a new `x11` channel to the client, with
/// `cookie` (hexadecimal): the X server's first byte of answer, or `none`
/// when the channel was refused or closed.
pub(super) async fn x11_probe(handle: &server::Handle, cookie: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(channel) = handle.channel_open_x11("127.0.0.1", 6010).await else { return "refused".into() };
    let cookie: Vec<u8> =
        (0..cookie.len() / 2).filter_map(|i| u8::from_str_radix(&cookie[2 * i..2 * i + 2], 16).ok()).collect();
    let name = b"MIT-MAGIC-COOKIE-1";
    let mut setup = vec![b'l', 0, 11, 0, 0, 0];
    setup.extend_from_slice(&(name.len() as u16).to_le_bytes());
    setup.extend_from_slice(&(cookie.len() as u16).to_le_bytes());
    setup.extend_from_slice(&[0, 0]);
    setup.extend_from_slice(name);
    setup.extend_from_slice(&[0, 0]);
    setup.extend_from_slice(&cookie);
    let mut stream = channel.into_stream();
    let mut status = [0u8; 1];
    if stream.write_all(&setup).await.is_err() || stream.read_exact(&mut status).await.is_err() {
        return "none".into();
    }
    status[0].to_string()
}
