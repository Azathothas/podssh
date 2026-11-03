//! The X client of the test's server (T-037).

use russh::server::{self, Session};
use russh::ChannelId;

/// The command `x11-probe` on `channel`: [`x11_probe`] with the cookie of
/// the client's `x11-req`, then the X server's status and that cookie, and
/// the status 0. From a task: the session's loop must go on, to carry the
/// `x11` channel's messages.
pub(super) fn run(cookie: String, channel: ChannelId, session: &mut Session) {
    let handle = session.handle();
    tokio::spawn(async move {
        let status = x11_probe(&handle, &cookie).await;
        let _ = handle.data(channel, format!("x11 status {status}\nx11-req cookie {cookie}\n").into_bytes()).await;
        let _ = handle.exit_status_request(channel, 0).await;
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;
    });
}

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
