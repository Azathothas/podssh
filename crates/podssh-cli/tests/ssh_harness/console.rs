//! The commands of the test's server for the tests of the Windows console
//! (T-132): `bytes HEX...` sends each word, read as hexadecimal, as one
//! message on stdout, then exits 0. For a user named `pty-...`, whose pty is
//! granted, `watch` prints `READY` and the pty's size as `SIZE COLSxROWS`,
//! then the size again at each change and `KEYS HEX` for each message of
//! input, and exits 0 at a `q`.

use russh::server::Session;
use russh::ChannelId;

/// `bytes HEX...`, when `command` is it; `None` else.
pub(super) fn bytes(command: &str, channel: ChannelId, session: &mut Session) -> Option<Result<(), russh::Error>> {
    let words = command.strip_prefix("bytes ")?;
    let mut sent = Ok(());
    for word in words.split_whitespace() {
        let message: Option<Vec<u8>> = (0..word.len())
            .step_by(2)
            .map(|at| word.get(at..at + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
            .collect();
        sent = sent.and_then(|()| session.data(channel, message.unwrap_or_else(|| word.as_bytes().to_vec())));
    }
    Some(
        sent.and_then(|()| session.exit_status_request(channel, 0))
            .and_then(|()| session.eof(channel))
            .and_then(|()| session.close(channel)),
    )
}

/// The start of `watch`, with the pty's size.
pub(super) fn watch(channel: ChannelId, size: (u32, u32), session: &mut Session) -> Result<(), russh::Error> {
    session.data(channel, format!("READY\r\nSIZE {}x{}\r\n", size.0, size.1).into_bytes())
}

/// A message of input to `watch`: its bytes, or the end at a `q`. True when
/// the command ended.
pub(super) fn watch_input(data: &[u8], channel: ChannelId, session: &mut Session) -> Result<bool, russh::Error> {
    if data.contains(&b'q') {
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        return Ok(true);
    }
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    session.data(channel, format!("KEYS {hex}\r\n").into_bytes())?;
    Ok(false)
}

/// A new size of the pty of `watch`.
pub(super) fn watch_size(size: (u32, u32), channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    session.data(channel, format!("SIZE {}x{}\r\n", size.0, size.1).into_bytes())
}
