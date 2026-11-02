//! The opening of a Wisp connection, after the upgrade. Version 2: the
//! server's INFO, this side's INFO, then the server's CONTINUE on stream 0
//! with the buffer of each stream, or its CLOSE, which refuses. Version 1:
//! the CONTINUE first, and no INFO; the protocol's document says that a
//! client that receives it first speaks version 1.

use std::time::Duration;

use super::mux::Session;
use super::packet::{self, ext, Extension, Info, Packet, Reason};
use super::{WispError, VERSION};
use crate::frame;
use crate::session::close_code_and_reason;

/// What the opening settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The version spoken: (1, 0) for a server that sent its CONTINUE first.
    pub version: (u8, u8),
    /// The DATA packets that the server buffers for each new stream.
    pub buffer: u32,
    /// Whether the server confirms each stream with a CONTINUE once its
    /// target's socket is open: both INFOs list stream open confirmation.
    pub confirm: bool,
    /// The server's message of the day, one line made safe.
    pub motd: Option<String>,
}

/// This side's INFO, in answer to the server's: the version that both
/// speak, and those of the server's extensions that podssh takes, its
/// message of the day and stream open confirmation, neither with a payload
/// of the client's. An extension that the server did not list is not sent.
/// Refused: a server that requires a password or a key, as podssh sends
/// neither and no credential goes in a URL.
pub fn answer(server: &Info) -> Result<(Info, Opened), String> {
    for (id, what) in [(ext::PASSWORD, "a user name and a password"), (ext::KEY, "a key's signature")] {
        // The first byte of the server's metadata says whether it requires it.
        if server.extension(id).is_some_and(|m| m.first().is_some_and(|b| *b != 0)) {
            return Err(format!("the Wisp server requires {what}, which podssh does not send"));
        }
    }
    let version = (server.major, server.minor).min(VERSION);
    let mut extensions = Vec::new();
    let motd = server.extension(ext::MOTD).map(super::note_text);
    if motd.is_some() {
        extensions.push(Extension { id: ext::MOTD, payload: Vec::new() });
    }
    let confirm = server.extension(ext::CONFIRM).is_some();
    if confirm {
        extensions.push(Extension { id: ext::CONFIRM, payload: Vec::new() });
    }
    let ours = Info { major: version.0, minor: version.1, extensions };
    let motd = motd.filter(|m| !m.is_empty());
    Ok((ours, Opened { version, buffer: 0, confirm, motd }))
}

/// The opening, within `timeout`.
pub(super) async fn open(session: &Session, timeout: Duration) -> Result<Opened, WispError> {
    match tokio::time::timeout(timeout, steps(session)).await {
        Ok(opened) => opened,
        Err(_) => {
            let secs = timeout.as_secs();
            Err(WispError::Opening(format!("the Wisp server did not open the connection within {secs} s")))
        }
    }
}

async fn steps(session: &Session) -> Result<Opened, WispError> {
    match next(session).await? {
        (0, Packet::Continue(buffer)) => Ok(Opened { version: (1, 0), buffer, confirm: false, motd: None }),
        (0, Packet::Info(info)) => {
            let (ours, mut opened) = match answer(&info) {
                Ok(both) => both,
                Err(why) => {
                    // A client's refusal: a CLOSE on stream 0, then the Close.
                    let refusal = packet::encode(0, &Packet::Close(Reason::INCOMPATIBLE));
                    let _ = session.send_binary(&refusal).await;
                    let _ = session.send_close(1000, "").await;
                    return Err(WispError::Opening(why));
                }
            };
            let sent = session.send_binary(&packet::encode(0, &Packet::Info(ours))).await;
            sent.map_err(|e| WispError::Failed(format!("sending the INFO to the Wisp server failed: {e}")))?;
            match next(session).await? {
                (0, Packet::Continue(buffer)) => {
                    opened.buffer = buffer;
                    Ok(opened)
                }
                (0, Packet::Close(reason)) => Err(WispError::Refused(reason)),
                (id, other) => Err(out_of_turn(id, &other, "its CONTINUE")),
            }
        }
        (0, Packet::Close(reason)) => Err(WispError::Refused(reason)),
        (id, other) => Err(out_of_turn(id, &other, "a CONTINUE or an INFO")),
    }
}

fn out_of_turn(id: u32, packet: &Packet, wanted: &str) -> WispError {
    WispError::Opening(format!(
        "the Wisp server sent {} on stream {id} where {wanted} on stream 0 opens the connection: it may not speak Wisp",
        packet.name()
    ))
}

/// The server's next packet. A text frame is no packet: a server of
/// another kind may say why in one, and its words go in the line.
async fn next(session: &Session) -> Result<(u32, Packet), WispError> {
    let f = session.read_frame().await.map_err(|e| WispError::Failed(e.to_string()))?;
    match f.opcode {
        frame::OPCODE_BINARY => {
            let not_wisp = |why: String| WispError::Opening(format!("the server sent {why}: it may not speak Wisp"));
            packet::decode(&f.payload).map_err(not_wisp)
        }
        frame::OPCODE_CLOSE => {
            let (code, reason) = close_code_and_reason(&f.payload);
            Err(WispError::Gone { code, reason })
        }
        _ => {
            let said = super::note_text(&f.payload);
            Err(WispError::Opening(format!("the server sent text where Wisp sends a packet: {said}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(major: u8, minor: u8, extensions: Vec<Extension>) -> Info {
        Info { major, minor, extensions }
    }

    fn with(id: u8, metadata: &[u8]) -> Extension {
        Extension { id, payload: metadata.to_vec() }
    }

    #[test]
    fn the_answer_takes_the_lower_version_and_only_the_extensions_that_both_list() {
        let motd = with(ext::MOTD, b"rate limits: 500 kB/s\r\n");
        let server = info(2, 0, vec![with(ext::UDP, b""), motd, with(ext::CONFIRM, b"")]);
        let (ours, opened) = answer(&server).unwrap();
        assert_eq!((ours.major, ours.minor), (2, 0));
        let ids: Vec<u8> = ours.extensions.iter().map(|e| e.id).collect();
        assert_eq!(ids, [ext::MOTD, ext::CONFIRM], "no UDP: this road carries none");
        assert!(ours.extensions.iter().all(|e| e.payload.is_empty()), "no client payload");
        assert_eq!(opened.motd.as_deref(), Some("rate limits: 500 kB/s"));
        assert!(opened.confirm);
        let (ours, opened) = answer(&info(3, 7, Vec::new())).unwrap();
        assert_eq!(((ours.major, ours.minor), opened.version), ((2, 1), (2, 1)), "this side's newest");
        assert!(ours.extensions.is_empty() && !opened.confirm && opened.motd.is_none());
    }

    #[test]
    fn a_server_that_requires_a_credential_is_refused_and_one_that_allows_it_is_not() {
        let password = answer(&info(2, 0, vec![with(ext::PASSWORD, &[1])])).unwrap_err();
        assert!(password.contains("requires a user name and a password"), "{password}");
        let key = answer(&info(2, 0, vec![with(ext::KEY, &[1, 1, 9, 9])])).unwrap_err();
        assert!(key.contains("a key's signature"), "{key}");
        assert!(answer(&info(2, 0, vec![with(ext::PASSWORD, &[0]), with(ext::KEY, &[0, 1])])).is_ok(), "optional");
    }
}
