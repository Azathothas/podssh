//! The relay role's mailbox (T-086): magic-wormhole's mailbox protocol of
//! version 1, at `/v1/mailbox`, for podssh's pairing by a short code alone,
//! so that a user's own relay is the meeting point of its node and its
//! operators, with no third party (`--pair-mailbox wss://HOST/v1/mailbox`).
//! A client of magic-wormhole's Python library with podssh's AppID speaks it
//! too. The role learns no code: the ends run SPAKE2 over it (`crate::code`,
//! feature `code`), and it stores and forwards their messages ([`table`]).
//! Each connection counts in the role's brake, as each is an attempt; the
//! role pings each client, and ends one that says nothing for 5 minutes, or
//! that has lived 20.

pub mod table;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::http::request::Request;
use podssh_ws::server;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

use self::table::stamped;
use super::{answer, Config};

/// Where the role serves the mailbox.
pub const PATH: &str = "/v1/mailbox";
/// podssh's AppID, the one that `crate::code` binds with: the role's
/// mailbox serves no other application.
pub const APPID: &str = "github.com/PodUtils/podssh/pair";
/// A client that says nothing for this long is ended.
const IDLE: Duration = Duration::from_secs(300);
/// A connection lives this long at most: a code lives 10 minutes.
const LIFE: Duration = Duration::from_secs(20 * 60);
/// The role pings each client this often, so that a path that ends a quiet
/// connection keeps it.
const PING_EVERY: Duration = Duration::from_secs(30);

/// Whether `path` is the mailbox's.
pub fn serves(path: &str) -> bool {
    path == PATH
}

/// Serve one client of the mailbox of `cfg`'s role on `stream`, from its
/// upgrade.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    if stream.write_all(&server::switching(&key)).await.is_err() {
        return;
    }
    let session = Arc::new(server::session(stream, pending, None));
    let (outbox, mut queued) = mpsc::channel::<String>(table::OUTBOX);
    // One writer, so that a message to this client from another one's
    // command never interleaves with its own answers.
    let writer = {
        let session = session.clone();
        tokio::spawn(async move {
            let mut ping = tokio::time::interval(PING_EVERY);
            ping.tick().await;
            loop {
                tokio::select! {
                    next = queued.recv() => {
                        let Some(text) = next else { break };
                        if session.send_text(&text).await.is_err() {
                            break;
                        }
                    }
                    _ = ping.tick() => {
                        if session.send_ping(b"podssh").await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = session.send_close(1000, "").await;
        })
    };
    let table = &cfg.pairs.mailbox;
    let mut conn = table.connection(outbox.clone());
    let deadline = Instant::now() + LIFE;
    let mut said = outbox.send(stamped(json!({ "type": "welcome", "welcome": {} }))).await.is_ok();
    while said {
        let left = deadline.saturating_duration_since(Instant::now()).min(IDLE);
        let message = match tokio::time::timeout(left, session.read_frame()).await {
            Ok(Ok(f)) if matches!(f.opcode, frame::OPCODE_TEXT | frame::OPCODE_BINARY) => f.payload,
            // A Close, which the session answered; an error; the end of its
            // life or of its patience.
            _ => break,
        };
        let answers = match serde_json::from_slice::<Value>(&message) {
            Ok(command) if command.is_object() => table.handle(&mut conn, &command),
            _ => vec![json!({ "type": "error", "error": "a message is one JSON object", "orig": Value::Null })],
        };
        for reply in answers {
            said = outbox.send(stamped(reply)).await.is_ok();
            if !said {
                break;
            }
        }
    }
    table.gone(&conn);
    // The writer ends once no sender is left: this one, and the table's.
    drop(conn);
    drop(outbox);
    let _ = writer.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mailbox_has_its_path_and_podssh_s_appid() {
        assert!(serves("/v1/mailbox") && !serves("/v1/mailbox/x") && !serves("/v1"));
        assert!(super::super::serves(PATH), "a quick tunnel's node gives the path to the role");
        assert!(super::super::brake::braked("GET", PATH), "each connection is an attempt");
        assert!(IDLE < LIFE && LIFE <= table::LIFE, "a client outlives no nameplate of its own");
    }

    #[cfg(feature = "code")]
    #[test]
    fn the_role_and_the_pairing_bind_one_appid() {
        assert_eq!(APPID, crate::code::APPID);
    }
}
