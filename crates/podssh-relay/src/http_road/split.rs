//! The split form (Q44): the caller's bytes up in numbered batches, one POST
//! after another on the session's first connection, and the target's bytes
//! down, each answer from the offset that came, on its second connection.
//! Each request goes again, as it was, until an answer comes.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use super::answer::Head;
use super::client::{closed, forgotten, gather, retry_after, End, Retry, Shared, LIMIT};
use super::conn::Conn;
use super::OFFSET;

/// How much longer than the wait that it asks an answer down may take.
const SLACK: Duration = Duration::from_secs(15);

/// The caller's bytes up, until its stream ends or the session does.
pub(super) async fn up(mut conn: Conn, s: Arc<Shared>, mut from_app: ReadHalf<DuplexStream>) {
    let mut buf = vec![0u8; s.batch];
    let mut seq: u64 = 0;
    loop {
        let (n, fin) = gather(&mut from_app, &mut buf).await;
        let query = if fin { format!("seq={seq}&fin=1") } else { format!("seq={seq}") };
        if let Err(end) = batch(&mut conn, &s, &s.path("up", &query), &buf[..n]).await {
            return s.end(end);
        }
        seq += 1;
        if fin || s.ended.get().is_some() {
            return;
        }
    }
}

/// One batch up, sent again until the role stored it.
pub(super) async fn batch(conn: &mut Conn, s: &Shared, path: &str, body: &[u8]) -> Result<(), End> {
    let head = s.request("POST", path, Some(body.len()));
    let mut tries = Retry::start();
    loop {
        let answer = match conn.ask(&head, body, LIMIT).await {
            Ok(answer) => answer,
            Err(e) => {
                tries.again(&e.to_string(), None).await?;
                continue;
            }
        };
        let words = conn.drop_body(&answer, LIMIT).await;
        s.heard(&answer);
        match answer.status {
            200 | 204 => return Ok(()),
            410 => return Err(closed(&answer)),
            404 => return Err(forgotten()),
            // The role's window is full, or a hop's own trouble: the same
            // batch again.
            408 | 429 | 502 | 503 | 504 => {
                tries.again(&format!("HTTP {} {words}", answer.status), retry_after(&answer)).await?
            }
            status => {
                return Err(End::Failed(format!("the relay refused a batch of the HTTP road: HTTP {status} {words}")))
            }
        }
    }
}

/// The target's bytes down to the caller, until the session ends or the
/// caller is gone.
pub(super) async fn down(mut conn: Conn, s: Arc<Shared>, mut to_app: WriteHalf<DuplexStream>) {
    let mut at: u64 = 0;
    let mut tries = Retry::start();
    let limit = s.wait + SLACK;
    let wait_ms = s.wait.as_millis();
    let end = loop {
        let head = s.request("GET", &s.path("down", &format!("at={at}&wait={wait_ms}")), None);
        let answer = match conn.ask(&head, &[], limit).await {
            Ok(answer) => answer,
            Err(e) => match tries.again(&e.to_string(), None).await {
                Ok(()) => continue,
                Err(end) => break end,
            },
        };
        s.heard(&answer);
        match answer.status {
            200 => {
                if answer.number(OFFSET) != Some(at) {
                    conn.after(false);
                    break End::Failed(format!("the relay sent the bytes of the HTTP road from another offset than {at}"));
                }
                let Some(came) = carried(&mut conn, &answer, &mut to_app, limit).await else { return };
                at += came;
                // A body cut before its first byte is no answer.
                if came > 0 {
                    tries.reset();
                } else if let Err(end) = tries.again("an answer down that a hop cut", None).await {
                    break end;
                }
            }
            204 => {
                conn.after(answer.keep);
                tries.reset();
            }
            410 => {
                let _ = conn.drop_body(&answer, LIMIT).await;
                break closed(&answer);
            }
            404 => break forgotten(),
            408 | 429 | 502 | 503 | 504 => {
                let words = conn.drop_body(&answer, LIMIT).await;
                let why = format!("HTTP {} {words}", answer.status);
                if let Err(end) = tries.again(&why, retry_after(&answer)).await {
                    break end;
                }
            }
            status => {
                let words = conn.drop_body(&answer, LIMIT).await;
                break End::Failed(format!("the relay refused the bytes down of the HTTP road: HTTP {status} {words}"));
            }
        }
    };
    s.end(end);
    let _ = to_app.shutdown().await;
}

/// The bytes of an answer down, to the caller as they come: how many came,
/// or `None` once the caller is gone. A body that stops for `limit` is cut.
async fn carried(
    conn: &mut Conn,
    answer: &Head,
    to_app: &mut WriteHalf<DuplexStream>,
    limit: Duration,
) -> Option<u64> {
    let mut came = 0u64;
    let mut whole = false;
    if let Some(mut body) = conn.body(answer) {
        loop {
            match tokio::time::timeout(limit, body.next()).await {
                Ok(Ok(Some(bytes))) => {
                    if to_app.write_all(&bytes).await.is_err() {
                        return None;
                    }
                    came += bytes.len() as u64;
                }
                Ok(Ok(None)) => {
                    whole = body.finished();
                    break;
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
    }
    conn.after(answer.keep && whole);
    Some(came)
}
