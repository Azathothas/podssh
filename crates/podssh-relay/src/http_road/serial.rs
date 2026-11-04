//! The serial form (Q44), the split form's fallback: one exchange after
//! another on one connection, each a POST that carries a batch up when one
//! waits, answered whole with the target's bytes from the offset that it
//! names, as meek carries Tor's bytes. With nothing either way, the pause
//! before the next exchange grows from 50 ms to the tuning's longest; a byte
//! either way makes it none.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::client::{closed, forgotten, gather_more, retry_after, End, Retry, Shared, LIMIT};
use super::conn::Conn;
use super::OFFSET;

/// The first pause after an exchange that carried nothing.
const PAUSE_FIRST: Duration = Duration::from_millis(50);

/// The session's exchanges, until it ends or the caller is gone.
pub(super) async fn run(mut conn: Conn, s: Arc<Shared>, ours: DuplexStream) {
    let (mut from_app, mut to_app) = tokio::io::split(ours);
    let mut buf = vec![0u8; s.batch];
    let (mut seq, mut at) = (0u64, 0u64);
    // A batch in `buf` that the role has not stored: its length, and whether
    // it is the last.
    let mut waiting: Option<(usize, bool)> = None;
    let mut open = true;
    let mut pause = Duration::ZERO;
    let mut tries = Retry::start();
    let end = loop {
        if waiting.is_none() && open {
            // The caller's bytes, or the pause with none.
            if let Ok(read) = tokio::time::timeout(pause, from_app.read(&mut buf)).await {
                let (n, fin) = match read {
                    Ok(0) | Err(_) => (0, true),
                    Ok(n) => gather_more(&mut from_app, &mut buf, n).await,
                };
                open = !fin;
                waiting = Some((n, fin));
            }
        } else if waiting.is_none() {
            tokio::time::sleep(pause).await;
        }
        let query = match waiting {
            Some((_, true)) => format!("seq={seq}&at={at}&wait=0&fin=1"),
            Some((_, false)) => format!("seq={seq}&at={at}&wait=0"),
            None => format!("at={at}&wait=0"),
        };
        let length = waiting.map_or(0, |(n, _)| n);
        let head = s.request("POST", &s.path("x", &query), Some(length));
        let answer = match conn.ask(&head, &buf[..length], LIMIT).await {
            Ok(answer) => answer,
            Err(e) => match tries.again(&e.to_string(), None).await {
                Ok(()) => continue,
                Err(end) => break end,
            },
        };
        s.heard(&answer);
        match answer.status {
            200 | 204 => {
                if answer.status == 200 && answer.number(OFFSET) != Some(at) {
                    conn.after(false);
                    break End::Failed(format!("the relay sent the bytes of the HTTP road from another offset than {at}"));
                }
                // The answer's head says that the role stored the batch, if
                // one went; the bytes of a body cut on the way come again
                // from the same offset.
                let took = waiting.take().is_some();
                if took {
                    seq += 1;
                }
                let came = match answer.status {
                    200 => match conn.whole(&answer, s.down_max, LIMIT).await {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            if let Err(end) = tries.again(&e.to_string(), None).await {
                                break end;
                            }
                            None
                        }
                    },
                    _ => {
                        conn.after(answer.keep);
                        Some(Vec::new())
                    }
                };
                let Some(came) = came else { continue };
                if !came.is_empty() {
                    if to_app.write_all(&came).await.is_err() {
                        return;
                    }
                    at += came.len() as u64;
                }
                tries.reset();
                pause = if took || !came.is_empty() { Duration::ZERO } else { next_pause(pause, s.poll_max) };
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
                break End::Failed(format!("the relay refused an exchange of the HTTP road: HTTP {status} {words}"));
            }
        }
    };
    s.end(end);
    let _ = to_app.shutdown().await;
}

/// The pause after `now`, in an exchange that carried nothing: 50 ms, then
/// half as long again each time, up to `most`.
fn next_pause(now: Duration, most: Duration) -> Duration {
    if now.is_zero() {
        PAUSE_FIRST
    } else {
        (now * 3 / 2).min(most).max(PAUSE_FIRST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pause_grows_from_50_ms_to_its_longest() {
        let most = Duration::from_secs(1);
        let mut pauses = vec![next_pause(Duration::ZERO, most)];
        for _ in 0..10 {
            pauses.push(next_pause(*pauses.last().unwrap(), most));
        }
        let ms: Vec<u128> = pauses.iter().map(Duration::as_millis).collect();
        assert_eq!(&ms[..4], &[50, 75, 112, 168]);
        assert_eq!(*ms.last().unwrap(), 1000);
    }
}
