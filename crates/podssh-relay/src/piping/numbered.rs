//! The numbered form of a link, for a proxy that holds a request's body
//! until its end, or an answer's: each way is a POST of a whole piece to
//! `PATH-N`, N from 0, one after another, and the far end GETs `PATH-0`,
//! `PATH-1`, ... in turn. Each request has a length, so a proxy that holds a
//! body holds one piece, and lets it go whole. Piece 0 is the way's mark. A
//! sender waits for the server's answer to each piece, which ends once the
//! receiver took it, so one piece of each way is in flight; the layer's
//! heartbeat sends a piece each 10 s, so a GET never waits long for the next.
//!
//! A POST that fails ends the link, as its piece may have gone or not; the
//! layer sends again what the far end did not acknowledge, on the next link.
//! A GET that got no answer is asked again: the far end's piece waits.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::exchange::{delivered, Failed, Http};
use super::flow::{check_mark, Link, Opening, HELLO_LIMIT, PIPE};
use super::paths::{Ends, MARK_BYTES};

/// The most bytes of a piece.
pub const PIECE: usize = 64 * 1024;
/// How long a POST of a piece may wait for its receiver.
const POST_WAIT: Duration = Duration::from_secs(60);
/// How long a GET may wait for the next piece: the far end's heartbeat sends
/// one each 10 s, so this long with none is a far end that is gone.
const GET_WAIT: Duration = Duration::from_secs(120);
/// How many times a GET that got no answer is asked again, and the pause
/// before each.
const TRIES: u32 = 5;
const PAUSE: Duration = Duration::from_secs(1);

/// The path of piece `n` of the way of `word`.
fn piece(http: &Http, word: &str, n: u64) -> String {
    http.server().path(&format!("{word}-{n}"))
}

/// A numbered link of `ends` on `http`'s server: piece 0 of each way, the
/// marks, within [`HELLO_LIMIT`]; then a task for the pieces after them.
pub async fn open(http: Arc<Http>, ends: &Ends) -> Result<Link, Opening> {
    let (send, recv) = (piece(&http, &ends.send, 0), piece(&http, &ends.recv, 0));
    let first = async {
        let sending = async {
            let text = http.post(&send, &ends.mine, HELLO_LIMIT).await?;
            delivered(&text).map_err(Failed::lost)
        };
        let receiving = receive(&http, &recv, HELLO_LIMIT);
        let ((), got) = tokio::try_join!(sending, receiving).map_err(Opening::from)?;
        if got.len() != MARK_BYTES {
            return Err(Opening::Failed(format!("the far end's first piece is {} bytes, not its mark", got.len())));
        }
        check_mark(&got, ends)
    };
    match tokio::time::timeout(HELLO_LIMIT, first).await {
        Ok(opened) => opened?,
        Err(_) => {
            let why = format!("no mark of the far end within {} s, in numbered pieces", HELLO_LIMIT.as_secs());
            return Err(Opening::Failed(why));
        }
    }
    Ok(carry(http, ends.send.clone(), ends.recv.clone()))
}

/// The whole of piece `path`, asked again while no answer comes.
async fn receive(http: &Http, path: &str, wait: Duration) -> Result<Vec<u8>, Failed> {
    let mut tries = 0;
    loop {
        match http.get_all(path, Some(wait), PIECE).await {
            Err(failed) if failed.again() && tries < TRIES => {
                tries += 1;
                tokio::time::sleep(PAUSE).await;
            }
            done => return done,
        }
    }
}

/// A task that carries the pipe's far end in numbered pieces from 1.
fn carry(http: Arc<Http>, send: String, recv: String) -> Link {
    let (ours, far) = tokio::io::duplex(PIPE);
    let task = tokio::spawn(async move {
        let (mut from_layer, mut to_layer) = tokio::io::split(far);
        // True when the layer ended its bytes.
        let up = async {
            let mut buf = vec![0u8; PIECE];
            for n in 1u64.. {
                let read = match from_layer.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(read) => read,
                    Err(_) => return false,
                };
                let sent = http.post(&piece(&http, &send, n), &buf[..read], POST_WAIT).await;
                if sent.map_err(|failed| failed.to_string()).and_then(|text| delivered(&text)).is_err() {
                    return false;
                }
            }
            false
        };
        let down = async {
            for n in 1u64.. {
                match receive(&http, &piece(&http, &recv, n), GET_WAIT).await {
                    Ok(bytes) if !bytes.is_empty() => {
                        if to_layer.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    _ => break,
                }
            }
            let _ = to_layer.shutdown().await;
        };
        tokio::pin!(down);
        let clean = tokio::select! {
            clean = up => clean,
            () = &mut down => return,
        };
        if clean {
            down.await;
        }
    });
    Link::new(ours, task.abort_handle())
}
