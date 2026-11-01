//! The worker of a session, as lyrebird's `ioWorker`: it waits for bytes of
//! the local side or for the poll's time, joins what is ready up to one body,
//! sends it, and gives the answer's bytes back; the bytes past one body go in
//! the next request. The poll's wait is none after any byte either way, and
//! grows while nothing moves ([`super::next_poll`]).

use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use super::exchange::Client;
use super::{next_poll, INIT_POLL, MAX_PAYLOAD};

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The local side ended, or went.
    Closed,
    /// The exchanges failed: the last failure, which names the front.
    Failed(String),
}

impl Ended {
    /// The failure, if the session ended with one.
    pub fn failure(&self) -> Option<&str> {
        match self {
            Ended::Closed => None,
            Ended::Failed(why) => Some(why),
        }
    }
}

/// Carry `local` over `client`'s exchanges until either ends.
pub(super) async fn run<S: AsyncRead + AsyncWrite + Unpin>(mut client: Client, mut local: S) -> Ended {
    let mut wait = INIT_POLL;
    let mut waiting: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut open = true;
    loop {
        if waiting.is_empty() {
            if !open {
                return Ended::Closed;
            }
            tokio::select! {
                read = local.read(&mut buf) => match read {
                    Ok(0) | Err(_) => open = false,
                    Ok(n) => waiting.extend_from_slice(&buf[..n]),
                },
                () = tokio::time::sleep(wait) => {}
            }
            // The local side ended with nothing to send: no last poll.
            if !open && waiting.is_empty() {
                return Ended::Closed;
            }
        }
        // Short writes are joined while more is ready at once, up to a body.
        while open && waiting.len() < MAX_PAYLOAD {
            let room = MAX_PAYLOAD - waiting.len();
            match ready_now(&mut local, &mut buf[..room]).await {
                Some(Ok(0)) | Some(Err(_)) => open = false,
                Some(Ok(n)) => waiting.extend_from_slice(&buf[..n]),
                None => break,
            }
        }
        let sent = waiting.len().min(MAX_PAYLOAD);
        let answer = match client.round_trip(&waiting[..sent]).await {
            Ok(answer) => answer,
            Err(why) => return Ended::Failed(why),
        };
        waiting.drain(..sent);
        if !answer.is_empty() {
            let given = async {
                local.write_all(&answer).await?;
                local.flush().await
            };
            if given.await.is_err() {
                return Ended::Closed;
            }
        }
        wait = match (answer.is_empty(), sent) {
            (false, _) | (true, 1..) => Duration::ZERO,
            (true, 0) => next_poll(wait),
        };
    }
}

/// The bytes of `local` that are there now, without waiting: `None` when
/// none are, as Go's `len(chan) > 0` asks.
async fn ready_now<S: AsyncRead + Unpin>(local: &mut S, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
    std::future::poll_fn(|cx| {
        let mut read = ReadBuf::new(&mut buf[..]);
        match Pin::new(&mut *local).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(read.filled().len()))),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Ready(None),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes already in a pipe are read at once; an empty pipe gives none
    /// without waiting, and a closed one its end.
    #[tokio::test]
    async fn what_is_ready_is_read_without_a_wait() {
        let (mut near, mut far) = tokio::io::duplex(64);
        let mut buf = [0u8; 16];
        assert!(ready_now(&mut far, &mut buf).await.is_none());
        near.write_all(b"ready").await.unwrap();
        assert_eq!(ready_now(&mut far, &mut buf).await.unwrap().unwrap(), 5);
        assert_eq!(&buf[..5], b"ready");
        drop(near);
        assert_eq!(ready_now(&mut far, &mut buf).await.unwrap().unwrap(), 0);
    }
}
