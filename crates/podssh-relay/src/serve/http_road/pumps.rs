//! The target of a session of the HTTP road: its bytes read into the
//! session's window down, which bounds them, and the batches up written to
//! it in order, each once; after the last batch, TCP's half-close, which
//! the WebSocket road cannot give. Each write waits for the target, so a
//! slow target fills the window up, and the client's next batch waits.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::sessions::{self, Session, DOWN_WINDOW};

/// The bytes asked of the target in each read.
const READ: usize = 64 * 1024;

/// The tasks of `session`'s target `tcp`, and of its limits.
pub fn start(session: &Arc<Session>, tcp: TcpStream) {
    let (from, to) = tcp.into_split();
    let writer = tokio::spawn(write_up(session.clone(), to));
    let reader = tokio::spawn(read_down(session.clone(), from));
    tokio::spawn(sessions::watch(session.clone()));
    session.set_tasks(vec![writer.abort_handle(), reader.abort_handle()]);
}

/// What the writer does next.
enum Step {
    Stop,
    Wait,
    Write(Vec<u8>),
    Finish,
}

async fn write_up(session: Arc<Session>, mut to: OwnedWriteHalf) {
    loop {
        let notified = session.changed.notified();
        let step = session.with(|st| {
            if st.ended.is_some() {
                Step::Stop
            } else if let Some(batch) = st.queue.pop_front() {
                Step::Write(batch)
            } else if st.fin {
                Step::Finish
            } else {
                Step::Wait
            }
        });
        match step {
            Step::Stop => return,
            Step::Wait => notified.await,
            Step::Finish => {
                let _ = to.shutdown().await;
                return;
            }
            Step::Write(batch) => {
                if let Err(e) = to.write_all(&batch).await {
                    return session.end(1011, format!("write failed: {e}"));
                }
                session.meter.up(batch.len());
                session.with(|st| {
                    st.written += 1;
                    st.moved += batch.len() as u64;
                    if !batch.is_empty() {
                        st.heard = Instant::now();
                    }
                });
                session.changed.notify_waiters();
            }
        }
    }
}

async fn read_down(session: Arc<Session>, mut from: OwnedReadHalf) {
    let mut buf = vec![0u8; READ];
    loop {
        // Room first: the target waits while its bytes wait for the client.
        loop {
            let notified = session.changed.notified();
            let room = session.with(|st| st.ended.is_none().then_some(st.down.len() < DOWN_WINDOW));
            match room {
                None => return,
                Some(true) => break,
                Some(false) => notified.await,
            }
        }
        match from.read(&mut buf).await {
            Ok(0) => {
                session.with(|st| st.target_ended = true);
                session.changed.notify_waiters();
                return;
            }
            Ok(n) => {
                // The client's due, whether or not it fetches them.
                session.meter.down(n);
                session.with(|st| {
                    st.down.extend(&buf[..n]);
                    st.moved += n as u64;
                    st.heard = Instant::now();
                });
                session.changed.notify_waiters();
            }
            Err(e) => return session.end(1011, format!("target read failed: {e}")),
        }
    }
}
