//! ⛔ **Shared test helpers. ⛔ No `Cargo.toml` change, no new dependency.**
//!
//! ⛔ **`futures_util::executor` is not compiled in.** The workspace declares
//! `futures-util` with `default-features = false` and features `std` + `sink`
//! (`Cargo.toml` at the root, which ⛔ this entry does not own), so the blocking
//! executor is unavailable and each test file needs its own ten lines rather
//! than a dependency change that another entry owns.
//!
//! ⛔ **The futures this drives are pure** — a send and a recv against a queue —
//! so a no-op waker cannot deadlock them. ⛔ That is why a hand-rolled executor is
//! safe here and would **not** be safe behind a socket.

// Each test binary uses part of these helpers.
#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

/// ⛔ **Drive a future to completion on this thread.**
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

pub mod dns;

/// ⛔ **A 32-lowercase-hex session id, written out.** ⛔ Not `"0".repeat(32)`,
/// because a repeated digit is the shape a mistake produces and it would hide
/// one.
pub const ID_HEX: &str = "0123456789abcdef0123456789abcdef";

pub fn id() -> podssh_transport::framing::SessionId {
    podssh_transport::framing::SessionId::parse(ID_HEX.as_bytes())
        .expect("the test id is 32 lowercase hex")
}
