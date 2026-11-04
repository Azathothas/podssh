//! The process's first thread, which waits while a thread of a larger stack
//! runs the command (`main.rs`). Linux keeps capabilities for each thread,
//! so what `podssh relay serve` gives up after its bind (T-629) must be
//! given up on this thread too, which holds what the process started with:
//! the command's thread sends the work here, and this thread runs it on
//! itself and answers.
//!
//! A command that runs with no first thread waiting (a test that calls the
//! dispatch in its own thread) gets no answer, and says so.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;

/// Work for the first thread.
type Job = Box<dyn FnOnce() + Send>;

enum Ask {
    Run(Job),
    /// The command's thread ended, by its return or by a panic.
    Ended,
}

/// The first thread's id and the way to it, while it waits.
type Way = (ThreadId, Sender<Ask>);

static FIRST: OnceLock<Mutex<Option<Way>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Way>> {
    FIRST.get_or_init(|| Mutex::new(None))
}

fn way() -> Option<Way> {
    slot().lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The first thread's end of the work, made on it before the command's
/// thread starts.
pub struct Waiter(Receiver<Ask>);

impl Waiter {
    pub fn new() -> Waiter {
        let (tx, rx) = mpsc::channel();
        *slot().lock().unwrap_or_else(PoisonError::into_inner) = Some((std::thread::current().id(), tx));
        Waiter(rx)
    }

    /// Until the command's `thread` ends: each job that it sends runs here.
    /// Its exit code, or 101 for a panic, which the thread said on stderr.
    pub fn wait(self, thread: JoinHandle<i32>) -> i32 {
        while let Ok(Ask::Run(job)) = self.0.recv() {
            job();
        }
        *slot().lock().unwrap_or_else(PoisonError::into_inner) = None;
        thread.join().unwrap_or(101)
    }
}

impl Default for Waiter {
    fn default() -> Self {
        Waiter::new()
    }
}

/// Held by the command's thread for its whole run: its drop, at the return
/// or in a panic's unwinding, ends the first thread's wait for work.
pub struct Ended;

impl Drop for Ended {
    fn drop(&mut self) {
        if let Some((_, tx)) = way() {
            let _ = tx.send(Ask::Ended);
        }
    }
}

/// What `job` gave on the first thread: run there and waited for `limit` at
/// most, or here when this thread is the first (its command's thread could
/// not start). `None` when no first thread waits, or it gave no answer in
/// time.
pub fn on_first<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static, limit: Duration) -> Option<T> {
    let (first, tx) = way()?;
    if first == std::thread::current().id() {
        return Some(job());
    }
    let (back, answer) = mpsc::channel();
    let job: Job = Box::new(move || {
        let _ = back.send(job());
    });
    tx.send(Ask::Run(job)).ok()?;
    answer.recv_timeout(limit).ok()
}

/// Whether a first thread waits for work now.
pub fn waits() -> bool {
    way().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test for the whole flow: the slot is the process's, so two tests
    // of it at once would share it.
    #[test]
    fn a_job_runs_on_the_first_thread_and_its_end_stops_the_wait() {
        let first = std::thread::spawn(move || {
            let waiter = Waiter::new();
            let me = std::thread::current().id();
            let command = std::thread::spawn(move || {
                let _ended = Ended;
                let ran_on = on_first(|| std::thread::current().id(), Duration::from_secs(5));
                i32::from(ran_on == Some(me))
            });
            waiter.wait(command)
        });
        assert_eq!(first.join().unwrap(), 1, "the job ran on the first thread");
        assert!(!waits(), "no first thread waits once the command ended");
        assert_eq!(on_first(|| 7, Duration::from_millis(50)), None, "no answer with no first thread");
    }
}
