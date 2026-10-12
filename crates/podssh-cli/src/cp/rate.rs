//! The limit of a copy's bandwidth (T-145): `-l LIMIT` in Kbit/s, as
//! OpenSSH's `scp` and `sftp` take it. A token bucket: each data request
//! takes its bytes before it goes, and waits for them at the limit's rate.
//! The run has one bucket, which each copy of it shares.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A token bucket of `rate` bytes a second, which holds a quarter of a
/// second of them at most.
#[derive(Debug)]
pub struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// A bucket of `kbits` Kbit/s (1000 bits), empty: the first bytes wait
    /// for their time too.
    pub fn of_kbits(kbits: u64) -> Bucket {
        Bucket { rate: kbits as f64 * 1000.0 / 8.0, tokens: 0.0, last: Instant::now() }
    }

    /// The bytes a second.
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Take `n` bytes at `now`: how long to wait before they may go.
    pub fn take_at(&mut self, n: u64, now: Instant) -> Duration {
        let cap = (self.rate / 4.0).max(n as f64);
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(cap);
        self.last = now;
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

static BUCKET: Mutex<Option<Bucket>> = Mutex::new(None);

/// The run's limit, from `-l`; none without it.
pub fn set(kbits: Option<u64>) {
    *BUCKET.lock().unwrap() = kbits.map(Bucket::of_kbits);
}

/// The bytes a second of the run's limit, if it has one.
pub fn limit() -> Option<f64> {
    BUCKET.lock().unwrap().as_ref().map(Bucket::rate)
}

/// Wait until `n` bytes may go, at the run's limit; at once with none.
pub async fn take(n: u64) {
    let wait = BUCKET.lock().unwrap().as_mut().map(|b| b.take_at(n, Instant::now()));
    if let Some(wait) = wait.filter(|w| !w.is_zero()) {
        tokio::time::sleep(wait).await;
    }
}

/// The bytes of each request under a limit of `rate` bytes a second: a
/// request ends well inside the 60 s that a reply may take (10 s at the
/// limit), and is never less than 1 KiB.
pub fn request_len(rate: f64, len: u32) -> u32 {
    ((rate * 10.0) as u64).clamp(1024, u64::from(len)) as u32
}

/// The requests in flight under a limit of `rate` bytes a second: about one
/// second of bytes, one at least.
pub fn requests(rate: f64, len: u32) -> usize {
    ((rate / f64::from(len.max(1))).ceil() as usize).max(1)
}

/// `pipe` under the run's limit: requests of about ten seconds of bytes at
/// most, under the server's size `limit`, and one second of them in flight.
pub fn shaped(pipe: podssh_ssh::sftp::Pipeline, limit: u32) -> podssh_ssh::sftp::Pipeline {
    match self::limit() {
        None => pipe,
        Some(rate) => {
            let len = request_len(rate, pipe.len_under(limit));
            podssh_ssh::sftp::Pipeline { len, requests: requests(rate, len).min(pipe.requests), ..pipe }
        }
    }
}

/// The value of `-l`: Kbit/s, 1 or more.
pub fn parse(flag: &str, text: &str) -> Result<u64, String> {
    match text.trim().parse::<u64>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(format!("{flag} {text}: give the limit in Kbit/s, 1 or more")),
    }
}
