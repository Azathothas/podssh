//! The client of the road: the open, then the tasks of the session in the
//! split form (`split.rs`) or the serial form (`serial.rs`),
//! between a pipe in memory, whose other end is the caller's stream, and the
//! relay host. With no form asked, the split form is tried first: its second
//! connection must answer a first request within a bound, else the session
//! goes on in the serial form on the first connection (Q44).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::{ConnectError, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, DuplexStream};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::answer::Head;
use super::conn::{request, BoxIo, Conn, Dial, Dialing};
use super::{is_id, is_key, Form, Tuning, DOWN_MAX, KEY, OPEN, SESSION, WAIT_MAX};
use crate::relay::Relay;

/// The bound of each step of the open, and of the split form's first
/// request on its second connection.
pub const LIMIT: Duration = Duration::from_secs(20);
/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;
/// The longest answer to the open.
const OPEN_ANSWER_MAX: usize = 16 * 1024;
/// How long more bytes of the caller may take to join a batch.
const GATHER: Duration = Duration::from_millis(2);
/// How long a request is tried again with no answer before the session ends.
pub const RETRY_FOR: Duration = Duration::from_secs(60);
/// The first pause between two tries, which doubles to [`PAUSE_MAX`].
const PAUSE_FIRST: Duration = Duration::from_millis(100);
const PAUSE_MAX: Duration = Duration::from_secs(2);

/// Where the road goes: how to reach the relay host, and its name in `Host`.
#[derive(Clone)]
pub struct Road {
    pub dial: Dial,
    pub authority: String,
}

impl Road {
    /// TLS to `relay` through `proxy`, checked with `trust`, as the
    /// WebSocket road reaches it.
    pub fn tls(relay: &Relay, trust: &Trust, proxy: &ProxyChoice, limit: Duration) -> Road {
        let (host, port, trust, proxy) = (relay.host.clone(), relay.port, trust.clone(), proxy.clone());
        let dial: Dial = Arc::new(move || -> Dialing {
            let (host, trust, proxy) = (host.clone(), trust.clone(), proxy.clone());
            Box::pin(async move {
                let tls = podssh_ws::client::open_tls(&host, port, &host, &trust, &proxy, limit).await?;
                Ok(Box::new(tls) as BoxIo)
            })
        });
        let authority =
            if relay.port == 443 { relay.host.clone() } else { podssh_ws::dial::authority(&relay.host, relay.port) };
        Road { dial, authority }
    }
}

/// The target of a session.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    /// 4 or 6, as `?family` asks the role.
    pub family: Option<u8>,
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The role's `X-Close`: the forward road's code and reason.
    Closed { code: u16, reason: String },
    /// The road failed: why.
    Failed(String),
}

/// The end of a session, once it came; the first word wins.
#[derive(Debug, Default)]
pub struct Ended(Mutex<Option<End>>);

impl Ended {
    pub fn set_once(&self, end: End) {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(end);
        }
    }

    pub fn get(&self) -> Option<End> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// An open session: the caller's end of the pipe, the session's end once it
/// comes, and the form that carries it.
pub struct Opened {
    pub stream: DuplexStream,
    pub ended: Arc<Ended>,
    pub form: Form,
}

/// What the tasks of one session share.
pub(super) struct Shared {
    pub id: String,
    /// Sent in a header alone, never in a URL.
    pub key: Zeroizing<String>,
    pub authority: String,
    pub batch: usize,
    pub wait: Duration,
    pub down_max: usize,
    pub poll_max: Duration,
    pub ended: Arc<Ended>,
    /// The role's last `X-Ack`: the batches that the target took.
    pub acked: AtomicU64,
}

impl Shared {
    /// The path of `what` of this session, with `query`.
    pub fn path(&self, what: &str, query: &str) -> String {
        format!("{SESSION}{}/{what}?{query}", self.id)
    }

    /// A request of this session, with its key.
    pub fn request(&self, method: &str, path: &str, length: Option<usize>) -> Vec<u8> {
        request(method, &self.authority, path, &[(KEY, self.key.as_str())], length)
    }

    /// What an answer says of the batches that the target took.
    pub fn heard(&self, answer: &Head) {
        if let Some(acked) = answer.number(super::ACK) {
            self.acked.fetch_max(acked, Ordering::Relaxed);
        }
    }

    pub fn end(&self, end: End) {
        self.ended.set_once(end);
    }
}

/// The end that a `410` says, or a failure that names it.
pub(super) fn closed(answer: &Head) -> End {
    match answer.header(super::CLOSE).and_then(super::parse_close) {
        Some((code, reason)) => End::Closed { code, reason },
        None => End::Failed("the relay ended the session of the HTTP road, and said no reason".into()),
    }
}

/// The failure that a `404` of a session says.
pub(super) fn forgotten() -> End {
    End::Failed("the relay no longer knows the session of the HTTP road: it may have restarted".into())
}

/// The tries of a request after it failed: a pause that doubles from 100 ms
/// to 2 s, for [`RETRY_FOR`] since the last answer at most.
pub(super) struct Retry {
    since: Instant,
    pause: Duration,
}

impl Retry {
    pub fn start() -> Retry {
        Retry { since: Instant::now(), pause: PAUSE_FIRST }
    }

    /// An answer came.
    pub fn reset(&mut self) {
        *self = Retry::start();
    }

    /// The pause before the next try, `at_least` as a server asked; `Err`
    /// once the tries ran past their bound, with `why`.
    pub async fn again(&mut self, why: &str, at_least: Option<Duration>) -> Result<(), End> {
        if self.since.elapsed() >= RETRY_FOR {
            let secs = RETRY_FOR.as_secs();
            return Err(End::Failed(format!("the HTTP road had no answer in {secs} s: {why}")));
        }
        tokio::time::sleep(at_least.map_or(self.pause, |asked| asked.max(self.pause))).await;
        self.pause = (self.pause * 2).min(PAUSE_MAX);
        Ok(())
    }
}

/// The seconds of `Retry-After`, 5 at most.
pub(super) fn retry_after(answer: &Head) -> Option<Duration> {
    answer.number("retry-after").map(|s| Duration::from_secs(s.min(5)))
}

/// The next batch of the caller's bytes into `buf`: what the first read
/// gives, and what more comes within a moment, up to `buf`'s size. `true`
/// with it once the caller's stream ended.
pub(super) async fn gather<R: AsyncRead + Unpin>(from: &mut R, buf: &mut [u8]) -> (usize, bool) {
    match from.read(buf).await {
        Ok(0) | Err(_) => (0, true),
        Ok(n) => gather_more(from, buf, n).await,
    }
}

/// [`gather`] after its first `n` bytes.
pub(super) async fn gather_more<R: AsyncRead + Unpin>(from: &mut R, buf: &mut [u8], mut n: usize) -> (usize, bool) {
    while n < buf.len() {
        match tokio::time::timeout(GATHER, from.read(&mut buf[n..])).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (n, true),
            Ok(Ok(more)) => n += more,
            Err(_) => break,
        }
    }
    (n, false)
}

/// The path of the open of `target`, checked as the forward road's.
fn open_path(target: &Target<'_>) -> Result<String, ConnectError> {
    let forward = crate::relay::forward_path(target.host, target.port).map_err(ConnectError::Config)?;
    let mut path = forward.replacen("/connect/", OPEN, 1);
    if let Some(family) = target.family {
        path.push_str(&format!("?family={family}"));
    }
    Ok(path)
}

/// Open a session to `target` on `road` with `token`, in `form`, or the
/// split form, then the serial one, when none is asked. A refusal of the
/// role keeps its status and words, as the WebSocket road's does.
pub async fn open(
    road: &Road,
    target: &Target<'_>,
    token: &str,
    form: Option<Form>,
    tuning: Tuning,
) -> Result<Opened, ConnectError> {
    if token.contains(['\r', '\n']) {
        return Err(ConnectError::Config("the relay token contains a line break".into()));
    }
    let path = open_path(target)?;
    let mut first = Conn::new(road.dial.clone());
    let head = request("POST", &road.authority, &path, &[("X-Relay-Token", token)], Some(0));
    let answer = first.ask(&head, &[], LIMIT).await?;
    let body = first.whole(&answer, OPEN_ANSWER_MAX, LIMIT).await?;
    if answer.status != 200 {
        let words = podssh_ws::text::one_line(&String::from_utf8_lossy(&body));
        let words: String = words.chars().take(200).collect();
        let body = if words.is_empty() { answer.reason.clone() } else { words };
        return Err(ConnectError::Refused { status: answer.status, body });
    }
    let doc: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| ConnectError::Http(format!("the answer to the open of the HTTP road: {e}")))?;
    let id = doc["session"].as_str().filter(|id| is_id(id));
    let key = doc["key"].as_str().filter(|key| is_key(key));
    let (Some(id), Some(key)) = (id, key) else {
        return Err(ConnectError::Http("the answer to the open of the HTTP road names no session".into()));
    };
    let bound = |name: &str, most: u64| doc[name].as_u64().filter(|n| *n > 0).unwrap_or(most).min(most);
    let shared = Arc::new(Shared {
        id: id.to_string(),
        key: Zeroizing::new(key.to_string()),
        authority: road.authority.clone(),
        batch: tuning.batch.min(bound("batch_max", super::BATCH_MAX as u64) as usize).max(1),
        wait: tuning.wait.min(Duration::from_millis(bound("wait_max_ms", WAIT_MAX.as_millis() as u64))),
        down_max: bound("down_max", DOWN_MAX as u64) as usize,
        poll_max: tuning.poll_max,
        ended: Arc::default(),
        acked: AtomicU64::new(0),
    });
    let (app, ours) = tokio::io::duplex(PIPE);
    let chosen = match form {
        Some(Form::Serial) => None,
        Some(Form::Split) => Some(Conn::new(road.dial.clone())),
        None => second(road, &shared).await,
    };
    let form = match chosen {
        Some(second) => {
            let (from_app, to_app) = tokio::io::split(ours);
            tokio::spawn(super::split::up(first, shared.clone(), from_app));
            tokio::spawn(super::split::down(second, shared.clone(), to_app));
            Form::Split
        }
        None => {
            tokio::spawn(super::serial::run(first, shared.clone(), ours));
            Form::Serial
        }
    };
    Ok(Opened { stream: app, ended: shared.ended.clone(), form })
}

/// The split form's second connection, once it answered a first request
/// within [`LIMIT`]: a request of the bytes down with no wait, whose bytes
/// the next one asks again, as none is acknowledged by it.
async fn second(road: &Road, shared: &Shared) -> Option<Conn> {
    let mut conn = Conn::new(road.dial.clone());
    let head = shared.request("GET", &shared.path("down", "at=0&wait=0"), None);
    let answer = conn.ask(&head, &[], LIMIT).await.ok()?;
    let _ = conn.drop_body(&answer, LIMIT).await;
    matches!(answer.status, 200 | 204 | 410).then_some(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_open_s_path_is_the_forward_road_s_under_the_road_s_prefix() {
        let to = |host, port, family| open_path(&Target { host, port, family }).unwrap();
        assert_eq!(to("github.com", 22, None), "/v1/http/open/github.com/22");
        assert_eq!(to("2001:db8::1", 22, Some(6)), "/v1/http/open/2001:db8::1/22?family=6");
        assert!(open_path(&Target { host: "a/b", port: 22, family: None }).is_err());
        assert!(open_path(&Target { host: "h", port: 0, family: None }).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn the_tries_pause_longer_each_time_and_end_at_their_bound() {
        let mut tries = Retry::start();
        let started = Instant::now();
        tries.again("x", None).await.unwrap();
        tries.again("x", Some(Duration::from_secs(1))).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(1100));
        tokio::time::sleep(RETRY_FOR).await;
        let failed = tries.again("the last error", None).await.unwrap_err();
        assert!(matches!(&failed, End::Failed(why) if why.contains("the last error")), "{failed:?}");
        tries.reset();
        assert!(tries.again("x", None).await.is_ok());
    }

    #[tokio::test]
    async fn a_batch_takes_what_comes_at_once_and_says_the_end() {
        use tokio::io::AsyncWriteExt;
        let (mut near, mut far) = tokio::io::duplex(1024);
        near.write_all(b"abc").await.unwrap();
        near.write_all(b"def").await.unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(gather(&mut far, &mut buf).await, (4, false));
        drop(near);
        let mut rest = [0u8; 8];
        assert_eq!(gather(&mut far, &mut rest).await, (2, true));
        assert_eq!(&rest[..2], b"ef");
        assert_eq!(gather(&mut far, &mut rest).await, (0, true));
    }
}
