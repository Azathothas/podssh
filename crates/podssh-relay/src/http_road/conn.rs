//! A connection of the road to the relay host: HTTP/1.1, kept between
//! requests while the server and each hop keep it, and dialed again when it
//! ends. A request that a kept connection could not carry goes once more on
//! a new one, as each request of the road may come twice ([`super`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::ConnectError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::answer::{self, Body, Head};

/// A byte stream to the relay host.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, ConnectError>> + Send>>;
/// How to reach the relay host: TLS through the proxy, or a test's TCP.
pub type Dial = Arc<dyn Fn() -> Dialing + Send + Sync>;

/// The most bytes of an answer that the road reads whole and drops.
const DROPPED_MAX: usize = 64 * 1024;

/// One connection, or none until the next request.
pub struct Conn {
    dial: Dial,
    io: Option<BoxIo>,
    buf: Vec<u8>,
    /// How many times it was dialed.
    pub dials: u32,
}

impl Conn {
    pub fn new(dial: Dial) -> Conn {
        Conn { dial, io: None, buf: Vec::new(), dials: 0 }
    }

    /// Whether a connection is open now.
    pub fn open(&self) -> bool {
        self.io.is_some()
    }

    /// Dial now, unless a connection is open.
    pub async fn ready(&mut self, limit: Duration) -> Result<(), ConnectError> {
        if self.io.is_none() {
            let dialed = tokio::time::timeout(limit, (self.dial)())
                .await
                .map_err(|_| ConnectError::Timeout { step: "the connection to the relay host", after: limit })??;
            self.io = Some(dialed);
            self.buf.clear();
            self.dials += 1;
        }
        Ok(())
    }

    /// `head` and `body`, then the head of the answer, each step within
    /// `limit`: once on the connection that is kept, and once more on a new
    /// one when the kept one failed.
    pub async fn ask(&mut self, head: &[u8], body: &[u8], limit: Duration) -> Result<Head, ConnectError> {
        let kept = self.io.is_some();
        match self.once(head, body, limit).await {
            Err(_) if kept => self.once(head, body, limit).await,
            asked => asked,
        }
    }

    async fn once(&mut self, head: &[u8], body: &[u8], limit: Duration) -> Result<Head, ConnectError> {
        self.ready(limit).await?;
        let Some(io) = self.io.as_mut() else { return Err(ConnectError::Http("no connection".into())) };
        let buf = &mut self.buf;
        let exchanged = tokio::time::timeout(limit, async {
            io.write_all(head).await.map_err(|e| e.to_string())?;
            io.write_all(body).await.map_err(|e| e.to_string())?;
            io.flush().await.map_err(|e| e.to_string())?;
            answer::read_head(io, buf).await
        })
        .await;
        match exchanged {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(why)) => {
                self.drop_io();
                Err(ConnectError::Http(why))
            }
            Err(_) => {
                self.drop_io();
                Err(ConnectError::Timeout { step: "an answer of the HTTP road", after: limit })
            }
        }
    }

    /// The body of the answer of `head`, as it comes; `None` with no
    /// connection.
    pub fn body(&mut self, head: &Head) -> Option<Body<'_, BoxIo>> {
        let io = self.io.as_mut()?;
        Some(Body::new(io, &mut self.buf, head.framing))
    }

    /// The whole body of the answer of `head`, `cap` bytes at most, within
    /// `limit`; then the connection goes on when the answer keeps it.
    pub async fn whole(&mut self, head: &Head, cap: usize, limit: Duration) -> Result<Vec<u8>, ConnectError> {
        let (read, finished) = match self.body(head) {
            Some(mut body) => {
                let read = tokio::time::timeout(limit, body.all(cap)).await;
                (read, body.finished())
            }
            None => return Err(ConnectError::Http("no connection".into())),
        };
        let read = match read {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(why)) => Err(ConnectError::Http(why)),
            Err(_) => Err(ConnectError::Timeout { step: "an answer's body of the HTTP road", after: limit }),
        };
        self.after(head.keep && finished && read.is_ok());
        read
    }

    /// The body of an answer whose words matter little: read and dropped,
    /// so that the connection may go on.
    pub async fn drop_body(&mut self, head: &Head, limit: Duration) -> String {
        match self.whole(head, DROPPED_MAX, limit).await {
            Ok(bytes) => podssh_ws::text::one_line(&String::from_utf8_lossy(&bytes)),
            Err(_) => String::new(),
        }
    }

    /// After an answer: the connection goes on only when `keep`.
    pub fn after(&mut self, keep: bool) {
        if !keep {
            self.drop_io();
        }
    }

    fn drop_io(&mut self) {
        self.io = None;
        self.buf.clear();
    }
}

/// A request's head. `authority`, `path` and each header are the road's own
/// words or checked by the caller, with no line break.
pub fn request(method: &str, authority: &str, path: &str, headers: &[(&str, &str)], length: Option<usize>) -> Vec<u8> {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\nAccept-Encoding: identity\r\n\
         Cache-Control: no-store\r\n",
        super::USER_AGENT
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(length) = length {
        head.push_str(&format!("Content-Length: {length}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_names_its_host_its_headers_and_its_length() {
        let head = String::from_utf8(request("POST", "relay.test", "/v1/http/s/x/up?seq=0", &[("X-A", "b")], Some(3)))
            .unwrap();
        assert!(head.starts_with("POST /v1/http/s/x/up?seq=0 HTTP/1.1\r\nHost: relay.test\r\n"), "{head}");
        assert!(head.contains("\r\nX-A: b\r\nContent-Length: 3\r\n\r\n") && head.ends_with("\r\n\r\n"), "{head}");
        let get = String::from_utf8(request("GET", "relay.test", "/", &[], None)).unwrap();
        assert!(!get.to_ascii_lowercase().contains("content-length"), "{get}");
    }

    /// A kept connection that the server closed while it was idle carries
    /// the request on a new one, which a dial counts.
    #[tokio::test]
    async fn a_request_on_a_connection_that_closed_goes_again_on_a_new_one() {
        let served = Arc::new(std::sync::Mutex::new(0u32));
        let count = served.clone();
        let dial: Dial = Arc::new(move || -> Dialing {
            let count = count.clone();
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(4096);
                let first = {
                    let mut n = count.lock().unwrap();
                    *n += 1;
                    *n == 1
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut theirs = theirs;
                    let mut got = vec![0u8; 4096];
                    let _ = theirs.read(&mut got).await;
                    if !first {
                        let _ = theirs.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    }
                });
                Ok(Box::new(ours) as BoxIo)
            })
        });
        let mut conn = Conn::new(dial);
        conn.ready(Duration::from_secs(5)).await.unwrap();
        let head = request("GET", "relay.test", "/", &[], None);
        let answer = conn.ask(&head, &[], Duration::from_secs(5)).await.unwrap();
        assert_eq!((answer.status, conn.dials), (204, 2));
    }
}
