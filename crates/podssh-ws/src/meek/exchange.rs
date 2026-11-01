//! One exchange of meek_lite: a POST of the bytes that wait, and the
//! bridge's bytes in the answer, over a connection to the front that is
//! kept between exchanges and opened again when it ends. A failure moves to
//! the next front, as lyrebird's `roundTrip` does: at once after a broken
//! connection, 100 ms later after a status other than 200.

use tokio::io::AsyncWriteExt as _;

use super::args::{Args, Front};
use super::{EXCHANGE_WAIT, MAX_PAYLOAD, MAX_TRIES, RETRY_DELAY};
use crate::http::Response;
use crate::pt::Reach;
use crate::url::Stream;

/// What one exchange brought.
enum Answer {
    /// Status 200: the bridge's bytes, maybe none.
    Bytes(Vec<u8>),
    /// Another status, and its reason.
    Refused(u16, String),
}

/// The client of a session: its fronts, its id, its connection.
pub(super) struct Client {
    fronts: Vec<Front>,
    at: usize,
    session: String,
    reach: Reach,
    conn: Option<Stream>,
}

impl Client {
    /// A client with a new session id, with no connection yet.
    pub(super) fn new(args: &Args, reach: Reach) -> Result<Client, String> {
        if args.fronts.is_empty() {
            return Err("a meek_lite bridge line names no URL".into());
        }
        Ok(Client { fronts: args.fronts.clone(), at: 0, session: super::session_id()?, reach, conn: None })
    }

    fn front(&self) -> &Front {
        &self.fronts[self.at % self.fronts.len()]
    }

    /// The URL and the front in use.
    pub(super) fn shown(&self) -> String {
        self.front().shown()
    }

    /// The next front; the connection goes with the front it reached.
    fn next_front(&mut self) {
        if self.fronts.len() > 1 {
            self.at = (self.at + 1) % self.fronts.len();
            self.conn = None;
        }
    }

    /// A connection to the front in use: TCP through the proxy, TLS for
    /// the front's name when the URL is `https://`.
    async fn connect(&mut self) -> Result<(), String> {
        let front = self.front().clone();
        let (host, port) = front.dial();
        let stream = crate::pt::open(&host, port, front.url.tls, &host, &self.reach).await?;
        self.conn = Some(stream);
        Ok(())
    }

    /// A connection to the first front that takes one, each tried once.
    pub(super) async fn connect_any(&mut self) -> Result<(), String> {
        let mut why = Vec::new();
        for _ in 0..self.fronts.len() {
            match self.connect().await {
                Ok(()) => return Ok(()),
                Err(e) => why.push(format!("{}: {e}", self.shown())),
            }
            self.next_front();
        }
        Err(why.join("; "))
    }

    /// `body` to the bridge, and the bridge's bytes: [`MAX_TRIES`]
    /// exchanges at most, each failure on the next front.
    pub(super) async fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let mut last = String::new();
        for _ in 0..MAX_TRIES {
            match self.post(body).await {
                Ok(Answer::Bytes(bytes)) => return Ok(bytes),
                Ok(Answer::Refused(status, reason)) => {
                    last = format!("{} answered {status} {reason}", self.shown());
                    self.next_front();
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(why) => {
                    last = format!("{}: {why}", self.shown());
                    self.conn = None;
                    self.next_front();
                }
            }
        }
        Err(format!("{last}, after {MAX_TRIES} exchanges"))
    }

    /// One POST of `body` and its answer, on the kept connection or a new
    /// one; a connection that the answer ends, or that failed, is dropped.
    async fn post(&mut self, body: &[u8]) -> Result<Answer, String> {
        if self.conn.is_none() {
            self.connect().await?;
        }
        let head = request(self.front(), &self.session, body.len());
        let Some(conn) = self.conn.as_mut() else { return Err("no connection".into()) };
        let exchanged = tokio::time::timeout(EXCHANGE_WAIT, async {
            conn.write_all(head.as_bytes()).await?;
            conn.write_all(body).await?;
            conn.flush().await?;
            crate::http::read_response(conn, Vec::new(), MAX_PAYLOAD).await
        })
        .await;
        let response = match exchanged {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                self.conn = None;
                return Err(e.to_string());
            }
            Err(_) => {
                self.conn = None;
                return Err(format!("no answer within {} s", EXCHANGE_WAIT.as_secs()));
            }
        };
        if !kept(&response) {
            self.conn = None;
        }
        match response.status {
            200 => Ok(Answer::Bytes(response.body)),
            status => Ok(Answer::Refused(status, response.reason)),
        }
    }
}

/// The head of a POST of `length` bytes, as Go's client writes lyrebird's:
/// `Host`, `Content-Length` (0 for a poll), the session's id, and no
/// `User-Agent`, which lyrebird sets empty so that Go sends none. No
/// `Accept-Encoding`: the body is Tor's TLS, which no CDN can shrink, and
/// no gzip is read here.
pub(super) fn request(front: &Front, session: &str, length: usize) -> String {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {length}\r\nX-Session-Id: {session}\r\n\r\n",
        front.url.target,
        front.host_header()
    )
}

/// Whether the connection serves another request after `response`: not
/// after `Connection: close`, nor after a body that ends with the
/// connection, which has no length of its own.
fn kept(response: &Response) -> bool {
    let closes =
        response.header("connection").is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
    let framed = response.header("content-length").is_some()
        || response.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    !closes && framed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_post_names_the_url_s_host_and_the_session_and_no_agent() {
        let pairs = [("url", "https://real.test/p?q=1"), ("front", "cdn.test")];
        let settings: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let args = Args::parse(&settings).unwrap();
        let head = request(&args.fronts[0], "0123456789abcdef0123456789abcdef", 5);
        assert_eq!(
            head,
            "POST /p?q=1 HTTP/1.1\r\nHost: real.test\r\nContent-Length: 5\r\n\
             X-Session-Id: 0123456789abcdef0123456789abcdef\r\n\r\n"
        );
        assert!(!head.to_ascii_lowercase().contains("user-agent"), "{head}");
    }

    #[test]
    fn a_connection_is_kept_after_a_framed_answer_alone() {
        let answer = |headers: &[(&str, &str)]| Response {
            status: 200,
            reason: "OK".into(),
            headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        };
        assert!(kept(&answer(&[("content-length", "0")])));
        assert!(kept(&answer(&[("transfer-encoding", "chunked")])));
        assert!(!kept(&answer(&[("content-length", "0"), ("connection", "close")])));
        assert!(!kept(&answer(&[])));
    }
}
