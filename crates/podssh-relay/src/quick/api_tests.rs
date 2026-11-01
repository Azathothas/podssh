//! The reply of the API, its refusals, and the requests asked again after a
//! refusal for now, on a paused clock (T-401).

use std::cell::{Cell, RefCell};

use super::*;
use podssh_ws::http::Response;

/// A reply of the shape that T-299 measured: 36 characters of id, 32 of
/// account tag, and the base64 of 32 bytes of secret (made up here).
fn reply(hostname: &str) -> String {
    let secret = STANDARD.encode([7u8; 32]);
    format!(
        r#"{{"success":true,"errors":[],"result":{{"id":"8e9d2f0c-4b1a-4f6e-9c3d-5a7b2e1f0d4c","name":"qt-x","hostname":"{hostname}","account_tag":"0123456789abcdef0123456789abcdef","secret":"{secret}"}}}}"#
    )
}

/// cfrs's GitHub #42: the API's answer, captured with curl through a
/// CONNECT proxy at 15:17 UTC on 2026-10-31, after about eight tunnels in
/// 20 minutes. The capture was of HTTP/2 and kept its status, its
/// Retry-After and its body; here they are in HTTP/1.1, the form that
/// podssh reads, with the length that HTTP/1.1 needs and no other header.
const CFRS_42: &[u8] =
    b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 2994\r\ncontent-length: 16\r\n\r\nerror code: 1015";
/// The clock of that capture: Sat, 31 Oct 2026 15:17:00 GMT (Python's
/// `calendar.timegm`).
const AT_42: i64 = 1_793_459_820;

fn answer(status: u16, retry: Option<&str>, body: &[u8]) -> Response {
    let headers = retry.map(|r| vec![("retry-after".to_string(), r.to_string())]).unwrap_or_default();
    Response { status, reason: String::new(), headers, body: body.to_vec() }
}

fn tunnel() -> Response {
    answer(200, None, reply("four-words-in-a.trycloudflare.com").as_bytes())
}

/// The requests of [`ask`] against `answers` in turn (the last one again
/// when they run out): the result, how many requests went, and the lines.
async fn ask_with(answers: Vec<Response>) -> (Result<Tunnel, Failed>, usize, Vec<String>) {
    let (count, said) = (Cell::new(0usize), RefCell::new(Vec::new()));
    let post = || {
        let next = answers[count.get().min(answers.len() - 1)].clone();
        count.set(count.get() + 1);
        async move { Ok::<_, String>(next) }
    };
    let say = |line: String| said.borrow_mut().push(line);
    let got = ask(post, &say, || AT_42).await;
    (got, count.get(), said.into_inner())
}

#[test]
fn a_reply_gives_the_tunnel_s_name_and_credentials() {
    let tunnel = read_reply(200, reply("four-words-in-a.trycloudflare.com").as_bytes()).unwrap();
    assert_eq!(tunnel.hostname, "four-words-in-a.trycloudflare.com");
    assert_eq!(
        tunnel.id,
        [0x8e, 0x9d, 0x2f, 0x0c, 0x4b, 0x1a, 0x4f, 0x6e, 0x9c, 0x3d, 0x5a, 0x7b, 0x2e, 0x1f, 0x0d, 0x4c]
    );
    assert_eq!(tunnel.secret.as_slice(), [7u8; 32]);
    assert!(!format!("{tunnel:?}").contains("BwcH"), "the secret is never shown");
}

#[test]
fn a_refusal_names_its_errors_and_never_quotes_a_reply_that_succeeded() {
    let errors = r#"{"success":false,"errors":[{"code":1003,"message":"too many tunnels"}],"result":null}"#;
    assert_eq!(read_reply(200, errors.as_bytes()).unwrap_err(), Refused::Errors("[1003] too many tunnels".into()));
    let status = read_reply(429, b"Too Many Requests\n").unwrap_err();
    assert_eq!(status.to_string(), "api.trycloudflare.com answered 429: Too Many Requests");
    let bad = read_reply(200, b"{\"success\":true,\"result\":{\"secret\":\"s3cr3t\"}}").unwrap_err();
    assert!(!bad.to_string().contains("s3cr3t"), "{bad}");
    assert_eq!(
        read_reply(200, reply("x.example.com").as_bytes()).unwrap_err(),
        Refused::Malformed("a name not under trycloudflare.com")
    );
    assert_eq!(
        read_reply(200, reply("a.b.trycloudflare.com").as_bytes()).unwrap_err(),
        Refused::Malformed("a name that is not one label")
    );
}

#[test]
fn a_uuid_reads_as_its_16_bytes() {
    assert_eq!(uuid_bytes("00000000-0000-0000-0000-0000000000ff").unwrap()[15], 0xff);
    assert_eq!(uuid_bytes("00000000000000000000000000000000"), None, "no hyphens");
    assert_eq!(uuid_bytes("zz000000-0000-0000-0000-000000000000"), None);
}

/// ESC, BEL and a bare CR of the API's body, or of a message in its JSON,
/// never reach a line; a long body is cut.
#[test]
fn the_api_s_text_reaches_a_line_with_no_control_character() {
    let status = read_reply(403, b"forbidden\x1b[2J\x07\rnow").unwrap_err();
    assert_eq!(status.to_string(), "api.trycloudflare.com answered 403: forbidden[2J now");
    let errors = r#"{"success":false,"errors":[{"code":1,"message":"bad\u001b]0;x\u0007 thing\r\nhere"}]}"#;
    assert_eq!(read_reply(200, errors.as_bytes()).unwrap_err(), Refused::Errors("[1] bad]0;x thing here".into()));
    let long = read_reply(502, "x".repeat(5000).as_bytes()).unwrap_err();
    assert_eq!(long.to_string().len(), "api.trycloudflare.com answered 502: ".len() + 200);
    for refused in [status, long] {
        assert!(!refused.to_string().chars().any(char::is_control), "{refused}");
    }
}

#[test]
fn a_retry_after_reads_as_seconds_or_an_http_date() {
    assert_eq!(retry_after("2994", AT_42), Some(Duration::from_secs(2994)));
    assert_eq!(retry_after(" 1 ", AT_42), Some(Duration::from_secs(1)));
    assert_eq!(retry_after("Sat, 31 Oct 2026 15:19:00 GMT", AT_42), Some(Duration::from_secs(120)));
    assert_eq!(retry_after("Sat, 31 Oct 2026 15:16:00 GMT", AT_42), Some(Duration::ZERO), "a date gone by");
    assert_eq!(retry_after("99999999999999999999999", AT_42), Some(Duration::from_secs(u64::MAX)));
    for neither in ["", "-1", "1.5", "soon", "Saturday, 31-Oct-26 15:19:00 GMT"] {
        assert_eq!(retry_after(neither, AT_42), None, "{neither:?}");
    }
}

#[test]
fn only_429_and_5xx_are_refusals_for_now() {
    let status = |status| Refused::Status { status, detail: String::new() };
    for now in [429, 500, 502, 503, 504, 520, 599] {
        assert!(status(now).for_now(), "{now}");
    }
    for not in [400, 401, 403, 404, 405, 407, 409, 413, 600] {
        assert!(!status(not).for_now(), "{not}");
    }
    assert!(!Refused::Errors("x".into()).for_now());
    assert!(!Refused::Malformed("x").for_now());
}

/// cfrs #42's answer, read as podssh reads it: its wait is past the budget,
/// so one request goes, and the line says until when, on the clock of the
/// capture.
#[tokio::test(start_paused = true)]
async fn cfrs_42_s_answer_ends_at_once_and_says_its_wait() {
    let captured = podssh_ws::http::read_response(&mut &CFRS_42[..], Vec::new(), 64 * 1024).await.unwrap();
    assert_eq!((captured.status, captured.header("Retry-After")), (429, Some("2994")));
    let started = tokio::time::Instant::now();
    let (got, requests, said) = ask_with(vec![captured]).await;
    let why = "api.trycloudflare.com answered 429: error code: 1015; it asks to wait 2994 s, until Sat, 31 Oct 2026 \
               16:06:54 GMT, past the 300 s that podssh asks again for: run again then";
    assert_eq!(got.unwrap_err(), Failed::ForNow(why.into()));
    assert_eq!((requests, said.len()), (1, 0));
    assert!(started.elapsed() < Duration::from_secs(1), "no wait");
}

#[tokio::test(start_paused = true)]
async fn a_retry_after_within_the_budget_is_waited_and_the_tunnel_comes() {
    let started = tokio::time::Instant::now();
    let (got, requests, said) = ask_with(vec![answer(429, Some("7"), b"slow down"), tunnel()]).await;
    assert_eq!(got.unwrap().hostname, "four-words-in-a.trycloudflare.com");
    assert_eq!(requests, 2);
    assert_eq!(said, ["api.trycloudflare.com answered 429: slow down; asking again in 7 s"]);
    assert!(started.elapsed() >= Duration::from_secs(7), "{:?}", started.elapsed());
}

#[tokio::test(start_paused = true)]
async fn each_5xx_is_asked_again_and_another_refusal_ends_at_once() {
    let fives = vec![answer(500, None, b""), answer(502, None, b"bad gateway"), answer(503, Some("2"), b""), tunnel()];
    let (got, requests, said) = ask_with(fives).await;
    assert!(got.is_ok(), "{got:?}");
    assert_eq!((requests, said.len()), (4, 3));
    let (got, requests, said) = ask_with(vec![answer(403, None, b"forbidden"), tunnel()]).await;
    assert_eq!(got.unwrap_err(), Failed::Refused("api.trycloudflare.com answered 403: forbidden".into()));
    assert_eq!((requests, said.len()), (1, 0));
}

/// With no Retry-After, the backoff of the relay's failover: growing waits,
/// the last one cut at the budget's end, then the end of the requests.
#[tokio::test(start_paused = true)]
async fn a_429_with_no_retry_after_waits_the_backoff_until_the_budget_ends() {
    let started = tokio::time::Instant::now();
    let (got, requests, said) = ask_with(vec![answer(429, None, b"error code: 1015")]).await;
    let elapsed = started.elapsed();
    assert_eq!(
        got.unwrap_err(),
        Failed::ForNow(
            "api.trycloudflare.com answered 429: error code: 1015; still refused after 300 s of requests: run \
             again later"
                .into()
        )
    );
    assert!((5..=40).contains(&requests), "{requests} requests");
    assert_eq!(said.len(), requests - 1);
    assert!(elapsed >= BUDGET && elapsed <= BUDGET + LEAST_WAIT, "{elapsed:?}");
}

/// A request that failed before an answer, as a proxy's refusal, is not
/// asked again: it would fail the same.
#[tokio::test(start_paused = true)]
async fn a_request_that_got_no_answer_is_not_asked_again() {
    let count = Cell::new(0);
    let post = || {
        count.set(count.get() + 1);
        async { Err::<Response, _>("the proxy refused CONNECT with 403".to_string()) }
    };
    let got = ask(post, &|_| {}, || AT_42).await;
    assert_eq!(got.unwrap_err(), Failed::Refused("the proxy refused CONNECT with 403".into()));
    assert_eq!(count.get(), 1);
}

#[test]
fn a_wait_past_the_budget_stops_and_one_within_it_is_kept() {
    let limited = Refused::Status { status: 429, detail: ": error code: 1015".into() };
    let left = Duration::from_secs(100);
    assert_eq!(then(&limited, Some("100"), 1, left, AT_42), Then::Again(Duration::from_secs(100)));
    assert_eq!(then(&limited, Some("0"), 1, left, AT_42), Then::Again(LEAST_WAIT));
    assert!(matches!(then(&limited, Some("101"), 1, left, AT_42), Then::Stop(Failed::ForNow(_))));
    let date = "Sat, 31 Oct 2026 15:19:00 GMT";
    let Then::Stop(Failed::ForNow(why)) = then(&limited, Some(date), 1, left, AT_42) else { panic!("not stopped") };
    assert!(why.contains("it asks to wait 120 s, until Sat, 31 Oct 2026 15:19:00 GMT"), "{why}");
    let Then::Again(wait) = then(&limited, None, 1, left, AT_42) else { panic!("not again") };
    assert!(wait >= LEAST_WAIT && wait < Duration::from_secs(2), "{wait:?}");
    let missing = Refused::Status { status: 404, detail: String::new() };
    assert_eq!(then(&missing, Some("1"), 1, left, AT_42), Then::Stop(Failed::Refused(missing.to_string())));
}
