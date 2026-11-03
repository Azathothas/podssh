//! The verdicts of T-325 on answers written by hand: what each line names,
//! by the times and the sizes that came.

use super::*;

const AT: &str = "https://relay.example/v1/probe";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// An answer of `status` whose body came in `reads` (the time in ms, and the
/// body's bytes by then), ended by `end`.
fn answer(status: u16, reads: &[(u64, u64)], end: End) -> Timed {
    Timed {
        head: Some((status, "OK".into())),
        head_at: Some(ms(reads.first().map_or(0, |r| r.0))),
        reads: reads.iter().map(|(at, n)| (ms(*at), *n)).collect(),
        body: Vec::new(),
        end,
    }
}

fn detail(verdict: Verdict) -> String {
    match verdict {
        Verdict::Ok { detail } => detail,
        other => panic!("not ok: {other:?}"),
    }
}

fn unknown(verdict: Verdict) -> String {
    match verdict {
        Verdict::Unknown { why } => why,
        other => panic!("not ????: {other:?}"),
    }
}

/// Five bytes sent over 2 s: over 2 s they stream, at once they were held,
/// and in two bursts they were held in parts.
#[test]
fn a_response_is_judged_by_when_its_bytes_came() {
    let over = Duration::from_secs(2);
    let streamed = answer(200, &[(1, 1), (501, 2), (1001, 3), (1501, 4), (2001, 5)], End::Whole(ms(2001)));
    let line = detail(response(AT, over, 5, &streamed));
    assert!(line.contains("came over 2.0 s") && line.contains("the path passes a response as it comes"), "{line}");
    let held = answer(200, &[(2003, 5)], End::Whole(ms(2003)));
    let line = detail(response(AT, over, 5, &held));
    let held_words = "came at once, after 2.0 s: something on the path holds a response until its end";
    assert!(line.ends_with(held_words), "{line}");
    assert!(line.starts_with("https://relay.example/v1/probe/drip: a response of 5 bytes sent over 2.0 s"), "{line}");
    let bursts = answer(200, &[(1, 2), (1001, 5)], End::Whole(ms(1001)));
    assert!(detail(response(AT, over, 5, &bursts)).contains("holds a response in parts"));
    // A cut, a short body and a server with no drip tell nothing.
    let cut = answer(200, &[(1, 1)], End::Cut { at: ms(900), why: "a reset".into() });
    assert!(unknown(response(AT, over, 5, &cut)).contains("was cut after 0.9 s (a reset)"));
    let none = answer(404, &[], End::Whole(ms(3)));
    assert!(unknown(response(AT, over, 5, &none)).contains("answered 404 OK: the server serves no such probe"));
}

/// The body's parts as the server said them: over 1.5 s they streamed, at
/// once they were held, by the path or, behind a node, by the node.
#[test]
fn a_body_is_judged_by_when_the_server_said_its_parts_came() {
    let over = Duration::from_millis(1500);
    let with = |parts: &str| {
        let mut a = answer(200, &[(1600, 80)], End::Whole(ms(1600)));
        a.body = format!(r#"{{"bytes": 4096, "parts": [{parts}]}}"#).into_bytes();
        a
    };
    let streamed = with(
        r#"{"from_ms":0,"to_ms":0,"bytes":1024},{"from_ms":500,"to_ms":500,"bytes":1024},
           {"from_ms":1000,"to_ms":1000,"bytes":1024},{"from_ms":1500,"to_ms":1500,"bytes":1024}"#,
    );
    let own = Own::unnamed();
    let line = detail(body(AT, over, 4, &streamed, &own));
    assert!(line.contains("came to the server over 1.5 s: the path passes a request's body as it comes"), "{line}");
    let held = with(r#"{"from_ms":1502,"to_ms":1503,"bytes":4096}"#);
    let line = detail(body(AT, over, 4, &held, &own));
    assert!(line.contains("at once, 1.5 s after its head: something on the path holds a request's body"), "{line}");
    let node = Own { body_whole: true, behind: Some("the node of a quick tunnel".into()), ..Own::unnamed() };
    let line = detail(body(AT, over, 4, &held, &node));
    let whole = "the node of a quick tunnel takes a body whole, so the path's own way is not seen";
    assert!(line.contains(whole), "{line}");
    // go-httpbin's echo says no part's time.
    let mut echo = answer(200, &[(1600, 80)], End::Whole(ms(1600)));
    echo.body = br#"{"data": "pppp", "headers": {}}"#.to_vec();
    assert!(unknown(body(AT, over, 4, &echo, &own)).contains("says not when each part came"));
}

#[test]
fn the_sizes_of_the_cap_double_up_to_the_most_and_end_with_it() {
    let sizes = sizes(CAP_MAX);
    assert_eq!((sizes.len(), sizes[0], sizes[7]), (8, 64 << 10, 8 << 20));
    assert_eq!(super::sizes(32 << 10), [32 << 10], "a node's cap, under the first");
    assert_eq!(super::sizes(100 << 10), [64 << 10, 100 << 10]);
    assert_eq!((size(1 << 20), size(64 << 10), size(1000)), ("1 MiB".into(), "64 KiB".into(), "1000 bytes".into()));
    assert_eq!(secs(ms(2049)), "2.0 s");
}

/// The last body that passed and the first that did not: no cap below the
/// most, a refusal with what it looks like, a cut, a path too slow to tell.
#[test]
fn the_cap_names_the_sizes_between_which_it_lies() {
    let own = Own { named: true, ..Own::unnamed() };
    let passed: Vec<(u64, Outcome)> = sizes(CAP_MAX).into_iter().map(|s| (s, Outcome::Passed)).collect();
    let line = detail(cap(AT, &passed, &own));
    assert!(line.contains("each body from 64 KiB to 8 MiB passed, the server's own cap"), "{line}");
    let mut refused: Vec<(u64, Outcome)> = passed[..5].to_vec();
    refused.push((2 << 20, Outcome::Refused { status: 413, reason: "Content Too Large".into() }));
    let line = detail(cap(AT, &refused, &own));
    let words = "a body of 1 MiB passed, and one of 2 MiB got 413 Content Too Large: something on the path refuses";
    assert!(line.contains(words), "{line}");
    assert!(line.ends_with("; looks like nginx's client_max_body_size (1 MiB by default)"), "{line}");
    assert_eq!(cap_numbers(&refused), json!({ "passed_bytes": 1 << 20, "refused_bytes": 2 << 20, "status": 413 }));
    let cut = [(64 << 10, Outcome::Cut("a reset".into()))];
    let line = detail(cap(AT, &cut, &own));
    assert!(line.contains("one of 64 KiB was cut with no answer (a reset)"), "{line}");
    assert!(unknown(cap(AT, &[(64 << 10, Outcome::Waited)], &own)).contains("too slow"));
    let unnamed = detail(cap(AT, &refused, &Own::unnamed()));
    assert!(unnamed.contains("or the server, which names no limits,"), "{unnamed}");
}

/// A quiet stream that came whole, one cut 3 s after its first byte, a 504
/// of the path at 60 s, and the 60 s of a quick tunnel's node, its own.
#[test]
fn a_quiet_stream_is_judged_by_when_and_how_it_ended() {
    let hold = Duration::from_secs(6);
    let own = Own::unnamed();
    let whole = answer(200, &[(2, 1), (6002, 2)], End::Whole(ms(6002)));
    let line = detail(quiet(AT, hold, &whole, &own));
    assert!(line.contains("came whole after 6.0 s: nothing on the path ends a stream quiet for that long"), "{line}");
    let cut = answer(200, &[(2, 1)], End::Cut { at: ms(3004), why: "a reset".into() });
    let line = detail(quiet(AT, hold, &cut, &own));
    assert!(line.contains("ended 3.0 s after it, with no end of its body (a reset)"), "{line}");
    assert!(line.ends_with("something on the path ends a stream quiet for about 3.0 s"), "{line}");
    let mut late = answer(504, &[], End::Whole(ms(60_100)));
    late.head = Some((504, "Gateway Timeout".into()));
    late.head_at = Some(ms(60_100));
    let line = detail(quiet(AT, Duration::from_secs(130), &late, &own));
    assert!(line.contains("the path answered 504 Gateway Timeout after 60.1 s"), "{line}");
    assert!(line.contains("looks like nginx's proxy_read_timeout (60 s by default)"), "{line}");
    let node = Own { quiet_max: Some(Duration::from_secs(60)), behind: Some("the node".into()), ..Own::unnamed() };
    let cut = answer(200, &[(2, 1)], End::Cut { at: ms(60_010), why: "a reset".into() });
    let line = detail(quiet(AT, Duration::from_secs(130), &cut, &node));
    assert!(line.ends_with("the node in front of the server ends an answer quiet so long, its own limit"), "{line}");
    assert_eq!(quiet_numbers(hold, &cut)["ended_ms"], 60_010);
}

/// The default relay's quiet socket: open for the hold, or ended, with both
/// of the causes that it cannot tell apart.
#[test]
fn the_quiet_socket_names_its_hold_or_its_end() {
    let hold = Duration::from_secs(130);
    let line = detail(socket("tcp.ssh.relay.ajam.dev", hold, &Ok(None)));
    assert!(line.contains("stayed open 130.0 s"), "{line}");
    let ended = Ok(Some((Duration::from_millis(60_200), "an end with no Close".into())));
    let line = detail(socket("tcp.ssh.relay.ajam.dev", hold, &ended));
    assert!(line.contains("ended after 60.2 s (an end with no Close)") && line.contains("or the relay dropped it"));
    assert!(line.contains("; looks like nginx's") && line.contains("or an AWS Application Load Balancer's"), "{line}");
    assert!(unknown(socket("r", hold, &Err("no pair: 429".into()))).ends_with("no pair: 429"));
}

#[test]
fn the_server_s_own_limits_come_from_its_relays_json() {
    let mut a = answer(200, &[(1, 10)], End::Whole(ms(1)));
    a.body = br#"{"limits": {"probe": {"body_max_bytes": 32768, "body": "whole", "quiet_max_ms": 60000,
                 "behind": "the node of a quick tunnel"}}}"#
        .to_vec();
    let own = Own::of(&a);
    assert_eq!((own.named, own.body_max, own.body_whole), (true, 32 << 10, true));
    assert_eq!(own.quiet_max, Some(Duration::from_secs(60)));
    assert_eq!(own.behind.as_deref(), Some("the node of a quick tunnel"));
    let line = server_line(AT, &own);
    assert!(line.contains("behind the node of a quick tunnel, which takes a body whole, 32 KiB at most"), "{line}");
    a.body = br#"{"limits": {"connect_timeout_ms": 10000}}"#.to_vec();
    assert_eq!(Own::of(&a), Own::unnamed(), "a relay of the contract alone");
    assert_eq!(Own::of(&answer(404, &[], End::Whole(ms(1)))), Own::unnamed());
    assert!(server_line(AT, &Own::unnamed()).contains("names no limits of the probes"));
}
