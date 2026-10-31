//! The pins, the JSON form's answers, the resolvers' forms and the fallback
//! from one form to the other (T-344).

use super::*;

#[test]
fn pins_parse_and_reject_garbage() {
    let pins = parse_pins("tcp.ssh.relay.ajam.dev=104.21.39.2, Relay.Example.=[2001:db8::1],x=1.2.3.4").unwrap();
    assert_eq!(pins[0], ("tcp.ssh.relay.ajam.dev".into(), "104.21.39.2".parse().unwrap()));
    assert_eq!(pins[1], ("relay.example".into(), "2001:db8::1".parse().unwrap()));
    assert_eq!(pins.len(), 3);
    for bad in ["noequals", "=1.2.3.4", "host=not-an-ip", "bad host=1.2.3.4", "h=1.2.3.4.5"] {
        assert!(parse_pins(bad).is_err(), "{bad}");
    }
    assert!(parse_pins("").unwrap().is_empty());
}

#[test]
fn srv_answers_parse_and_drop_what_does_not_read() {
    // The answer that 1.1.1.1 gave for the edge's record (T-299), and
    // the forms that must not read as a record.
    let body = br#"{"Status":0,"Answer":[
        {"name":"_v2-origintunneld._tcp.argotunnel.com","type":33,"TTL":60,"data":"1 1 7844 region1.v2.argotunnel.com."},
        {"name":"_v2-origintunneld._tcp.argotunnel.com","type":33,"TTL":60,"data":"2 1 7844 REGION2.v2.argotunnel.com"},
        {"name":"x","type":33,"data":"1 1 notaport a.example"},
        {"name":"x","type":33,"data":"1 1 7844 a.example extra"},
        {"name":"x","type":33,"data":"1 1 7844 bad/name.example"},
        {"name":"x","type":1,"data":"192.0.2.1"}]}"#;
    let records = parse_srv(body).unwrap();
    assert_eq!(
        records,
        vec![
            Srv { priority: 1, weight: 1, port: 7844, target: "region1.v2.argotunnel.com".into() },
            Srv { priority: 2, weight: 1, port: 7844, target: "region2.v2.argotunnel.com".into() },
        ]
    );
    assert_eq!(parse_srv(br#"{"Status":3}"#).unwrap_err(), NXDOMAIN);
    assert!(parse_srv(br#"{"Status":0}"#).unwrap().is_empty());
    assert!(parse_srv(b"not json").is_err());
}

#[test]
fn dns_json_answers_parse_by_type() {
    let body = br#"{"Status":0,"Answer":[
        {"name":"a.example.","type":5,"data":"b.example."},
        {"name":"b.example.","type":1,"data":"192.0.2.7"},
        {"name":"b.example.","type":28,"data":"2001:db8::7"}]}"#;
    assert_eq!(parse_answer(body, "A").unwrap(), vec!["192.0.2.7".parse::<IpAddr>().unwrap()]);
    assert_eq!(parse_answer(body, "AAAA").unwrap(), vec!["2001:db8::7".parse::<IpAddr>().unwrap()]);
    assert_eq!(parse_answer(br#"{"Status":3}"#, "A").unwrap_err(), NXDOMAIN);
    assert_eq!(parse_answer(br#"{"Status":2}"#, "A").unwrap_err(), "DNS status 2");
    assert_eq!(parse_answer(br#"{"Answer":[]}"#, "A").unwrap_err(), "DNS status missing");
    assert!(parse_answer(b"nope", "A").is_err());
    assert!(parse_answer(br#"{"Status":0}"#, "A").unwrap().is_empty());
}

#[tokio::test]
async fn literals_and_pins_need_no_resolver() {
    let soon = Instant::now() + Duration::from_secs(1);
    assert_eq!(resolve("192.0.2.1", 443, soon).await.unwrap(), vec!["192.0.2.1:443".parse().unwrap()]);
    assert_eq!(resolve("[2001:db8::1]", 22, soon).await.unwrap(), vec!["[2001:db8::1]:22".parse().unwrap()]);
    set_pins(parse_pins("pinned.invalid=192.0.2.9").unwrap());
    assert_eq!(resolve("PINNED.invalid", 443, soon).await.unwrap(), vec!["192.0.2.9:443".parse().unwrap()]);
    set_pins(Vec::new());
}

/// Today's four resolvers first, then Quad9's two, each address once; the
/// JSON API first where there is one, the wire form for each; each target as
/// its form writes it.
#[test]
fn each_resolver_is_asked_in_its_forms() {
    let ips: Vec<&str> = DOH_RESOLVERS.iter().map(|r| r.ip).collect();
    assert_eq!(ips, ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4", "9.9.9.9", "149.112.112.112"]);
    for resolver in DOH_RESOLVERS {
        assert!(resolver.ip.parse::<IpAddr>().is_ok(), "a resolver needs no resolver: {}", resolver.ip);
        let forms = resolver.forms();
        assert_eq!(forms.last(), Some(&Form::Wire), "{}: the wire form is each one's fallback", resolver.ip);
        assert_eq!(forms.len(), 1 + usize::from(resolver.json.is_some()));
    }
    let cloudflare = DOH_RESOLVERS[0];
    assert_eq!(cloudflare.target(Form::Json, "relay.example", "AAAA").unwrap(), "/dns-query?name=relay.example&type=AAAA");
    // RFC 8484's own query of section 4.1.1.
    let wire = cloudflare.target(Form::Wire, "www.example.com", "A").unwrap();
    assert_eq!(wire, "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
    let quad9 = DOH_RESOLVERS[4];
    assert_eq!(quad9.target(Form::Json, "www.example.com", "A").unwrap(), wire, "no JSON: the wire form");
    assert!(cloudflare.target(Form::Wire, "bad name", "A").is_err());
}

fn answer(status: u16, body: &[u8]) -> http::Response {
    http::Response { status, reason: String::new(), headers: Vec::new(), body: body.to_vec() }
}

/// An answer that is not of the form asked goes to the other form; the status
/// of a busy or broken resolver, and the resolver's own status, do not.
#[test]
fn a_miss_of_the_form_falls_back_and_the_others_do_not() {
    let json = |body: &[u8]| parse_answer(body, "A");
    // Quad9's answer to the JSON API's query, 2026-10-31.
    assert_eq!(read(&answer(400, b"DoH unable to decode BASE64-URL"), json), Err(Miss::Form("HTTP 400".into())));
    assert_eq!(read(&answer(415, b""), json), Err(Miss::Form("HTTP 415".into())));
    assert_eq!(read(&answer(200, b"<html>"), json), Err(Miss::Form("not a DNS JSON answer".into())));
    assert_eq!(read(&answer(200, br#"{"Answer":[]}"#), json), Err(Miss::Form("DNS status missing".into())));
    assert_eq!(read(&answer(200, br#"{"Status":2}"#), json), Err(Miss::Said("DNS status 2".into())));
    assert_eq!(read(&answer(200, br#"{"Status":3}"#), json), Err(Miss::Said(NXDOMAIN.into())));
    assert_eq!(read(&answer(503, b""), json), Err(Miss::Way("HTTP 503".into())));
    assert_eq!(read(&answer(429, b""), json), Err(Miss::Way("HTTP 429".into())));
    let one = br#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"}]}"#;
    assert_eq!(read(&answer(200, one), json), Ok(vec!["192.0.2.1".parse::<IpAddr>().unwrap()]));
    // A JSON body where the wire form was asked is no DNS message.
    let as_wire = |body: &[u8]| wire::addrs(body, "relay.example", wire::A);
    assert!(matches!(read(&answer(200, one), as_wire), Err(Miss::Form(_))));
}
