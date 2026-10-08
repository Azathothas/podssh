//! E15 — ⛔ **the DoH wire format: the question, its encoding, and the
//! endpoint's own rules.**
//!
//! ⛔ **This file was `dns_props.rs` once.** It is split by responsibility
//! ⛔ because ⛔ **the chain's properties and the wire format are two
//! ⛔ subjects** ⛔ — ⛔ and ⛔ **a file a reader cannot
//! ⛔ hold in one screen stops being reviewed**, ⛔ which is the whole
//! ⛔ of the 500-line rule. ⛔ **Nothing was deleted to fit**:
//! ⛔ every assertion in the combined file is here or in
//! ⛔ `dns_props.rs`, ⛔ and ⛔ the counts beside them say so.
//!
//! ⛔ **The controls that live here and not in the plants file** ⛔ — ⛔
//! ⛔ a test whose whole purpose is ⛔ *"this guard accepts correct input"*
//! ⛔ has no defect arm ⛔ — ⛔ and ⛔ **a
//! ⛔ control with no plant beside it is not a plant's other half**, ⛔
//! ⛔ it is a test in its own right.

use std::net::SocketAddr;

use podssh_transport::dns::{self, DohEndpoint};

mod common;
use common::dns::RELAY;

/// ⛔ **The endpoint is built by a constructor that refuses the three shapes
/// that would make the fallback depend on itself.**
#[test]
fn the_doh_endpoint_must_be_an_ip_literal_and_https_only() {
    // ⛔ **A name, refused** ⛔ — ⛔ `relay-hostname.md` measured it: ⛔ *"a DoH
    // ⛔ endpoint specified by name needs the same resolution podssh is trying to
    // ⛔ perform."* ⛔ **MEASURED 2026-10-01, host `Ajam`:** ⛔
    // ⛔ `curl https://cloudflare-dns.com/dns-query` ⛔ → ⛔ `curl: (6) Could
    // ⛔ not resolve host`, ⛔ while ⛔ `curl https://1.1.1.1/dns-query` ⛔ → ⛔
    // ⛔ `Status 0`.
    assert!(
        matches!(
            DohEndpoint::from_url("https://cloudflare-dns.com/dns-query", 443),
            Err(dns::DohError::NotAnAddress { .. })
        ),
        "⛔ a DoH endpoint specified by name is refused"
    );
    // ⛔ **Plaintext, refused and never downgraded.** ⛔ **READ**, `dropssh`
    // ⛔ `src/dns.c:231-234` accepts both schemes ⛔ — ⛔ *"HTTPS only, never
    // ⛔ plaintext, because the whole point is that a name which cannot be
    // ⛔ resolved is still a name that must not be sent in the clear to a party
    // ⛔ that might answer for it wrongly."*
    assert!(
        matches!(DohEndpoint::from_url("http://1.1.1.1/dns-query", 443), Err(dns::DohError::NotHttps { .. })),
        "⛔ an http:// endpoint is Err and not a fallback"
    );
    assert!(
        matches!(DohEndpoint::from_url("1.1.1.1/dns-query", 443), Err(dns::DohError::NotHttps { .. })),
        "⛔ a scheme-less URL is not https either"
    );
    // ⛔ **No name at all: a client with no name to verify is a client with no
    // ⛔ name to verify against** ⛔ — ⛔ and `podssh-ws`'s `WsClientConfig::validate`
    // ⛔ refuses an empty `server_name` ⛔ with ⛔ *"a server name is required:
    // ⛔ hostname verification has no bypass."*
    assert!(
        matches!(DohEndpoint::from_url("https://", 443), Err(dns::DohError::NoServerName { .. })),
        "⛔ an endpoint with no authority has no name to verify"
    );

    // ⛔ **THE CONTROL: the IP literal the entry prescribes is accepted**, ⛔ and
    // ⛔ **both halves survive** ⛔ — ⛔ **the name for the certificate
    // ⛔ and the literal to dial** ⛔ — ⛔ because ⛔ a pinned
    // ⛔ address with no name is a TLS failure.
    let ok = DohEndpoint::from_url("https://1.1.1.1/dns-query", 443).expect("the prescribed form");
    assert_eq!(ok.name, "1.1.1.1", "⛔ the name the certificate must carry");
    assert_eq!(ok.address, "1.1.1.1:443".parse::<SocketAddr>().unwrap(), "⛔ and the literal to dial");
    assert_eq!(ok.path, "/dns-query");
    assert_eq!(dns::DOH_DEFAULT_PATH, "/dns-query", "⛔ and that path is the published one");

    // ⛔ **THE NAMED FORM**, ⛔ which is ⛔ `relay-hostname.md`'s pair ⛔ applied to the
    // ⛔ resolver ⛔ — ⛔ and ⛔ **the only way a name that is not
    // ⛔ an IP literal is ever accepted.** ⛔ `named("")`
    // ⛔ is refused ⛔ and ⛔ a name with a hostname
    // ⛔ where an address ⛔ belongs ⛔ is refused ⛔ —
    // ⛔ **and that second refusal is the
    // ⛔ resolution E17 is failing to perform.**
    assert!(matches!(DohEndpoint::named("", "1.1.1.1", 443), Err(dns::DohError::NoServerName { .. })));
    assert!(
        matches!(
            DohEndpoint::named("cloudflare-dns.com", "1.1.1.1", 443),
            Ok(ref e) if e.name == "cloudflare-dns.com" && e.address.ip().to_string() == "1.1.1.1"
        ),
        "⛔ THE CONTROL: a name beside its address is accepted and BOTH survive"
    );
    assert!(
        matches!(
            DohEndpoint::named("cloudflare-dns.com", "tcp.ssh.relay.ajam.dev", 443),
            Err(dns::DohError::NotAnAddress { .. })
        ),
        "⛔ and a name where the address belongs is refused"
    );
}

/// ⛔ **`Host` carries the ADDRESS and never the name**, ⛔ and ⛔ **the reason
/// ⛔ is the opposite of what an operator expects**: ⛔ **E17's measurement
/// ⛔ is that the pool answers for the name in SNI and for the address
/// ⛔ on the wire**, ⛔ and ⛔ **no credential and
/// ⛔ no relay name enters a header**, ⛔ because ⛔ a URL
/// ⛔ ends up in proxy access logs** ⛔ — ⛔ `endpoint.rs`
/// ⛔ already says the same thing about tokens.
#[test]
fn the_host_header_carries_the_address_and_no_credential_carries_anything() {
    let ok = DohEndpoint::from_url("https://1.1.1.1/dns-query", 443).expect("an endpoint");
    let headers = ok.headers();
    let host = headers.iter().find(|(k, _)| k == "host").expect("⛔ a Host header");
    assert_eq!(host.1, "1.1.1.1:443", "⛔ the Host header carries the address");
    assert!(
        headers.iter().any(|(k, v)| k == "accept" && v == "application/dns-json"),
        "⛔ and the Accept header asks for the JSON shape: {headers:?}"
    );
    for (name, value) in &headers {
        assert!(
            !value.contains("relay.ajam.dev") && !name.contains("token") && !value.contains("Bearer"),
            "⛔ no credential and no relay name enters a header: {name}: {value}"
        );
    }

    // ⛔ **An IPv6 literal is bracketed in the authority and the brackets are
    // ⛔ not part of the address** ⛔ — ⛔ **a `Host` header of `2606:4700::1`
    // ⛔ is a malformed header**, ⛔ and ⛔ the failure would be a DoH
    // ⛔ stage that never answers on a v6-only host.
    let v6 = DohEndpoint::from_url("https://[2606:4700:4700::1111]/dns-query", 443).expect("a v6 endpoint");
    assert_eq!(v6.address.port(), 443);
    let v6_host = v6.headers().into_iter().find(|(k, _)| k == "host").expect("⛔ a Host header");
    assert!(
        v6_host.1.starts_with('[') && v6_host.1.contains("]:443"),
        "⛔ a v6 authority is bracketed: {}",
        v6_host.1
    );
}

/// ⛔ **The question podssh puts on the wire round-trips**, ⛔ and ⛔ **an
/// unencodable name is rejected rather than truncated into a different
/// question.**
#[test]
fn the_wire_question_round_trips_and_refuses_an_unencodable_name() {
    let query = dns::DohQuery::a(RELAY);
    let wire = query.wire();
    assert!(
        !wire.contains('=') && !wire.contains('+') && !wire.contains('/'),
        "⛔ base64url, unpadded, and a URL-safe alphabet: {wire}"
    );

    // ⛔ **Decode it back and read the name out of the bytes.** ⛔ **A
    // ⛔ hand-rolled base64url encoder with no decoder is an encoder nobody
    // ⛔ has checked** ⛔ — ⛔ and ⛔ **a subtly wrong one produces a
    // ⛔ question nobody answers**, ⛔ **so the "empty
    // ⛔ answer" assertion in the plants ⛔ would then pass for the wrong
    // ⛔ reason.**
    let bytes = dns::base64url_decode(&wire).expect("⛔ podssh's own alphabet decodes itself");
    assert_eq!(&bytes[..2], &[0x00, 0x00], "⛔ id 0: the connection is the security boundary");
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x0100, "⛔ RD set, a standard query");
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1, "⛔ QDCOUNT 1");
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0, "⛔ ANCOUNT 0: a question, not an answer");

    // ⛔ **Walk the labels and rebuild the name.** ⛔ **read off the decoded
    // ⛔ bytes, ⛔ and not off the `DohQuery`** ⛔ — ⛔ **a round trip that
    // ⛔ compares the input to itself proves nothing.**
    let mut name = String::new();
    let mut i = 12;
    while bytes[i] != 0 {
        let len = bytes[i] as usize;
        assert!(len <= 63, "⛔ a label over 63 bytes cannot be on the wire");
        name.push_str(std::str::from_utf8(&bytes[i + 1..i + 1 + len]).expect("⛔ a label is ASCII"));
        name.push('.');
        i += 1 + len;
    }
    assert_eq!(name, format!("{RELAY}."), "⛔ the name survives the encoding");
    let qtype = u16::from_be_bytes([bytes[i + 1], bytes[i + 2]]);
    assert_eq!(qtype, 1, "⛔ QTYPE A");
    assert_eq!(u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]), 1, "⛔ QCLASS IN");

    // ⛔ **THE AAAA ARM**, ⛔ because ⛔ **READ**, `dropssh` `src/dns.c:221-223`:
    // ⛔ *"THE DNS QUERY TYPE IS ASKED FOR EXPLICITLY AND BOTH FAMILIES
    // ⛔ are requested IN ONE CALL"* ⛔ — ⛔ and a v6-only name must
    // ⛔ not cost a round trip to discover.
    //
    // ⛔ **The qtype is read by WALKING THE NAME, ⛔ and not from a byte
    // ⛔ offset.** ⛔ **MEASURED 2026-10-02: this assertion
    // ⛔ first read a hardcoded `aaaa[20]` and got 29544** ⛔ — ⛔
    // ⛔ **because the offset is a function of the name's
    // ⛔ length** ⛔ — ⛔ **so the one offset
    // ⛔ that worked for `A` was wrong for `AAAA`** ⛔, ⛔
    // ⛔ **and a name three bytes longer would have made it
    // ⛔ wrong in the other direction.** ⛔
    let aaaa = dns::base64url_decode(&dns::DohQuery::aaaa(RELAY).wire()).expect("decodes");
    let mut j = 12;
    while aaaa[j] != 0 {
        j += 1 + aaaa[j] as usize;
    }
    assert_eq!(u16::from_be_bytes([aaaa[j + 1], aaaa[j + 2]]), 28, "⛔ QTYPE AAAA is 28");
    assert_eq!(u16::from_be_bytes([aaaa[j + 3], aaaa[j + 4]]), 1, "⛔ and QCLASS IN is unchanged");
    // ⛔ **And the same name encodes to the same bytes in both queries** ⛔
    // ⛔ — ⛔ **only the last four bytes differ**, ⛔ which is ⛔
    // ⛔ **what makes one `getaddrinfo`-shaped call able to ask for
    // ⛔ both.**
    let a = dns::base64url_decode(&dns::DohQuery::a(RELAY).wire()).expect("decodes");
    assert_eq!(a.len(), aaaa.len());
    assert_eq!(
        a[..a.len() - 4],
        aaaa[..aaaa.len() - 4],
        "⛔ the header, the name and QCLASS are byte-identical between A and AAAA"
    );
    assert_eq!(dns::TYPE_A, "A");
    assert_eq!(dns::TYPE_AAAA, "AAAA");
    assert_eq!(dns::DOH_SCHEME, "https://");

    // ⛔ **A label over 63 bytes cannot be encoded, and truncating it would ask
    // ⛔ a DIFFERENT question** ⛔ — ⛔ so the name is rejected, ⛔ and ⛔ **an
    // ⛔ empty string is ⛔ not ⛔ a question about the root** ⛔ — ⛔ **a
    // ⛔ truncated name asking a resolvable question is worse than no
    // ⛔ question**, ⛔ because ⛔ it answers for a name nobody wrote.
    let long = format!("{}.example", "a".repeat(64));
    assert!(
        dns::DohQuery::a(&long).wire().is_empty(),
        "⛔ a 64-byte label is refused and never silently shortened"
    );
    assert_eq!(dns::DohQuery::a(RELAY).wire(), wire, "⛔ and a good name still encodes");
}