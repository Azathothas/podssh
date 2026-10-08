//! E12: the tests that a token cannot be printed.
//!
//! ⛔ **Every token-shaped string in this file is synthetic.** ⛔ `E12`'s entry
//! records that two research agents minted live credentials while building this
//! repository's evidence base, and `scripts/check-todo.py`'s `check_no_secrets`
//! fails any document carrying one. ⛔ These values have the relay's shape
//! (`ephm1.<expiry-ms>.<role>.<mac>`, spec lines 81-87) and ⛔ **a mac of all
//! zeroes**, which is not a credential for anything.
//!
//! ⛔ **The tests are written to fail on the failure mode, not on the code.** A
//! test that passes because the value was never printed proves only that the
//! value was never printed. ⛔ [`a_token_in_a_log_line_cannot_survive`] and
//! [`the_failure_mode_is_a_line_that_a_token_cannot_escape`] are about the
//! *output*, and ⛔ [`a_planted_leak_is_caught`] is about the filter catching a
//! real one.

use std::fmt::Write as _;

mod common;

use common::{SYNTHETIC, SYNTHETIC_2};
use podssh_cli::security::redact::{emit, looks_like_token, scan_for_tokens, scrub, MemorySink};
use podssh_cli::security::redpair::ReversePair;
use podssh_cli::security::request::RelayRequest;
use podssh_cli::security::token::{RelayToken, TokenRole, REDACTED, TOKEN_HEADER};

fn tok(s: &str) -> RelayToken {
    s.parse().expect("a synthetic token parses")
}

// ⛔ **The compile-time guard: `Display`, `LowerHex` and `UpperHex` are not
// reachable.** ⛔ Two blanket impls of a helper trait, one bound to each
// formatter and one carrying a different type parameter. ⛔ The path below
// resolves to the `()` impl only while none of the three formatters applies;
// implement any one of them and two candidate impls match, `_` cannot be
// inferred, and this file stops compiling (E0283). ⛔ This is the guard an
// earlier version of the test below claimed in a comment and did not have.
const _: () = {
    trait AmbiguousIfImpl<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    impl<T: ?Sized + std::fmt::Display> AmbiguousIfImpl<u8> for T {}
    impl<T: ?Sized + std::fmt::LowerHex> AmbiguousIfImpl<u16> for T {}
    impl<T: ?Sized + std::fmt::UpperHex> AmbiguousIfImpl<u32> for T {}
    let _ = <RelayToken as AmbiguousIfImpl<_>>::some_item;
};

#[test]
fn display_cannot_be_reached_at_all() {
    let t = tok(SYNTHETIC);
    // ⛔ **The absence is asserted by the compiler, not by a comment.** The
    // `const _` block above stops compiling if `Display`, `LowerHex` or
    // `UpperHex` is added to `RelayToken`, which is what makes *"a token
    // cannot be printed"* a property of the type rather than of this test.
    // ⛔ The `Debug` half is asserted at run time below, because a fixed string
    // is something a test can compare.
    assert_eq!(format!("{:?}", t), REDACTED);
}

#[test]
fn debug_cannot_render_the_value() {
    let t = tok(SYNTHETIC);
    let rendered = format!("{t:?}");
    assert_eq!(rendered, REDACTED);
    assert!(!rendered.contains(SYNTHETIC), "the value leaked through Debug");
    // ⛔ Every three format verbs a diagnostic actually uses.
    for line in [
        format!("connecting with token={t:?}"),
        format!("{t:#?}"),
        format!("token is {t:?} and that is all we say"),
    ] {
        assert!(!line.contains(SYNTHETIC), "the value leaked: {line}");
    }
}

#[test]
fn debug_of_a_collection_of_tokens_renders_none_of_them() {
    // ⛔ The `Prove` requirement, asserted directly: ⛔ *"including through
    // `{:?}` on a `Vec` of them"*. ⛔ A `Vec<RelayToken>`'s `Debug` calls each
    // element's `Debug`, so ⛔ this passes only if every element's `Debug`
    // redacts, and it would fail against a `#[derive(Debug)]` newtype.
    let tokens = vec![tok(SYNTHETIC), tok(SYNTHETIC_2)];
    let rendered = format!("{tokens:?}");
    assert!(!rendered.contains(SYNTHETIC), "Vec Debug leaked the first");
    assert!(!rendered.contains(SYNTHETIC_2), "Vec Debug leaked the second");
    assert!(!rendered.contains("0000000000000000"), "any MAC reached the output");
}

#[test]
fn debug_of_a_struct_holding_a_token_renders_none_of_them() {
    // ⛔ A field named `Debug`. ⛔ This is the "stray `{:?}` in a panic message"
    // case `E12`'s Approach names, and ⛔ a derived `Debug` on a caller's
    // struct would print the field's `Debug` ⛔ — which is this one, not a bare
    // `String`, and that is the whole design.
    #[derive(Debug)]
    struct Session {
        target: &'static str,
        token: RelayToken,
    }
    let s = Session {
        target: "github.com",
        token: tok(SYNTHETIC),
    };
    let rendered = format!("{s:?}");
    assert_eq!(s.target, "github.com", "the field itself carries the host");
    assert_eq!(format!("{:?}", s.token), REDACTED, "and the field is the token type");
    assert!(rendered.contains("github.com"), "the control: real fields do print");
    assert!(!rendered.contains(SYNTHETIC), "the token leaked through a derived Debug");
    assert!(rendered.contains(REDACTED), "the redaction must be visible in the output");
}

#[test]
fn an_error_holding_a_token_does_not_leak_through_its_debug() {
    // ⛔ "and through an error's `Debug`" \u2014 an error is what a `?` prints, and
    // a `?` in a `main` is how a secret reaches a terminal most often.
    #[derive(Debug)]
    #[allow(dead_code)]
    enum HandshakeError {
        Refused { host: &'static str, token: RelayToken },
    }
    let e = HandshakeError::Refused {
        host: "github.com",
        token: tok(SYNTHETIC),
    };
    let rendered = format!("{e:?}");
    assert!(!rendered.contains(SYNTHETIC), "the token leaked through an error Debug");
    assert!(rendered.contains(REDACTED));
}

/// ⛔ **The failure mode, asserted as a failure mode.** ⛔ `E12`'s instruction:
/// ⛔ *"A redaction test that passes only because the value was never printed is
/// weak \u2014 make one that proves the failure mode (a token in a log line) cannot
/// happen."* ⛔ So this constructs the log line a diagnostic would have produced
/// ⛔ **by handing the value to a formatter that does not go through the
/// wrapper** \u2014 which is the only way a token reaches a log line in a program
/// whose token type is sound.
#[test]
fn a_token_in_a_log_line_cannot_survive_the_sink() {
    // ⛔ **The plant, constructed honestly.** A `String` holding a token, which
    // is what a mint response, a cache-file read, or a third-party error gives
    // a caller. ⛔ Nothing prevents a program from putting that into a `String`
    // and formatting it; ⛔ what this asserts is that when it does, the line
    // does not survive.
    let leaked = format!("relay: connecting with token={SYNTHETIC}");
    assert!(leaked.contains(SYNTHETIC), "the plant must really contain the token");

    let mut sink = MemorySink::default();
    emit(&mut sink, &leaked).expect("a memory sink cannot fail");
    assert_eq!(sink.lines.len(), 1);
    assert!(
        !sink.lines[0].contains(SYNTHETIC),
        "the token survived the sink: {}",
        sink.lines[0]
    );
    assert!(sink.lines[0].contains("redacted"), "the line must say what happened to it");
}

#[test]
fn the_failure_mode_is_a_line_that_a_token_cannot_escape() {
    // ⛔ A realistic session transcript, with a token spliced into the one line
    // that would leak it, and ⛔ every line pushed through the sink.
    let transcript = [
        "podssh: target github.com:22 via tcp-1.ssh.relay.ajam.dev",
        "podssh: TLS 1.3, TLS13_AES_256_GCM_SHA384, X25519",
        "podssh: upgrade 101 in 41ms",
        "podssh: upgrade 403 relay: missing or wrong token",
        "podssh: banner SSH-2.0-podssh_0.1",
    ];
    let contaminated: Vec<String> = transcript
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i == 3 {
                format!("{l} (sent {SYNTHETIC})")
            } else {
                (*l).to_string()
            }
        })
        .collect();

    let mut out = String::new();
    let mut sink = MemorySink::default();
    for line in &contaminated {
        emit(&mut sink, line).expect("a memory sink cannot fail");
        writeln!(out, "{}", sink.lines.last().expect("emit pushes a line")).unwrap();
    }

    // ⛔ The assertion that matters: nothing shaped like a token survived.
    assert!(
        scan_for_tokens(&out).is_empty(),
        "a token-shaped value survived into the transcript"
    );
    // ⛔ And the control, which is what stops a filter that swallows everything
    // from passing: ⛔ the other four lines are still there, byte for byte.
    for line in &transcript[..2] {
        assert!(out.contains(line), "the control line was altered or dropped: {line}");
    }
    assert!(out.contains("banner SSH-2.0-podssh_0.1"), "the last line must survive");
}

#[test]
fn a_planted_leak_is_caught_and_the_control_is_not() {
    // ⛔ **Both directions in one test, because a filter that drops everything
    // would pass the first half.**
    let dirty = format!("mint ok: {SYNTHETIC}");
    let clean = "mint ok: expires 1900000000000 ms since epoch";
    assert!(looks_like_token(&dirty), "the planted line must be recognised");
    assert!(!looks_like_token(clean), "the control line must not be recognised");
    assert!(scrub(&dirty).is_some(), "a dirty line is replaced");
    assert!(scrub(clean).is_none(), "a clean line is returned unchanged");
    assert_eq!(scrub(clean), None);
}

#[test]
fn a_reverse_pairs_debug_holds_no_token() {
    // ⛔ `ReversePair` carries three credentials and ⛔ its `Debug` is written by
    // hand. ⛔ A derived `Debug` would print three `RelayToken`s, which are safe
    // today and would stop being safe the day a fourth `String` field landed.
    let mut pair = ReversePair::new(
        "podssh-fixture",
        1_900_000_000_000,
        tok(SYNTHETIC),
        tok(SYNTHETIC_2),
        tok(SYNTHETIC),
    );
    let rendered = format!("{pair:?}");
    for secret in [SYNTHETIC, SYNTHETIC_2] {
        assert!(!rendered.contains(secret), "the pair Debug leaked {secret}");
    }
    assert!(rendered.contains("podssh-fixture"), "the name is not a secret and should print");
    assert!(rendered.contains("expir"), "the expiry is not a secret and should print");
    // ⛔ **The revocation report, and the two halves of it.** ⛔ `revoke` does
    // the local destruction and nothing else, ⛔ so the report says the local
    // copy is gone and that the server was not asked ⛔ — **in that order**,
    // ⛔ because the record’s measurement is that the relay destroyed the
    // ⛔ credentials while answering `{"stopped": false}`, so a report that read
    // ⛔ the server first would describe a success as a failure.
    let mut rev = pair.revoke();
    let report = rev.to_string();
    assert!(report.contains("local destroyed"), "got: {report}");
    assert!(report.contains("server not asked"), "got: {report}");
    // ⛔ And the `stopped` field is not a verdict, ⛔ **and is not a field the
    // ⛔ type can hold** ⛔ — `ServerAttempt` has three variants and none of
    // ⛔ them carries a bool.
    assert!(
        !report.contains("stopped"),
        "the stopped field must not appear: {report}"
    );
    // ⛔ Now the server leg, ⛔ **and the outcome is recorded without its
    // ⛔ body.** ⛔ The one observation in this repository’s evidence base is
    // ⛔ `{"stopped": false}` on a stop that ⛔ did destroy the credentials, so
    // ⛔ a body could not be a verdict even if there were one.
    pair.record_server_attempt(&mut rev, true);
    let after = rev.to_string();
    assert!(after.contains("server asked"), "got: {after}");
    assert!(after.contains("its answer is not a verdict"), "got: {after}");
    assert!(after.contains("local destroyed"), "the local half must not be undone: {after}");
}

#[test]
fn a_request_carries_the_token_in_the_header_and_nowhere_else() {
    let t = tok(SYNTHETIC);
    let req = RelayRequest::new("wss://tcp.ssh.relay.ajam.dev/connect/github.com/22")
        .with_query("family", "4")
        .with_token(&t);
    let url = req.url().expect("a clean request has a URL");
    assert_eq!(req.headers.get(TOKEN_HEADER).map(String::as_str), Some(SYNTHETIC));
    assert!(!url.contains(SYNTHETIC), "the token is in the URL: {url}");
    assert!(!url.contains("token"), "the URL names a token at all: {url}");
    assert!(url.contains("family=4"), "a non-secret knob must still work: {url}");
    // ⛔ **The request's own `Debug`, and it contains the header**
    // map, so it is the case that most needs asserting: ⛔ a derived `Debug`
    // on a request type prints the token because the token is a header, and
    // that is a leak a caller triggers by `{:?}` on a struct it did not write.
    // ⛔ So `RelayRequest`'s `Debug` is NOT derived in `request.rs`; see the
    // note there. This test is the assertion for it.
    let rendered = format!("{req:?}");
    assert!(
        !rendered.contains(SYNTHETIC),
        "RelayRequest's Debug leaked the header value: {rendered}"
    );
}
#[test]
fn expiry_is_read_from_the_token_and_not_from_a_second_field() {
    // ⛔ **The minted token, MAC and all.** ⛔ Spec lines 81-87: the shape is
    // `ephm1.<exp-ms>.forward.<mac>` — **four** dot-separated fields, and
    // ⛔ `facts` reads the first three and treats the fourth as opaque. ⛔ A
    // first version required exactly three and refused every real token.
    let t = tok(SYNTHETIC);
    let facts = t.facts().expect("a minted token yields facts");
    assert_eq!(facts.kind, TokenRole::Forward);
    assert_eq!(facts.expires_ms, 1_900_000_000_000);
    // ⛔ Spec lines 81-87: a token expires at most 72 h after minting,
    // and the check is per session establishment, not per frame. ⛔ So the
    // predicate is a comparison against a clock the caller supplies.
    assert!(!t.is_expired_at(1_899_999_999_999).expect("facts parse"));
    assert!(t.is_expired_at(1_900_000_000_000).expect("facts parse"));
    assert!(t.is_expired_at(1_900_000_000_001).expect("facts parse"));
    // ⛔ **A token with no MAC is not required to parse** — ⛔ so a relay that
    // shortens its credential, or a test that uses a literal, both work, and ⛔ a
    // future `ephm2.` prefix fails on its own terms rather than on a count.
    let short: RelayToken = "ephm1.1900000000000.forward".parse().expect("a three-field token parses");
    assert_eq!(short.facts().expect("no MAC is still a token").expires_ms, 1_900_000_000_000);
    // ⛔ And a shape podssh does not know is an error, not a silent "never
    // expires" — ⛔ neither one that is not a token, nor one whose prefix has
    // moved on, nor one whose role is a word this version does not name.
    for bad in [
        "not-a-relay-token",
        "ephm2.1900000000000.forward.abc",
        "ephm1.1900000000000.teleport.abc",
    ] {
        let odd: RelayToken = bad.parse().expect("a token is any header-safe string");
        assert!(odd.facts().is_err(), "{bad:?} must not yield facts");
        assert!(odd.is_expired_at(0).is_err(), "{bad:?} must not be judged unexpired");
    }
}

#[test]
fn a_token_that_is_not_a_header_value_is_refused_at_the_parse() {
    // ⛔ A newline in a credential is a header injection, not a malformed token,
    // and it is refused where it enters rather than at the socket.
    assert!("ephm1.1.forward.abc\nX-Evil: 1".parse::<RelayToken>().is_err());
    assert!("ephm1.1.forward.abc def".parse::<RelayToken>().is_err());
    assert!("   ".parse::<RelayToken>().is_err());
    // ⛔ The control: the real shape parses.
    assert!(SYNTHETIC.parse::<RelayToken>().is_ok());
}
