//! The answers of a CA, from the examples of RFC 8555 and the words of
//! Pebble's (`wfe/wfe.go` and `acme/problems.go` of its v2.10.1).

use super::*;

fn answer(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status,
        reason: "Reason".into(),
        headers: headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.to_string())).collect(),
        body: body.as_bytes().to_vec(),
    }
}

/// RFC 8555, section 7.1.1.
const DIRECTORY: &str = r#"{
  "newNonce": "https://example.com/acme/new-nonce",
  "newAccount": "https://example.com/acme/new-account",
  "newOrder": "https://example.com/acme/new-order",
  "newAuthz": "https://example.com/acme/new-authz",
  "revokeCert": "https://example.com/acme/revoke-cert",
  "keyChange": "https://example.com/acme/key-change",
  "meta": {
    "termsOfService": "https://example.com/acme/terms/2017-5-30",
    "website": "https://www.example.com/",
    "caaIdentities": ["example.com"],
    "externalAccountRequired": false
  }
}"#;

#[test]
fn a_directory_gives_its_urls_and_terms_and_one_that_wants_an_external_account_is_refused() {
    let d = Directory::parse(DIRECTORY.as_bytes()).unwrap();
    assert_eq!(d.new_nonce, "https://example.com/acme/new-nonce");
    assert_eq!(d.new_account, "https://example.com/acme/new-account");
    assert_eq!(d.new_order, "https://example.com/acme/new-order");
    assert_eq!(d.terms.as_deref(), Some("https://example.com/acme/terms/2017-5-30"));
    let eab = DIRECTORY.replace(r#""externalAccountRequired": false"#, r#""externalAccountRequired": true"#);
    assert!(Directory::parse(eab.as_bytes()).unwrap_err().contains("external account binding"));
    let none = DIRECTORY.replace("newOrder", "newOrders");
    assert!(Directory::parse(none.as_bytes()).unwrap_err().contains("newOrder"));
}

/// RFC 8555, section 6.7.1.
const SUBPROBLEMS: &str = r#"{
    "type": "urn:ietf:params:acme:error:malformed",
    "detail": "Some of the identifiers requested were rejected",
    "subproblems": [
        {
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Invalid underscore in DNS name \"_example.org\"",
            "identifier": {"type": "dns", "value": "_example.org"}
        },
        {
            "type": "urn:ietf:params:acme:error:rejectedIdentifier",
            "detail": "This CA will not issue for \"example.net\"",
            "identifier": {"type": "dns", "value": "example.net"}
        }
    ]
}"#;

#[test]
fn a_problem_is_said_in_one_line_with_its_subproblems() {
    let text = problem(&answer(400, &[], SUBPROBLEMS));
    assert_eq!(
        text,
        "malformed: Some of the identifiers requested were rejected; malformed: Invalid underscore in DNS name \
         \"_example.org\"; rejectedIdentifier: This CA will not issue for \"example.net\""
    );
    // Not JSON: the status and the start of the body.
    assert_eq!(problem(&answer(502, &[], "bad\ngateway")), "HTTP 502 Reason: bad gateway");
    // A control character of the CA's never reaches the terminal.
    let sly = r#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"no\u001b[2Jway"}"#;
    assert!(!problem(&answer(403, &[], sly)).contains('\u{1b}'));
}

#[test]
fn pebbles_bad_nonce_is_known_and_a_nonce_of_another_shape_is_not_taken() {
    let body = "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\
                \"detail\":\"JWS has an invalid anti-replay nonce: x\",\"status\":400}";
    let refused = answer(400, &[("Replay-Nonce", "u3TS7Ui8bq3C1Q5JsBxmkk")], body);
    assert_eq!(problem_type(&refused).as_deref(), Some(BAD_NONCE));
    assert_eq!(replay_nonce(&refused).as_deref(), Some("u3TS7Ui8bq3C1Q5JsBxmkk"));
    for wrong in ["", "a\"b", "a b", "a,b"] {
        assert_eq!(replay_nonce(&answer(200, &[("Replay-Nonce", wrong)], "")), None, "{wrong:?}");
    }
    assert_eq!(replay_nonce(&answer(200, &[], "")), None);
}

#[test]
fn retry_after_is_taken_from_1_to_10_seconds_in_either_form() {
    let at = |value: &str| retry_after(&answer(200, &[("Retry-After", value)], "{}"), 1_791_440_980);
    assert_eq!(at("3"), Duration::from_secs(3));
    assert_eq!(at("0"), Duration::from_secs(1));
    assert_eq!(at("3600"), Duration::from_secs(10));
    // 9 s after the time given.
    assert_eq!(at("Thu, 08 Oct 2026 06:29:49 GMT"), Duration::from_secs(9));
    assert_eq!(at("soon"), Duration::from_secs(2));
    assert_eq!(retry_after(&answer(200, &[], "{}"), 0), Duration::from_secs(2));
}

#[test]
fn json_is_taken_from_200_and_201_alone() {
    assert_eq!(json_of(&answer(201, &[], r#"{"status":"pending"}"#)).unwrap()["status"], "pending");
    let refused = r#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"Account is not valid"}"#;
    assert_eq!(json_of(&answer(403, &[], refused)).unwrap_err(), "unauthorized: Account is not valid");
}
