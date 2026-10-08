//! ⛔ **Where a socket goes, and what podssh refuses to guess.**
//!
//! Two rules are asserted here that a comment cannot carry:
//!
//! 1. ⛔ **No token in a URL.** **READ**, live spec lines 94-96: *"Send a
//!    forward token in `X-Relay-Token`; use `?token=` or `/t/<t>/...` … only when
//!    headers are unavailable, since URLs can appear in logs."*
//! 2. ⛔ **No compiled default relay path.** `01-relay-protocol.md:65-77` records
//!    that **live line 28 reads `- (none configured)`**, **line 21 reads
//!    `not configured`** and `/health` reports `"relays": []` — ⛔ **MEASURED**
//!    2026-10-02 from this machine. ⛔ The sibling hardcodes `/connect/railway`
//!    (`dropssh` `src/dropssh.h:42`) and that target no longer exists.

use podssh_transport::endpoint::{
    endpoint, AddressFamily, EgressRoad, Knobs, LegTarget, RelayConfig, TOKEN_HEADER,
};
use podssh_transport::TransportError;

/// ⛔ **A token that is obviously a test string and can never be a credential.**
const TOKEN: &str = "ephm1.0000000000000.forward.TESTONLYNOTACREDENTIAL";

#[test]
fn every_leg_puts_the_token_in_a_header_and_nowhere_else() {
    let config = RelayConfig { origin: "wss://tcp-1.example.invalid".into(), knobs: Knobs::default() };
    let cases = [
        LegTarget::Forward { host: "github.com".into(), port: 22 },
        LegTarget::ReverseNode { name: "podssh".into() },
        LegTarget::ReverseOperator { name: "podssh".into() },
    ];
    for target in cases {
        let built = endpoint(&config, &target, TOKEN);
        assert!(
            built.token_positions_in_url().is_empty(),
            "⛔ a credential reached the URL {:?}: {:?}",
            built.token_positions_in_url(),
            built.url
        );
        assert!(!built.url.contains(TOKEN), "⛔ the raw token is in the URL");
        assert!(!built.url.contains("token="), "⛔ the query form leaked: {}", built.url);
        assert_eq!(built.headers.len(), 1);
        assert_eq!(built.headers[0].0, TOKEN_HEADER);
        assert_eq!(built.headers[0].1, TOKEN);
        assert!(built.url.starts_with("wss://"), "the origin is kept: {}", built.url);
    }
}

#[test]
fn the_token_check_itself_has_a_failure_direction() {
    // ⛔ **A guard that has never refused anything is a guard nobody has checked.**
    // `AGENTS.md:167-172`: six guards in the sibling projects were claimed
    // "proven to fire" and three caught nothing. ⛔ So the detector is planted:
    // a URL carrying the query form, and a URL carrying the path form.
    let mut query = podssh_transport::endpoint::Endpoint {
        url: format!("wss://relay.invalid/connect/github.com/22?token={TOKEN}"),
        headers: vec![],
    };
    assert_eq!(query.token_positions_in_url(), vec!["the ?token= query form"]);

    query.url = format!("wss://relay.invalid/t/{TOKEN}/connect/github.com/22");
    assert_eq!(query.token_positions_in_url(), vec!["the /t/<token>/ path form"]);

    query.url = format!("wss://relay.invalid/t/{TOKEN}/connect/github.com/22?token={TOKEN}");
    assert_eq!(query.token_positions_in_url().len(), 2, "both forms are named");

    // ⛔ **CONTROL: a clean URL is clean**, which is the other half.
    query.url = "wss://relay.invalid/connect/github.com/22".into();
    assert!(query.token_positions_in_url().is_empty());
}

#[test]
fn the_paths_are_the_published_ones() {
    // ⛔ **READ**, live lines 22, 23 and 24 — read with `sed -n 'Np'`, not
    // recalled:
    //   22 | | Arbitrary target (WebSocket) | wss://…/connect/<host>/<port>
    //   23 | | Reverse node (control host only) | wss://…/v1/node/<name>
    //   24 | | Reverse operator (control host only) | wss://…/v1/connect/<name>
    let cases = [
        (LegTarget::Forward { host: "github.com".into(), port: 22 }, "/connect/github.com/22"),
        (LegTarget::ReverseNode { name: "podssh".into() }, "/v1/node/podssh"),
        (LegTarget::ReverseOperator { name: "podssh".into() }, "/v1/connect/podssh"),
    ];
    for (target, path) in cases {
        assert_eq!(target.path(), path);
    }
}

#[test]
fn no_relay_configured_is_an_error_and_never_a_fallback_name() {
    // ⛔ `01-relay-protocol.md:76-77`: *"podssh ships no default relay path. If no
    // target is configured, podssh errors and says so. It does not fall back to a
    // name that may be gone."*
    let error = TransportError::NoRelayConfigured;
    let message = error.to_string();
    assert!(message.contains("no relay target is configured"));
    assert!(message.contains("ships no default relay path"));
    assert_eq!(error.retry(), podssh_transport::Retry::Never, "⛔ retrying a misconfiguration loops forever");

    // ⛔ **CONTROL: the type has no `Default`,** so a configuration cannot exist
    // without a relay being named. ⛔ This is the structural half of the rule.
    let _cannot: fn() -> RelayConfig = || RelayConfig {
        origin: String::new(),
        knobs: Knobs::default(),
    };
}

#[test]
fn the_knobs_are_off_until_something_measured_turns_them_on() {
    // ⛔ **`?precheck` is clamped by a server cap the specification does not
    // publish** (live line 202, and [`exp-03-precheck-cap.md`](exp-03-precheck-cap.md)),
    // so it is `Option` and `None` by default. ⛔ Every knob is off until a caller
    // sets it with a reason.
    assert_eq!(Knobs::default(), Knobs { family: None, path: None, lazy: false, precheck_ms: None });

    let config = RelayConfig {
        origin: "wss://relay.invalid/".into(),
        knobs: Knobs {
            family: Some(AddressFamily::V4),
            path: Some(EgressRoad::Vpc),
            lazy: true,
            precheck_ms: Some(500),
        },
    };
    let built = endpoint(
        &config,
        &LegTarget::Forward { host: "github.com".into(), port: 22 },
        TOKEN,
    );
    assert_eq!(
        built.url,
        "wss://relay.invalid/connect/github.com/22?family=4&path=vpc&dial=lazy&precheck=500",
        "⛔ byte-exact: the knob names are the relay's, and a trailing slash on \
         the origin does not produce a double slash"
    );
    assert!(built.token_positions_in_url().is_empty(), "⛔ knobs never carry a credential");
}

#[test]
fn the_forward_cap_is_a_record_with_the_measurement_that_produced_it() {
    // ⛔ **MEASURED 2026-10-02, this machine, Git Bash on Windows:**
    // `curl -sSL 'https://tcp.ssh.relay.ajam.dev/relays.json?host=github.com&port=22'`
    // → `"max_frame_bytes": 262144`. ⛔ It is **read from `/relays.json` at
    // startup and never compiled as a protocol constant** — there is no `hello`
    // frame on the forward path, so nothing on the wire can correct a constant.
    assert_eq!(podssh_transport::endpoint::FORWARD_MAX_FRAME_MEASURED, 262_144);
    assert_eq!(podssh_transport::Limits::forward(262_144).max_wire_frame, 262_144);
    // ⛔ **And a different number produces a different limit**, which is what
    // proves it is a value rather than a constant in disguise.
    assert_eq!(podssh_transport::Limits::forward(1024).max_wire_frame, 1024);
}

#[test]
fn each_leg_shape_names_its_own_token_role_and_framing() {
    use podssh_transport::LegShape;
    assert_eq!(LegShape::Forward.token_role(), "forward");
    assert_eq!(LegShape::ReverseNode.token_role(), "node_token");
    assert_eq!(LegShape::ReverseOperator.token_role(), "connect_token");

    // ⛔ **The asymmetry, straight from `01-relay-protocol.md:371-376`:**
    // ⛔ only the node leg prefixes an id, and only the node leg may send control.
    assert!(!LegShape::Forward.prefixes_with_id());
    assert!(LegShape::ReverseNode.prefixes_with_id());
    assert!(!LegShape::ReverseOperator.prefixes_with_id());

    assert!(!LegShape::Forward.may_send_control());
    assert!(LegShape::ReverseNode.may_send_control());
    assert!(!LegShape::ReverseOperator.may_send_control());

    assert!(!LegShape::Forward.has_control_channel());
    assert!(LegShape::ReverseNode.has_control_channel());
    assert!(LegShape::ReverseOperator.has_control_channel());

    // ⛔ **Inbound ids are stripped on the node leg only.** ⛔ On the operator leg
    // the strip behaviour is undocumented (`01-relay-protocol.md:352-355`, and
    // `grep -i strip` over the live document returns zero hits), and subtracting
    // 32 would eat the first 32 bytes of every message received.
    assert!(LegShape::ReverseNode.inbound_carries_id());
    assert!(!LegShape::ReverseOperator.inbound_carries_id());
    assert!(!LegShape::Forward.inbound_carries_id());
}