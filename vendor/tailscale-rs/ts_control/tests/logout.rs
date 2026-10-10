//! The request that logs a node out (podssh's patch 0016): this node's key, and an expiry in the
//! past, which expires that key at once. No auth key goes with it.

use ts_keys::NodeState;

fn body(config: &ts_control::Config, keys: &NodeState) -> serde_json::Value {
    let text = ts_control::logout_body(config, keys).expect("the request serializes");
    serde_json::from_str(&text).expect("the body is JSON")
}

#[test]
fn the_logout_names_this_node_key_and_an_expiry_in_the_past() {
    let keys = NodeState::generate();
    let config = ts_control::Config {
        ephemeral: true,
        ..Default::default()
    };
    let doc = body(&config, &keys);

    assert_eq!(
        doc["NodeKey"],
        serde_json::to_value(keys.node_keys.public).unwrap(),
        "this node's key: {doc}"
    );
    let expiry = doc["Expiry"].as_str().expect("an expiry");
    let expiry = chrono::DateTime::parse_from_rfc3339(expiry).expect("an RFC 3339 time");
    assert!(
        expiry < chrono::Utc::now(),
        "the expiry {expiry} is not in the past"
    );
    assert_eq!(doc["Ephemeral"], true);
    assert!(doc.get("Auth").is_none(), "no auth key: {doc}");
    assert!(doc.get("Followup").is_none(), "no followup: {doc}");
}

#[test]
fn another_node_key_gives_another_request() {
    let (one, two) = (NodeState::generate(), NodeState::generate());
    let config = ts_control::Config::default();
    let (a, b) = (body(&config, &one), body(&config, &two));
    assert_ne!(a["NodeKey"], b["NodeKey"]);
    // A node that is not ephemeral says nothing of it: the field is omitted when false.
    assert!(a.get("Ephemeral").is_none(), "{a}");
}
