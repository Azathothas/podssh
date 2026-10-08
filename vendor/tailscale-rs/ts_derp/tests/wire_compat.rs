//! M1 — offline wire compatibility of the ClientInfo payload.
//!
//! The relay at `tcp.ts.relay.ajam.dev` parses the ClientInfo JSON by exact
//! camelCase property name and ignores unknown properties: it looks for
//! `meshKey` and never at `mesh_key` (`worker/src/derp/login.ts`). A `meshKey`
//! property makes the relay close the connection with 1008 "mesh not
//! supported" (or "bad client info" when its value is not 64-hex), while its
//! absence lets the connection proceed to admission.
//!
//! `ClientInfoPayload` has no serde rename, so the JSON on the wire is
//! snake_case and the relay never sees a `meshKey` property — that name
//! mismatch is the entire reason this handshake is compatible. This test pins
//! the contract, and plants the exact regression it exists to catch: a
//! camelCase payload, which the same predicate must reject. A test that cannot
//! fail is not a test.

use ts_derp::frame::ClientInfoPayload;

/// The exact payload that `Client::handshake` sends, in serialization order.
const EXPECTED: &str = r#"{"can_ack_pings":false,"is_prober":false,"mesh_key":"none","version":2}"#;

/// The relay-compatibility predicate: exactly these bytes, and no `meshKey`.
fn relay_compatible(json: &str) -> bool {
    json == EXPECTED && !json.contains(r#""meshKey""#)
}

fn payload_json() -> String {
    let payload = ClientInfoPayload {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_owned(),
        version: 2,
    };
    let bytes = serde_json::to_vec(&payload).expect("serialize ClientInfoPayload");
    String::from_utf8(bytes).expect("ClientInfoPayload JSON is UTF-8")
}

#[test]
fn client_info_is_the_exact_expected_snake_case_json() {
    let json = payload_json();

    assert_eq!(
        json, EXPECTED,
        "the ClientInfo JSON changed; the relay reads camelCase `meshKey` and must not see one"
    );
    assert!(
        !json.contains(r#""meshKey""#),
        "the wire JSON grew a `meshKey` property; the relay closes 1008 when it is present"
    );
    assert!(relay_compatible(&json));
}

/// Self-plant: a full camelCase rename is the regression this contract fears,
/// and the predicate must reject it.
#[test]
fn relay_predicate_rejects_camel_case_rename() {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CamelCaseShadow {
        can_ack_pings: bool,
        is_prober: bool,
        mesh_key: String,
        version: i32,
    }

    let json = serde_json::to_string(&CamelCaseShadow {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_owned(),
        version: 2,
    })
    .expect("serialize shadow");

    assert!(
        json.contains(r#""meshKey""#),
        "the shadow did not produce a meshKey property: {json}"
    );
    assert!(
        !relay_compatible(&json),
        "the compatibility predicate accepted a camelCase payload: {json}"
    );
}

/// Self-plant, narrower: renaming only `mesh_key` produces a payload that
/// differs from the expected bytes by exactly the `meshKey` property, so the
/// `meshKey` clause is the only one that can reject it.
#[test]
fn relay_predicate_rejects_mesh_key_rename_alone() {
    #[derive(serde::Serialize)]
    struct MeshKeyRenamedShadow {
        can_ack_pings: bool,
        is_prober: bool,
        #[serde(rename = "meshKey")]
        mesh_key: String,
        version: i32,
    }

    let json = serde_json::to_string(&MeshKeyRenamedShadow {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_owned(),
        version: 2,
    })
    .expect("serialize shadow");

    assert!(
        !relay_compatible(&json),
        "the compatibility predicate accepted a payload with a meshKey property: {json}"
    );
}
