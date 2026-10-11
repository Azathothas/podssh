use serde_json::{json, Value};

use super::*;

fn tools() -> Vec<Value> {
    vec![json!({ "name": "status", "inputSchema": { "type": "object" } })]
}

fn reply(line: &str, era: &mut Era) -> Value {
    match handle(line.as_bytes(), era, &tools()) {
        Action::Reply(value) => value,
        other => panic!("{line}: {other:?}"),
    }
}

fn modern(method: &str, id: u64, extra: Value) -> String {
    let mut params = json!({ "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }});
    if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

#[test]
fn a_line_that_is_not_one_request_gets_its_error() {
    let mut era = Era::default();
    for (line, code) in [
        ("not json", -32700),
        ("{\"jsonrpc\":\"2.0\"", -32700),
        ("[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]", -32600),
        ("7", -32600),
        ("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}", -32600),
        ("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}", -32600),
        ("{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"ping\"}", -32600),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}", -32600),
    ] {
        let r = reply(line, &mut era);
        assert_eq!(r["error"]["code"], code, "{line}: {r}");
        assert_eq!(r["jsonrpc"], "2.0");
    }
    let invalid = [0xff_u8, b'{', b'}'];
    assert!(matches!(handle(&invalid, &mut era, &tools()), Action::Reply(r) if r["error"]["code"] == -32700));
}

#[test]
fn initialize_chooses_a_revision_of_the_handshake() {
    let mut era = Era::default();
    let early = reply(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &mut era);
    assert_eq!((early["id"].clone(), early["error"]["code"].clone()), (json!(1), json!(-32602)), "{early}");
    let ping = reply(r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#, &mut era);
    assert_eq!(ping, json!({ "jsonrpc": "2.0", "id": "p", "result": {} }));
    let line = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18",
        "capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#
        .replace('\n', "");
    let r = reply(&line, &mut era);
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r["result"]["serverInfo"]["name"], "podssh");
    assert_eq!(r["result"]["capabilities"]["tools"], json!({ "listChanged": false }));
    assert!(r["result"].get("resultType").is_none());
    let list = reply(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#, &mut era);
    assert_eq!(list["result"], json!({ "tools": tools() }));
    // A revision that this server does not have: its latest.
    let mut era = Era::default();
    let r =
        reply(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#, &mut era);
    assert_eq!(r["result"]["protocolVersion"], LEGACY[0]);
    let r = reply(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#, &mut Era::default());
    assert_eq!(r["error"]["code"], -32602);
}

#[test]
fn a_request_with_its_version_is_answered_by_itself() {
    let mut era = Era::default();
    let r = reply(&modern("server/discover", 1, json!({})), &mut era);
    assert_eq!(r["result"]["resultType"], "complete");
    assert_eq!(r["result"]["supportedVersions"][0], "2026-07-28");
    assert!(r["result"]["supportedVersions"].as_array().unwrap().contains(&json!("2024-11-05")));
    assert_eq!(r["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "podssh");
    let r = reply(&modern("tools/list", 2, json!({})), &mut era);
    assert_eq!((r["result"]["tools"].clone(), r["result"]["ttlMs"].clone()), (json!(tools()), json!(3_600_000)));
    assert_eq!(r["result"]["cacheScope"], "private");
    let r = reply(&modern("tools/list", 3, json!({ "cursor": "x" })), &mut era);
    assert_eq!(r["error"]["code"], -32602);
    // An unknown revision: the error names the ones this server has.
    let line = modern("tools/list", 4, json!({})).replace("2026-07-28", "1900-01-01");
    let r = reply(&line, &mut era);
    assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(4), json!(-32022)), "{r}");
    assert_eq!(r["error"]["data"]["requested"], "1900-01-01");
    assert!(r["error"]["data"]["supported"].as_array().unwrap().contains(&json!("2026-07-28")));
    // The capabilities of the client are required.
    let line = json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list",
        "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } });
    let r = reply(&line.to_string(), &mut era);
    assert_eq!(r["error"]["code"], -32602, "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("clientCapabilities"));
}

#[test]
fn a_call_names_a_tool_that_the_server_has() {
    let mut era = Era::default();
    let r = reply(&modern("tools/call", 1, json!({ "name": "nope" })), &mut era);
    assert_eq!(
        (r["error"]["code"].clone(), r["error"]["message"].clone()),
        (json!(-32602), json!("Unknown tool: nope"))
    );
    let r = reply(&modern("tools/call", 2, json!({ "name": "status", "arguments": [] })), &mut era);
    assert_eq!(r["error"]["code"], -32602);
    let line = modern("tools/call", 3, json!({ "name": "status", "arguments": { "a": 1 } }));
    match handle(line.as_bytes(), &mut era, &tools()) {
        Action::Call { id, kind, name, arguments } => {
            assert_eq!((id, kind, name.as_str()), (json!(3), Kind::Modern, "status"));
            assert_eq!(Value::Object(arguments), json!({ "a": 1 }));
        }
        other => panic!("{other:?}"),
    }
    let r = reply(&modern("resources/list", 4, json!({})), &mut era);
    assert_eq!(r["error"]["code"], -32601);
}

#[test]
fn notifications_and_responses_get_no_answer() {
    let mut era = Era::default();
    let none = |line: &str, era: &mut Era| handle(line.as_bytes(), era, &tools());
    assert_eq!(none(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &mut era), Action::Nothing);
    assert_eq!(none(r#"{"jsonrpc":"2.0","id":9,"result":{}}"#, &mut era), Action::Nothing);
    assert_eq!(none(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":7}"#, &mut era), Action::Nothing);
    let cancel = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"a","reason":"x"}}"#;
    assert_eq!(none(cancel, &mut era), Action::Cancel(json!("a")));
}

#[test]
fn an_answer_has_the_shape_of_its_revision() {
    let legacy = answer(&json!(1), Kind::Legacy, json!({ "content": [] }));
    assert_eq!(legacy, json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [] } }));
    let modern = answer(&json!("x"), Kind::Modern, json!({ "content": [] }));
    assert_eq!(modern["result"]["resultType"], "complete");
    assert_eq!(modern["result"]["_meta"]["io.modelcontextprotocol/serverInfo"], server_info());
    assert!(!modern.to_string().contains('\n'));
}
