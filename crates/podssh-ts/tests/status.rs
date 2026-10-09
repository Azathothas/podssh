//! `podssh-ts` status-line tests: facts on the line, secrets nowhere.

use podssh_ts::status::StatusFacts;

#[test]
fn the_line_carries_facts_not_secrets() {
    let line =
        StatusFacts { nodekey_prefix: "0a1b2c3d".to_string(), tailnet_ip: "100.64.0.7".to_string(), home_region: 901 }
            .render();
    assert_eq!(line, "node 0a1b2c3d… ip 100.64.0.7 home 901");
}
