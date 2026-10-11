//! A list of relay hosts (`podssh_relay::relay::parse_relay_list`), as
//! `--relay-host` or `PODSSH_RELAY` gives it, and the path of a forward
//! session (`forward_path`) for each host and for the input itself: a path is
//! always `/connect/HOST/PORT`, three segments, with nothing that could add
//! a segment, a query or a line to the request.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;
use podssh_relay::relay::{forward_path, parse_relay_list};

/// The form of a forward path for `host` and `port`.
fn check(host: &str, port: u16) {
    let Ok(path) = forward_path(host, port) else { return };
    assert_eq!(path, format!("/connect/{host}/{port}"));
    assert_eq!(path.split('/').count(), 4, "{path:?}");
    assert!(
        !host.chars().any(|c| matches!(c, '?' | '#' | '%' | '@') || c.is_whitespace() || c.is_control()),
        "{host:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = text(data) else { return };
    if let Ok(relays) = parse_relay_list(input) {
        for relay in relays {
            check(&relay.host, relay.port);
        }
    }
    let port = input.len() as u16;
    check(input, port);
});
