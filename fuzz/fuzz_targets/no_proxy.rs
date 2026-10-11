//! A `NO_PROXY` list against a host (`podssh_ws::dial::no_proxy_matches`):
//! the first line is the list, the rest the host; `*` matches each host.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;
use podssh_ws::dial::no_proxy_matches;

fuzz_target!(|data: &[u8]| {
    let Some(input) = text(data) else { return };
    let (list, host) = input.split_once('\n').unwrap_or((input, ""));
    let _ = no_proxy_matches(list, host);
    assert!(no_proxy_matches("*", host), "{host:?}");
});
