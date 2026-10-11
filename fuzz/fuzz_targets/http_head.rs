//! An HTTP response head (`podssh_ws::http::parse_head`), as a relay or a
//! proxy sends it: the reason is safe on one line, and each header name is in
//! lower case and each value trimmed, as the head's readers expect.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::{is_one_line, text};
use podssh_ws::http::parse_head;

fuzz_target!(|data: &[u8]| {
    let Some(head) = text(data) else { return };
    let Ok((_, reason, headers)) = parse_head(head) else { return };
    assert!(is_one_line(&reason), "{reason:?}");
    for (name, value) in headers {
        assert_eq!(name, name.trim().to_ascii_lowercase(), "{name:?}");
        assert_eq!(value, value.trim(), "{value:?}");
    }
});
