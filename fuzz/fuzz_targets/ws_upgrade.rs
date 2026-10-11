//! The answer to the WebSocket upgrade (`podssh_ws::handshake::check_response`),
//! with the key of RFC 6455's example: any head, no panic, and an error that
//! is safe to print.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;
use podssh_ws::handshake::check_response;

fuzz_target!(|data: &[u8]| {
    let Some(head) = text(data) else { return };
    if let Err(e) = check_response(head, "dGhlIHNhbXBsZSBub25jZQ==") {
        let shown = e.to_string();
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7}'), "{shown:?}");
    }
});
