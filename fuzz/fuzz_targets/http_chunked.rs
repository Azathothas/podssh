//! A chunked body (`podssh_ws::http::decode_chunked`), as a relay sends it to
//! `https_get`: a body is never longer than its limit, under a small limit
//! and under the largest.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ws::http::decode_chunked;

fuzz_target!(|data: &[u8]| {
    for max in [0, 16, 4096, usize::MAX] {
        if let Ok(Some(body)) = decode_chunked(data, max) {
            assert!(body.len() <= max, "{} bytes past the limit of {max}", body.len());
            assert!(body.len() <= data.len(), "{} bytes from {}", body.len(), data.len());
        }
    }
});
