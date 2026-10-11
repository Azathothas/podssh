//! A proxy's answer to CONNECT (`podssh_ws::dial::parse_status_line`): its
//! reason goes to the user's terminal, so it is safe on one line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::{is_one_line, text};
use podssh_ws::dial::parse_status_line;

fuzz_target!(|data: &[u8]| {
    let Some(head) = text(data) else { return };
    if let Ok((_, reason)) = parse_status_line(head) {
        assert!(is_one_line(&reason), "{reason:?}");
    }
});
