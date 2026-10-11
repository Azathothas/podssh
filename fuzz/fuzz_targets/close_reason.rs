//! A Close frame's payload (`podssh_ws::session::close_code_and_reason`), as
//! the relay sends it: the code is the first two bytes when there are two, and
//! the reason, which goes to the user's terminal, is safe on one line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::is_one_line;
use podssh_ws::session::close_code_and_reason;

fuzz_target!(|data: &[u8]| {
    let (code, reason) = close_code_and_reason(data);
    match data {
        [a, b, ..] => assert_eq!(code, Some(u16::from_be_bytes([*a, *b]))),
        _ => assert_eq!((code, reason.as_str()), (None, "")),
    }
    assert!(is_one_line(&reason), "{reason:?}");
});
