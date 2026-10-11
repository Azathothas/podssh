//! Text from a peer made safe for one line (`podssh_ws::text::one_line`,
//! `SECURITY.md`): no control or bidirectional formatting character is left,
//! whitespace is single spaces between words, and a second pass changes
//! nothing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::{is_one_line, text};
use podssh_ws::text::one_line;

fuzz_target!(|data: &[u8]| {
    let Some(input) = text(data) else { return };
    let safe = one_line(input);
    assert!(is_one_line(&safe), "{safe:?}");
    assert_eq!(one_line(&safe), safe);
});
