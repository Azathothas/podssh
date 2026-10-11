//! A line of `known_hosts` (`podssh_ssh::known_hosts::fuzz_parse_line`, the
//! private parser under `cfg(fuzzing)`), as OpenSSH or another program wrote
//! it: any text, no panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;

fuzz_target!(|data: &[u8]| {
    let Some(line) = text(data) else { return };
    let _ = podssh_ssh::known_hosts::fuzz_parse_line(line);
});
