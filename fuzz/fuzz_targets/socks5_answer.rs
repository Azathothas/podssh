//! A SOCKS5 proxy's answers (`podssh_ws::fuzz_exchange`, T-070): the first
//! byte chooses whether the URL has credentials and whether the target goes
//! by name; the rest is what the proxy says before it ends. The exchange ends
//! at once, as the proxy is always ready, and never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&choice, answer)) = data.split_first() else { return };
    let _ = podssh_ws::fuzz_exchange(answer, choice & 1 != 0, choice & 2 != 0);
});
