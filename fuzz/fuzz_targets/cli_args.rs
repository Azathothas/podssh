//! The command line (`podssh_cli::tree::parse`): any words, each ended by a
//! NUL in the input, parse to something with no panic. Only the parse runs:
//! no dispatch, so no target reaches the network or a file.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let words: Vec<String> = data.split(|b| *b == 0).map(|w| String::from_utf8_lossy(w).into_owned()).collect();
    let _ = podssh_cli::tree::parse(words);
});
