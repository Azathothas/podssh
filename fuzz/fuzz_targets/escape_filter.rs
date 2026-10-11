//! The escape filter of an interactive session (`podssh_ssh::escape`): it
//! never sends more than it was given, and the same input split anywhere into
//! two reads gives the same bytes and commands, up to a disconnect.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ssh::escape::{Command, Escapes};

/// The bytes and commands of `reads`, fed in turn, until a disconnect.
fn run(reads: &[&[u8]]) -> (Vec<u8>, Vec<Command>) {
    let mut escapes = Escapes::new(b'~');
    let (mut sent, mut commands, mut fed) = (Vec::new(), Vec::new(), 0);
    for read in reads {
        let (out, found) = escapes.feed(read);
        fed += read.len();
        sent.extend_from_slice(&out);
        // An escape held at the end of one read goes out with the next, so
        // the bound holds for the stream, not for each read.
        assert!(sent.len() <= fed, "{} bytes sent of {fed}", sent.len());
        commands.extend_from_slice(&found);
        if found.contains(&Command::Disconnect) {
            break;
        }
    }
    (sent, commands)
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, input)) = data.split_first() else { return };
    let whole = run(&[input]);
    let (a, b) = input.split_at(usize::from(cut).min(input.len()));
    assert_eq!(run(&[a, b]), whole, "split at {}", a.len());
});
