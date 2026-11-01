//! The control stream of a quick tunnel (`podssh_relay::quick::control`,
//! T-403), as the edge writes to it: its frames of Cap'n Proto's RPC read
//! with no panic within the control stream's budget, and the same bytes in
//! one piece or cut anywhere in two end the same way: with the same failure,
//! or with the same events and the same bytes to send back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_relay::quick::control::{Control, Event, Failure};
use podssh_relay::quick::register::{Registration, FEATURES};

/// The registration of the tests of `quick::capnp`, as any node makes one.
fn registration() -> Registration<'static> {
    Registration {
        account_tag: "0123456789abcdef0123456789abcdef",
        secret: &[7; 32],
        tunnel_id: [0x8e; 16],
        conn_index: 0,
        client_id: [0xf1; 16],
        features: FEATURES,
        version: "podssh fuzz",
        arch: "linux_amd64",
    }
}

/// What `pieces`, fed in turn, gave: the failure that ended them, or each
/// event and each byte to send back. The events of a call that failed are
/// not returned, so they are compared only where none failed.
fn run(pieces: &[&[u8]]) -> Result<(Vec<Event>, Vec<u8>), Failure> {
    let (mut control, _) = Control::register(&registration());
    let (mut events, mut out) = (Vec::new(), Vec::new());
    for piece in pieces {
        let (more, back) = control.feed(piece)?;
        events.extend(more);
        out.extend(back);
    }
    let _ = control.unregister();
    Ok((events, out))
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, input)) = data.split_first() else { return };
    let whole = run(&[input]);
    let (a, b) = input.split_at(usize::from(cut).min(input.len()));
    assert_eq!(run(&[a, b]), whole, "cut at {}", a.len());
});
