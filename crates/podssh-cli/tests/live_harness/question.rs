//! The run of GitHub #114 (T-588): `podssh ssh node://` with ConnectTimeout
//! 25 and nothing that answers the question of a new host key, as a
//! tester's agent ran it, with stdin, stdout and stderr not a terminal.
//! Where nobody can be asked (no terminal, as under a runner of Linux), the
//! key is refused at once. Where a console with no window can ask (a runner
//! of Windows, as the tester's agent), the question waits 60 s, says so 10 s
//! in, and the key is then refused. Never the line of #114, a handshake that
//! did not finish within 25 s: the question waited inside it, on a console
//! that nobody saw, with no bound.

use std::path::Path;
use std::time::{Duration, Instant};

/// The question's 60 s, the handshake around it, and room.
const LIMIT: Duration = Duration::from_secs(150);

/// `podssh ssh` to `destination` through the pair of `pair_file` with the
/// key `key`, a known_hosts file of its own, and no answer to the question:
/// 255 with the refusal of the key and its remedy, and no key recorded. No
/// login comes, so no word of the node's TARGET is printed.
pub fn a_new_key_with_nobody_to_ask(home: &Path, pair_file: &str, key: &Path, destination: &str) {
    let known = home.join("known_hosts_asked");
    let known_option = format!("UserKnownHostsFile={}", known.display());
    let args = [
        "ssh",
        "-T",
        "-vvv",
        "-i",
        key.to_str().unwrap(),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        &known_option,
        "--ConnectTimeout",
        "25",
        "--pair-file",
        pair_file,
        destination,
        "exit 3",
    ];
    let started = Instant::now();
    let (rc, _, err) = super::run_within(home, &args, LIMIT);
    let took = started.elapsed().as_secs();
    assert_eq!(rc, 255, "after {took} s: {err}");
    assert!(!err.contains("did not finish within 25 s"), "the line of #114 again, after {took} s: {err}");
    assert!(err.contains("is not a known host") && err.contains("StrictHostKeyChecking=accept-new"), "{err}");
    assert!(!known.exists(), "a key with no answer is not recorded");
    let asked = err.contains("nobody answered on the terminal");
    if asked {
        assert!(err.contains("waits for the answer to the question of the host key"), "the first word: {err}");
    }
    let how = if asked {
        "the question waited on a console that nobody saw, said so 10 s in, and was refused"
    } else {
        "no terminal to ask on: refused at once"
    };
    eprintln!("podssh ssh {destination} with a new key and nobody to ask: 255 after {took} s; {how}");
}
