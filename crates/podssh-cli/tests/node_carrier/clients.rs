//! The clients of a carrier (T-595): the copies through a node on one, and
//! the refusals of each client's flags, beside `node_carrier`'s own tests.

use super::*;

/// cp up and down, scp up, and sftp's put and get, each on a node that the
/// run's own stream starts, through the sshd's own SFTP: each file as it was.
#[cfg(unix)]
#[test]
fn the_copies_reach_openssh_s_sshd_through_a_node_on_a_carrier() {
    let home = scratch("carrier-copy");
    let _scratch = Scratch(home.clone());
    let Some((key, sshd)) = openssh_server(&home, true) else { return };
    let carrier = node_exec(&format!("127.0.0.1:{}", sshd.port), "");
    let path = |name: &str| home.join(name).display().to_string();
    assert!(!path("x").contains(' '), "a path that the batch of sftp cannot carry");
    let user = live_harness::this_user();
    let far = |name: &str| format!("node://{user}@box:{}", path(name));
    let want = pattern(300_000);
    std::fs::write(path("here.bin"), &want).unwrap();
    let copy = |verb: &str, rest: &[&str]| run_with(carried(verb, &home, &key, &carrier, rest), Vec::new(), LIMIT);
    let (here, there) = (path("here.bin"), far("there.bin"));
    // cp asks for a bound with no terminal (T-139); scp and sftp need none (T-508).
    let (code, _, err) = copy("cp", &["--timeout", "120s", here.as_str(), there.as_str()]);
    assert_eq!(code, Some(0), "cp up: {err}");
    assert!(std::fs::read(path("there.bin")).unwrap() == want, "cp up: {err}");
    assert!(err.contains("podssh node: box: the carrier's client ended the stream"), "the node's end: {err}");
    let back = path("back.bin");
    let (code, _, err) = copy("cp", &["--timeout", "120s", there.as_str(), back.as_str()]);
    assert_eq!(code, Some(0), "cp down: {err}");
    assert!(std::fs::read(&back).unwrap() == want, "cp down: {err}");
    let scp = far("scp.bin");
    let (code, _, err) = copy("scp", &[here.as_str(), scp.as_str()]);
    assert_eq!(code, Some(0), "scp up: {err}");
    assert!(std::fs::read(path("scp.bin")).unwrap() == want, "scp up: {err}");
    let (put, got, batch) = (path("put.bin"), path("got.bin"), path("batch"));
    std::fs::write(&batch, format!("put {here} {put}\nget {put} {got}\n")).unwrap();
    let node = format!("node://{user}@box");
    let (code, out, err) = copy("sftp", &["-b", batch.as_str(), node.as_str()]);
    assert_eq!(code, Some(0), "sftp: {err}");
    assert!(String::from_utf8_lossy(&out).contains("sftp> put "), "{err}");
    assert!(std::fs::read(&put).unwrap() == want, "sftp's put: {err}");
    assert!(std::fs::read(&got).unwrap() == want, "sftp's get: {err}");
}

/// A client's carrier is its node's one road: a flag of another road, stdio
/// (the client's own), a kind that is no stream, and a destination that is
/// no node are refused before anything starts.
#[test]
fn a_client_s_carrier_takes_no_other_road_and_reaches_a_node_alone() {
    let home = scratch("carrier-client-flags");
    let _scratch = Scratch(home.clone());
    let a = home.join("a");
    std::fs::write(&a, b"a").unwrap();
    let a = a.display().to_string();
    let refused: [&[&str]; 11] = [
        &["pipe", "-", "node:box", "--carrier", "stdio"],
        &["pipe", "-", "tcp:127.0.0.1:1", "--carrier", "exec:cat"],
        &["pipe", "-", "node:box", "--carrier", "exec:cat", "--pair-file", "x"],
        &["ssh", "--carrier", "stdio", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--pair-file", "x", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--direct", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "--derp-server", "derp.example", "node://tester@box", "true"],
        &["ssh", "--carrier", "exec:cat", "tester@example.org", "true"],
        // The exit at the other end of the stream takes it (T-614), but no
        // other road's flag.
        &["ssh", "--carrier", "exec:cat", "--exit", "gw", "--pair-file", "x", "tester@example.org", "true"],
        &[
            "cp",
            "--timeout",
            "30s",
            "--carrier",
            "exec:cat",
            "--relay-host",
            "relay.example",
            a.as_str(),
            "node://tester@box:x",
        ],
        &["scp", "--carrier", "tcp:127.0.0.1:1", a.as_str(), "node://tester@box:x"],
    ];
    for args in refused {
        let (code, out, err) = run_with(podssh(&home, args), Vec::new(), LIMIT);
        assert_eq!(code, Some(64), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out:?}");
        assert!(err.contains("--carrier"), "{args:?}: {err}");
    }
}
