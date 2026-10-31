//! `cf://HOST`, the road to a service that `cloudflared` publishes (T-264),
//! as a process: each flag that cannot apply is refused with 64 before
//! anything connects, `PODSSH_OFFLINE` stops it, and a credential of
//! Cloudflare Access that is half there or not one is refused before any
//! connection, naming its variable and never its value. The upgrade itself is
//! tested against a stand-in in `crates/podssh-ws/tests/cloudflare_access.rs`.

use std::process::{Command, Stdio};

const VALUE: &str = "a value of this test with spaces";

/// `podssh ARGS` with `set`, and none of the machine's settings: its code
/// and stderr.
fn podssh(args: &[&str], set: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_TIMEOUT",
        "PODSSH_CF_ACCESS_CLIENT_ID",
        "PODSSH_CF_ACCESS_CLIENT_SECRET",
        "PODSSH_CF_ACCESS_TOKEN",
        "PODSSH_CF_ACCESS_TOKEN_FILE",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(name);
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_cloudflare_destination_is_checked_before_anything_connects() {
    let offline = [("PODSSH_OFFLINE", "1")];
    for (args, says) in [
        (&["ssh", "cf://", "true"][..], "no HOST after cf://"),
        (&["ssh", "cf://ssh.example.org:22", "true"][..], "has no port here"),
        (&["ssh", "-p", "2222", "cf://ssh.example.org", "true"][..], "has no port here"),
        (&["ssh", "--direct", "cf://ssh.example.org", "true"][..], "--direct cannot reach a Cloudflare tunnel"),
        (&["ssh", "-J", "jump.example", "cf://ssh.example.org", "true"][..], "-J hop"),
        (&["ssh", "-4", "cf://ssh.example.org", "true"][..], "-4 and -6 do not apply"),
        (&["ssh", "-o", "HostName=other.example", "cf://ssh.example.org", "true"][..], "HostName"),
        (&["proxy", "cf://ssh.example.org", "22"][..], "takes no PORT"),
        (&["proxy", "cf://me@ssh.example.org"][..], "has no user here"),
        (&["proxy", "--relay-host", "r.example", "cf://ssh.example.org"][..], "the relay's flags do not apply"),
    ] {
        let (rc, err) = podssh(args, &offline);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    let (rc, err) = podssh(&["ssh", "-o", "BatchMode=yes", "cf://ssh.example.org", "true"], &offline);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    let (rc, err) = podssh(&["proxy", "cf://ssh.example.org"], &offline);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
}

/// A cf://HOST name may be a podssh node's quick tunnel (T-300): the
/// channel's keys are taken for it, and checked before anything connects;
/// no key of this client is made before the far end greets as a node, and
/// --no-e2e is refused.
#[test]
fn the_channel_s_flags_are_taken_for_a_cloudflare_name_that_may_be_a_node() {
    let key = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    let offline = [("PODSSH_OFFLINE", "1")];
    for args in [
        &["ssh", "-o", "BatchMode=yes", "--node-key", key, "cf://q.trycloudflare.com", "true"][..],
        &["ssh", "-o", "BatchMode=yes", "--client-key", "no-such.key", "cf://q.trycloudflare.com", "true"][..],
    ] {
        let (rc, err) = podssh(args, &offline);
        assert_eq!(rc, 255, "{args:?}: {err}");
        assert!(err.contains("PODSSH_OFFLINE"), "{args:?}: {err}");
    }
    let (rc, err) = podssh(&["ssh", "--node-key", "not-a-key", "cf://q.trycloudflare.com", "true"], &offline);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("cf://q.trycloudflare.com"), "{err}");
    // A quick tunnel's node always runs the channel.
    let (rc, err) = podssh(&["ssh", "--no-e2e", "cf://q.trycloudflare.com", "true"], &offline);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--no-e2e cannot go with it"), "{err}");
}

/// A service token with no secret, and a token that is not one: refused
/// before any connection (78 for proxy; ssh exits 255), naming the
/// variables, never the value.
#[test]
fn a_bad_credential_of_access_is_refused_before_anything_connects() {
    for (set, names) in [
        (
            &[("PODSSH_CF_ACCESS_CLIENT_ID", "id.access")][..],
            &["PODSSH_CF_ACCESS_CLIENT_ID", "PODSSH_CF_ACCESS_CLIENT_SECRET"][..],
        ),
        (&[("PODSSH_CF_ACCESS_TOKEN", VALUE)][..], &["PODSSH_CF_ACCESS_TOKEN"][..]),
    ] {
        let (rc, err) = podssh(&["proxy", "cf://ssh.example.org"], set);
        assert_eq!(rc, 78, "{set:?}: {err}");
        let (code, said) = podssh(&["ssh", "-o", "BatchMode=yes", "cf://ssh.example.org", "true"], set);
        assert_eq!(code, 255, "{set:?}: {said}");
        for text in [&err, &said] {
            assert!(names.iter().all(|n| text.contains(n)), "{set:?}: {text}");
            assert!(!text.contains(VALUE) && !text.contains("id.access"), "a value was shown: {text}");
        }
    }
}

/// T-347: `-J cf://HOST` takes the tunnel as the road of the run, and the
/// hops after it run in its channels; a tunnel after the first hop, and the
/// flags that cannot reach a tunnel, are refused before anything connects.
#[test]
fn a_cloudflare_tunnel_is_the_road_to_a_first_jump_hop() {
    let offline = [("PODSSH_OFFLINE", "1")];
    for (args, says) in [
        (
            &["ssh", "-J", "jump.example,cf://second.example.org", "dest.example", "true"][..],
            "can only be the first hop",
        ),
        (&["ssh", "--direct", "-J", "cf://jump.example.org", "dest.example", "true"][..], "--direct cannot reach"),
        (&["ssh", "-4", "-J", "cf://jump.example.org", "dest.example", "true"][..], "-4 and -6 do not apply"),
    ] {
        let (rc, err) = podssh(args, &offline);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    // The road is the tunnel, not the relay; the destination keeps its port.
    let args =
        ["ssh", "-v", "-o", "BatchMode=yes", "-p", "2222", "-J", "cf://me@jump.example.org", "dest.example", "true"];
    let (rc, err) = podssh(&args, &offline);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE") && !err.contains("through the relay"), "{err}");
    // The control: a plain first hop goes through the relay.
    let (_, err) =
        podssh(&["ssh", "-v", "-o", "BatchMode=yes", "-J", "jump.example", "dest.example", "true"], &offline);
    assert!(err.contains("through the relay"), "{err}");
}
