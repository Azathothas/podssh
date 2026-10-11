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
