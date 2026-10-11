//! `podssh keygen -s` and `-L` as a process (T-021): certificates with the
//! lines and the messages of OpenSSH's `ssh-keygen`. OpenSSH itself reads
//! them, and its sshd lets a user in with one, in `scripts/interop-keygen.sh`;
//! a CA in an agent is in `tests/agent_cli.rs`.

mod cleanup;
mod keygen_support;

use std::path::Path;

use keygen_support::*;

/// A CA and a user key in `dir`: their files.
fn ca_and_user(dir: &Path) -> (String, String) {
    let ca = file(dir, "ca");
    let user = file(dir, "user");
    for (key, comment) in [(&ca, "the-ca"), (&user, "the-user")] {
        let made = podssh(&["keygen", "-q", "-N", "", "-C", comment, "-f", key]);
        assert_eq!(made.code, 0, "{}", made.err);
    }
    (ca, format!("{user}.pub"))
}

fn validity(after: &str, before: &str) -> String {
    let t = |s: &str| podssh_ssh::sshsig::parse_time(s).unwrap() as u64;
    podssh_ssh::cert::format_validity(t(after), t(before))
}

/// `-s` says what `ssh-keygen -s` says and writes FILE-cert.pub; `-L`
/// prints it as `ssh-keygen -L` does.
#[test]
fn a_certificate_is_signed_and_printed() {
    let dir = scratch();
    let (ca, user) = ca_and_user(&dir);
    let args = ["keygen", "-s", &ca, "-I", "the id", "-n", "alice,bob", "-z", "7", "-V", "20260101Z:20270101Z", &user];
    let run = podssh(&args);
    assert_eq!(run.code, 0, "{}", run.err);
    let cert = file(&dir, "user-cert.pub");
    let valid = validity("20260101Z", "20270101Z");
    assert_eq!(run.err, format!("Signed user key {cert}: id \"the id\" serial 7 for alice,bob valid {valid}\n"));
    let text = std::fs::read_to_string(&cert).unwrap();
    assert!(text.starts_with("ssh-ed25519-cert-v01@openssh.com ") && text.trim_end().ends_with(" the-user"), "{text}");
    let shown = podssh(&["keygen", "-L", "-f", &cert]);
    assert_eq!(shown.code, 0, "{}", shown.err);
    let lines: Vec<&str> = shown.out.lines().collect();
    assert_eq!(lines[0], format!("{cert}:"));
    assert_eq!(lines[1], "        Type: ssh-ed25519-cert-v01@openssh.com user certificate");
    assert!(lines[2].starts_with("        Public key: ED25519-CERT SHA256:"), "{}", lines[2]);
    assert!(lines[3].starts_with("        Signing CA: ED25519 SHA256:") && lines[3].ends_with(" (using ssh-ed25519)"));
    assert_eq!(
        lines[4..],
        [
            "        Key ID: \"the id\"",
            "        Serial: 7",
            &format!("        Valid: {valid}"),
            "        Principals: ",
            "                alice",
            "                bob",
            "        Critical Options: (none)",
            "        Extensions: ",
            "                permit-X11-forwarding",
            "                permit-agent-forwarding",
            "                permit-port-forwarding",
            "                permit-pty",
            "                permit-user-rc",
        ]
    );
}

/// A host certificate has no extensions; a certificate that is there is
/// made again, as OpenSSH makes it; `-L` of a plain key says so.
#[test]
fn a_host_certificate_and_a_new_one_in_place() {
    let dir = scratch();
    let (ca, user) = ca_and_user(&dir);
    assert_eq!(podssh(&["keygen", "-q", "-s", &ca, "-I", "first", "-n", "a", &user]).code, 0);
    let run = podssh(&["keygen", "-s", &ca, "-I", "host-id", "-h", &user]);
    assert_eq!(run.code, 0, "{}", run.err);
    let cert = file(&dir, "user-cert.pub");
    assert_eq!(run.err, format!("Signed host key {cert}: id \"host-id\" serial 0 valid forever\n"));
    let shown = podssh(&["keygen", "-L", "-f", &cert]).out;
    for line in [
        "        Type: ssh-ed25519-cert-v01@openssh.com host certificate",
        "        Valid: forever",
        "        Principals: (none)",
        "        Extensions: (none)",
    ] {
        assert!(shown.contains(line), "{line}: {shown}");
    }
    let plain = podssh(&["keygen", "-L", "-f", &user]);
    assert_eq!((plain.code, plain.err), (1, format!("{user}:1 is not a certificate\n")));
}

/// A validity that starts with `-` is the value of `-V`, as getopt takes
/// it: in CI the box's `-V -5m:+1h` was refused as flags (T-021).
#[test]
fn a_validity_may_start_with_a_hyphen() {
    let dir = scratch();
    let (ca, user) = ca_and_user(&dir);
    for spec in ["-5m:+1h", "-2h:-1h"] {
        let run = podssh(&["keygen", "-q", "-s", &ca, "-I", "x", "-n", "a", "-V", spec, &user]);
        assert_eq!(run.code, 0, "-V {spec}: {}", run.err);
    }
    let shown = podssh(&["keygen", "-L", "-f", &file(&dir, "user-cert.pub")]).out;
    assert!(shown.contains("        Valid: from "), "{shown}");
}

/// `-O` sets the options of the certificate, which `-L` names.
#[test]
fn a_certificate_takes_options() {
    let dir = scratch();
    let (ca, user) = ca_and_user(&dir);
    let mut args = vec!["keygen", "-q", "-s", &ca, "-I", "opts", "-n", "alice"];
    for option in [
        "clear",
        "permit-pty",
        "force-command=/bin/true",
        "source-address=192.0.2.0/24",
        "extension:x@example.com=v",
        "critical:y@example.com",
    ] {
        args.extend(["-O", option]);
    }
    args.push(&user);
    let run = podssh(&args);
    assert_eq!(run.code, 0, "{}", run.err);
    let shown = podssh(&["keygen", "-L", "-f", &file(&dir, "user-cert.pub")]).out;
    let tail: Vec<&str> = shown.lines().skip_while(|l| !l.contains("Critical Options")).collect();
    assert_eq!(
        tail,
        [
            "        Critical Options: ",
            "                force-command /bin/true",
            "                source-address 192.0.2.0/24",
            "                y@example.com UNKNOWN FLAG OPTION",
            "        Extensions: ",
            "                permit-pty",
            "                x@example.com UNKNOWN OPTION: 0000000176 (len 5)",
        ]
    );
}

/// What `-s` lacks, or takes wrong, is refused in OpenSSH's words, as a
/// usage error; the flags of a certificate alone are refused too.
#[test]
fn certificate_refusals() {
    let dir = scratch();
    let (ca, user) = ca_and_user(&dir);
    for (args, says) in [
        (vec!["keygen", "-s", &ca, "-n", "a", &user], "Must specify key id (-I) when certifying"),
        (
            vec!["keygen", "-s", &ca, "-I", "x", "-V", "garbage", &user],
            "Invalid certificate life specification garbage",
        ),
        (vec!["keygen", "-s", &ca, "-I", "x", "-V", "20270101:20260101", &user], "Empty certificate validity interval"),
        (vec!["keygen", "-s", &ca, "-I", "x", "-z", "0x10", &user], "Invalid serial number \"0x10\""),
        (
            vec!["keygen", "-s", &ca, "-I", "x", "-O", "frobnicate", &user],
            "Unsupported certificate option \"frobnicate\"",
        ),
        (vec!["keygen", "-s", &ca, "-I", "x", "-t", "ssh-rsa", &user], "rsa-sha2-256 or rsa-sha2-512"),
        (vec!["keygen", "-V", "+1d", "-f", &ca], "-V goes with -s"),
        (vec!["keygen", "-s", &ca, "-I", "x", "-D", "/usr/lib/pkcs11.so", &user], "PKCS#11"),
    ] {
        let run = podssh(&args);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(run.err.contains(says), "{args:?}: {}", run.err);
    }
    assert!(!Path::new(&file(&dir, "user-cert.pub")).exists(), "a refused -s wrote a certificate");
}
