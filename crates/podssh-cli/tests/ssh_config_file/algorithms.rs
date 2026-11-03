//! The keywords of a restriction (T-505, Q71): `Ciphers`, `MACs`,
//! `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms` and
//! `CASignatureAlgorithms` filter what podssh offers, read as OpenSSH
//! 10.3p1's `kex_assemble_names` reads them, and `-G` prints each list; a
//! list that leaves nothing is refused before anything connects;
//! `RequiredRSASize` refuses a smaller host key with 255;
//! `PubkeyAcceptedAlgorithms` leaves a key of another algorithm unoffered;
//! and a restriction that podssh does not apply is said once, at the
//! default level, when the user gave it.

use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env};
use podssh_ssh::algorithms::{own, Kind};

use super::login::{direct, offline, server, user_key};
use super::{ssh, ssh_harness, Home};

/// The keywords of `-G`'s lists of algorithms.
const LISTS: [&str; 6] =
    ["ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "casignaturealgorithms"];

/// Whether a line of `-G` is one of the lists of algorithms: podssh's own,
/// which differ from OpenSSH's on purpose.
pub fn is_list(line: &str) -> bool {
    LISTS.iter().any(|k| line.starts_with(&format!("{k} ")))
}

/// The value of `keyword` in `-G -F none WORDS host`.
fn shown(h: &Home, words: &[&str], keyword: &str) -> String {
    let mut all = vec!["-G", "-F", "none"];
    all.extend_from_slice(words);
    all.push("host");
    let lines = dump::lines(&resolve(&ssh(&all), &h.env()).unwrap_or_else(|e| panic!("{words:?}: {e}")));
    let prefix = format!("{keyword} ");
    let found = lines.iter().find_map(|l| l.strip_prefix(&prefix));
    found.unwrap_or_else(|| panic!("no {keyword} in {lines:#?}")).to_string()
}

#[test]
fn algorithms_each_list_and_its_forms_as_g_prints_them() {
    let h = Home::new("algorithms-g");
    let joined = |kind: Kind| own(kind).join(",");
    // podssh's own, with no keyword; RequiredRSASize 1024, as OpenSSH's.
    for kind in Kind::ALL {
        assert_eq!(shown(&h, &[], kind.dumped()), joined(kind), "{kind:?}");
    }
    assert_eq!(shown(&h, &[], "requiredrsasize"), "1024");
    let without_rsa: Vec<String> = own(Kind::CaSignature).into_iter().filter(|n| n != "ssh-rsa").collect();
    let cases = [
        ("Ciphers=aes128-ctr,3des-cbc,aes256-ctr", "ciphers", "aes128-ctr,aes256-ctr".to_string()),
        ("Ciphers=+aes128-cbc", "ciphers", format!("{},aes128-cbc", joined(Kind::Ciphers))),
        ("MACs=-*-etm@openssh.com", "macs", "hmac-sha2-512,hmac-sha2-256".to_string()),
        ("KexAlgorithms=curve25519-sha256", "kexalgorithms", "curve25519-sha256".to_string()),
        (
            "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512",
            "hostkeyalgorithms",
            "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512".to_string(),
        ),
        ("PubkeyAcceptedKeyTypes=ssh-ed25519", "pubkeyacceptedalgorithms", "ssh-ed25519".to_string()),
        ("CASignatureAlgorithms=-ssh-rsa", "casignaturealgorithms", without_rsa.join(",")),
        ("RequiredRSASize=3072", "requiredrsasize", "3072".to_string()),
    ];
    for (option, keyword, want) in cases {
        assert_eq!(shown(&h, &["-o", option], keyword), want, "{option}");
    }
    assert!(shown(&h, &["-o", "Ciphers=^aes128-ctr"], "ciphers").starts_with("aes128-ctr,"));
    // A file's list, whose first value holds; RequiredRSASize from a file.
    let f = h.file("lists", "Host *\n  Ciphers aes128-ctr\n  Ciphers 3des-cbc\n  RequiredRSASize 2048\n");
    let lines = dump::lines(&resolve(&ssh(&["-G", "-F", &f, "host"]), &h.env()).unwrap_or_else(|e| panic!("{e}")));
    assert!(lines.contains(&"ciphers aes128-ctr".to_string()) && lines.contains(&"requiredrsasize 2048".to_string()));
    // The command line's goes before the file's, whose list is then not
    // read, also one that would leave nothing.
    let f = h.file("bad", "Host *\n  Ciphers 3des-cbc\n");
    let lines = dump::lines(&resolve(&ssh(&["-G", "-F", &f, "-o", "Ciphers=aes256-ctr", "host"]), &h.env()).unwrap());
    assert!(lines.contains(&"ciphers aes256-ctr".to_string()), "{lines:#?}");
    // -v names what was left out; a hop of -J takes the command line's lists.
    let r = resolve(&ssh(&["-F", "none", "-o", "Ciphers=aes128-ctr,3des-cbc", "-J", "bastion", "host"]), &h.env())
        .unwrap_or_else(|e| panic!("{e}"));
    let note = "Ciphers aes128-ctr,3des-cbc (-o): podssh does not speak 3des-cbc, and leaves it out";
    assert!(r.notes.iter().any(|n| n == note), "{:?}", r.notes);
    assert_eq!(r.options.algorithms.ciphers, Some(vec!["aes128-ctr".to_string()]));
    assert_eq!(r.options.jump_options[0].algorithms.ciphers, Some(vec!["aes128-ctr".to_string()]));
}

#[test]
fn algorithms_a_list_that_leaves_nothing_is_refused_before_anything_connects() {
    let h = Home::new("algorithms-refused");
    let err = resolve_or_refuse(&ssh(&["-F", "none", "-o", "Ciphers=3des-cbc", "host"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 64, "{}", err.message);
    assert!(
        err.message.contains("-o Ciphers=3des-cbc") && err.message.contains("chacha20-poly1305@openssh.com"),
        "the refusal names what podssh speaks: {}",
        err.message
    );
    for option in [
        "Ciphers=-*",
        "MACs=!hmac-sha1",
        "KexAlgorithms=sntrup761x25519-sha512@openssh.com",
        "PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com",
        "RequiredRSASize=big",
    ] {
        let err = resolve_or_refuse(&ssh(&["-F", "none", "-o", option, "host"]), &h.env()).unwrap_err();
        assert_eq!(err.code, 64, "{option}: {}", err.message);
    }
    let f = h.file("bad", "Host *\n  Ciphers 3des-cbc\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "host"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(
        err.message.contains(&format!("{f}:2: Ciphers=3des-cbc")) && err.message.contains("-o Ciphers=LIST"),
        "the refusal names its line and the way past it: {}",
        err.message
    );
    // The binary, offline: 64, and nothing came near a connection.
    let (rc, err) = offline(&["ssh", "-F", "none", "-o", "Ciphers=3des-cbc", "host", "true"]);
    assert_eq!(rc, 64, "{err}");
    assert!(!err.contains("PODSSH_OFFLINE"), "{err}");
}

/// The test's server with an RSA host key of 2048 bits: podssh's own
/// floor takes it, `RequiredRSASize 4096` refuses it with 255 and its
/// words, from `-o` or a file, and a list of host key algorithms that the
/// server has none of finds no algorithm in common.
#[test]
fn algorithms_required_rsa_size_refuses_a_smaller_host_key_with_255() {
    let h = Home::new("algorithms-rsa");
    let (_runtime, port) = server(&h.0, "rsa", Some("2048"));
    let p = port.to_string();
    let (rc, out, err) = direct(&h.0, &["-p", &p, "tester@127.0.0.1", "greet"]);
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "the default takes it: {err}");
    let (rc, _, err) = direct(&h.0, &["-p", &p, "-o", "RequiredRSASize=4096", "tester@127.0.0.1", "greet"]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("RSA key of 2048 bits") && err.contains("RequiredRSASize 4096"), "{err}");
    let f = h.file("rsa", "Host *\n  RequiredRSASize 3072\n");
    let (rc, _, err) = direct(&h.0, &["-F", &f, "-p", &p, "tester@127.0.0.1", "greet"]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("RequiredRSASize 3072"), "{err}");
    let (rc, _, err) = direct(&h.0, &["-p", &p, "-o", "HostKeyAlgorithms=ssh-ed25519", "tester@127.0.0.1", "greet"]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("in common") && err.contains("ssh-ed25519"), "{err}");
}

/// A login with a key of the user's: `-v` says why one that the list leaves
/// out is not offered, and the server, which wants a key, refuses the run.
fn key_login(h: &Home, port: &str, key: &str, extra: &[&str]) -> (i32, String, String) {
    let mut words = vec!["-v", "-p", port, "-i", key, "-o", "IdentitiesOnly=yes"];
    words.extend_from_slice(extra);
    words.extend(["key-tester@127.0.0.1", "greet"]);
    direct(&h.0, &words)
}

#[test]
fn algorithms_a_key_that_pubkey_accepted_algorithms_leaves_out_is_not_offered() {
    let h = Home::new("algorithms-pubkey");
    let (_runtime, port) = server(&h.0, "ed25519", None);
    let p = port.to_string();
    let key = user_key(&h.0, "ed25519");
    let (rc, out, err) = key_login(&h, &p, &key, &[]);
    assert_eq!((rc, out.as_str()), (0, ssh_harness::GREETING), "{err}");
    let (rc, _, err) = key_login(&h, &p, &key, &["-o", "PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256"]);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("ssh-ed25519 is not in PubkeyAcceptedAlgorithms"), "-v says why: {err}");
}

#[test]
fn algorithms_a_restriction_that_podssh_does_not_apply_is_said_once_for_the_users_own() {
    let h = Home::new("algorithms-noted");
    let f = h.file("noted", "Host *\n  VerifyHostKeyDNS yes\n  VerifyHostKeyDNS no\n  HashKnownHosts yes\n");
    let r = resolve(&ssh(&["-F", &f, "-o", "IPQoS=none", "host"]), &h.env()).unwrap_or_else(|e| panic!("{e}"));
    let dns = format!("VerifyHostKeyDNS yes ({f}:2) is not applied: podssh checks host keys against known_hosts alone");
    assert!(r.warnings.contains(&dns), "{:?}", r.warnings);
    assert!(r.warnings.iter().any(|w| w.starts_with("IPQoS none (-o) is not applied")), "{:?}", r.warnings);
    assert_eq!(r.warnings.iter().filter(|w| w.starts_with("VerifyHostKeyDNS")).count(), 1, "once");
    assert!(r.notes.contains(&format!("{f}:4: HashKnownHosts has no effect in podssh")), "{:?}", r.notes);
    // The same line in the system's file: at -v alone.
    let system = h.file("system_config", "Host *\n  VerifyHostKeyDNS yes\n");
    let env = Env { system_config: Some(system.clone().into()), ..h.env() };
    let r = resolve(&ssh(&["host"]), &env).unwrap_or_else(|e| panic!("{e}"));
    assert!(!r.warnings.iter().any(|w| w.contains("VerifyHostKeyDNS")), "{:?}", r.warnings);
    assert!(r.notes.iter().any(|n| n.starts_with(&format!("VerifyHostKeyDNS yes ({system}:2)"))), "{:?}", r.notes);
    // On stderr at the default level, before anything connects; none with -q.
    let (_, err) = offline(&["ssh", "-F", &f, "-o", "BatchMode=yes", "host", "true"]);
    assert!(err.contains(&dns), "{err}");
    let (_, err) = offline(&["ssh", "-q", "-F", &f, "-o", "BatchMode=yes", "host", "true"]);
    assert!(!err.contains("is not applied"), "-q: {err}");
}
