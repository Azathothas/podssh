//! The forms of `-L` and `-D`, each with the line that OpenSSH 10.3p1's
//! `ssh -G -F none` printed for it (measured in the build image,
//! 2026-10-11), and the forms that it refused.

use super::*;

fn dumped_local(spec: &str) -> String {
    local(spec).unwrap_or_else(|e| panic!("{spec}: {e}")).dumped()
}

fn dumped_dynamic(spec: &str) -> String {
    dynamic(spec).unwrap_or_else(|e| panic!("{spec}: {e}")).dumped()
}

#[test]
fn local_forward_forms_print_as_openssh_prints_them() {
    for (spec, openssh) in [
        ("8080:db:5432", "localforward 8080 [db]:5432"),
        ("127.0.0.1:8080:db:5432", "localforward [127.0.0.1]:8080 [db]:5432"),
        (":8081:db:1", "localforward []:8081 [db]:1"),
        ("*:8082:db:2", "localforward [*]:8082 [db]:2"),
        ("localhost:8083:db:3", "localforward [localhost]:8083 [db]:3"),
        ("[::1]:8084:[fd00::1]:5", "localforward [::1]:8084 [fd00::1]:5"),
        ("/tmp/l.sock:db:5432", "localforward /tmp/l.sock [db]:5432"),
        ("8085:/run/remote.sock", "localforward 8085 /run/remote.sock"),
        ("/tmp/a.sock:/tmp/b.sock", "localforward /tmp/a.sock /tmp/b.sock"),
        ("8086:db\\:x:1", "localforward 8086 [db:x]:1"),
        ("8087:[db]:1", "localforward 8087 [db]:1"),
    ] {
        assert_eq!(dumped_local(spec), openssh, "{spec}");
    }
    assert_eq!(local_keyword("8088 db:5432").unwrap().dumped(), "localforward 8088 [db]:5432");
    assert_eq!(local_keyword("[::1]:8089 [db]:5432").unwrap().dumped(), "localforward [::1]:8089 [db]:5432");
}

#[test]
fn dynamic_forward_forms_print_as_openssh_prints_them() {
    for (spec, openssh) in [
        ("1080", "dynamicforward 1080"),
        ("127.0.0.1:1081", "dynamicforward [127.0.0.1]:1081"),
        ("/tmp/socks.sock", "dynamicforward /tmp/socks.sock"),
        ("[::1]:1082", "dynamicforward [::1]:1082"),
    ] {
        assert_eq!(dumped_dynamic(spec), openssh, "{spec}");
    }
    assert_eq!(dynamic_keyword("1083").unwrap().dumped(), "dynamicforward 1083");
}

#[test]
fn the_parts_of_each_form() {
    let spec = local("[::1]:8084:[fd00::1]:5").unwrap();
    assert_eq!(spec.listen, Listen::Port { bind: Some("::1".into()), port: 8084 });
    assert_eq!(spec.target, Target::Tcp { host: "fd00::1".into(), port: 5 });
    assert_eq!(spec.shown, "-L [::1]:8084:[fd00::1]:5");
    let spec = local("/tmp/l.sock:db:5432").unwrap();
    assert_eq!(spec.listen, Listen::Path("/tmp/l.sock".into()));
    let spec = dynamic("1080").unwrap();
    assert_eq!((spec.listen, spec.target), (Listen::Port { bind: None, port: 1080 }, Target::Socks));
    assert_eq!(local(":8081:db:1").unwrap().listen, Listen::Port { bind: Some(String::new()), port: 8081 });
}

#[test]
fn the_forms_that_openssh_refuses_are_refused() {
    for (spec, says) in [
        ("0:db:1", "port of 0"),
        ("8080:db:0", "port of 0 to connect to"),
        ("8090:db:5432:9", "\"db\" is not a port"),
        ("db:5432", "not [bind_address:]port:host:hostport"),
        ("8080", "not [bind_address:]port:host:hostport"),
        ("[::1:8080:db:1", "bracket"),
        ("[::1]x:8080:db:1", "bracket"),
        ("a:1:b:2:c", "more than four fields"),
        ("8080:db:http", "\"http\" is not a port"),
        ("8080::80", "no host"),
        ("8080:db:5432\\", "a \\ at the end"),
    ] {
        let err = local(spec).expect_err(spec);
        assert!(err.starts_with(&format!("-L {spec}: ")) && err.contains(says), "{spec}: {err}");
    }
    for (spec, says) in
        [("0", "port of 0"), ("8080:db:1", "not [bind_address:]port"), ("8080:/x", "not [bind_address:]port")]
    {
        let err = dynamic(spec).expect_err(spec);
        assert!(err.starts_with(&format!("-D {spec}: ")) && err.contains(says), "{spec}: {err}");
    }
    assert!(local_keyword("8080").unwrap_err().contains("expected [bind_address:]port host:hostport"));
    let unset = local("${PODSSH_TEST_NEVER_SET_038}/l.sock:db:1").unwrap_err();
    assert!(unset.contains("${PODSSH_TEST_NEVER_SET_038} is not set"), "{unset}");
}
