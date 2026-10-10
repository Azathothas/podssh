//! `ssh_config` files (T-043): `~/.ssh/config`, `-F FILE` and
//! `PODSSH_SSH_CONFIG`, read as OpenSSH 10.3p1 reads them (`docs/cli.md`,
//! section "ssh_config"). Nothing connects.

use std::path::PathBuf;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env};
use podssh_cli::tree::{parse, Parsed};
use podssh_ssh::StrictHostKeyChecking;

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

/// A scratch directory of this test run, as HOME; removed when dropped, so
/// that a failed test leaves nothing behind either.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ssh")).expect("a scratch home");
        Home(dir)
    }

    fn env(&self) -> Env {
        Env { home: Some(self.0.clone()), user: Some("envuser".into()), ..Default::default() }
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("a config file");
        path.display().to_string()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_first_value_wins_and_a_negated_pattern_excludes() {
    let h = Home::new("first");
    let f = h.file(
        "first",
        "# a comment\n\
         Host alias\n  HostName example.org\n  Port 2222\n  User alice\n  IdentityFile ~/.ssh/k1\n\n\
         Host *\n  Port 2200\n  User bob\n  IdentityFile ~/.ssh/k2\n  StrictHostKeyChecking=accept-new\n",
    );
    let r = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.options.destination.host, "example.org");
    assert_eq!((r.options.destination.port, r.options.user.as_str()), (2222, "alice"));
    assert_eq!(r.options.identity_files, [h.0.join(".ssh/k1"), h.0.join(".ssh/k2")]);
    assert_eq!(r.options.strict_host_key_checking, StrictHostKeyChecking::AcceptNew);
    let r = resolve(&ssh(&["-F", &f, "other"]), &h.env()).unwrap();
    assert_eq!((r.options.destination.host.as_str(), r.options.destination.port), ("other", 2200));

    let f = h.file("negated", "Host * !alias\n  Port 2300\nHost alias\n  Port 2400\n");
    assert_eq!(resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap().options.destination.port, 2400);
    assert_eq!(resolve(&ssh(&["-F", &f, "alias.other"]), &h.env()).unwrap().options.destination.port, 2300);
}

#[test]
fn a_pattern_matches_the_host_as_typed_with_its_case() {
    let h = Home::new("case");
    let f = h.file("case", "Host MyHost\n  Port 2301\nHost myhost\n  Port 2302\n");
    let port = |host: &str| resolve(&ssh(&["-F", &f, host]), &h.env()).unwrap().options.destination.port;
    assert_eq!((port("MyHost"), port("myhost"), port("MYHOST")), (2301, 2302, 22));
}

#[test]
fn the_command_line_beats_the_file() {
    let h = Home::new("beats");
    let f = h.file(
        "beats",
        "Host alias\n  User filed\n  Port 2222\n  StrictHostKeyChecking yes\n  IdentityFile ~/.ssh/filed\n",
    );
    let r = resolve(&ssh(&["-F", &f, "-o", "StrictHostKeyChecking=no", "-i", "/k/cli", "u@alias:2000"]), &h.env())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((r.options.user.as_str(), r.options.destination.port), ("u", 2000), "user@host and host:PORT beat it");
    assert_eq!(r.options.strict_host_key_checking, StrictHostKeyChecking::No, "-o beats it");
    assert_eq!(r.options.identity_files, [PathBuf::from("/k/cli"), h.0.join(".ssh/filed")], "-i and the file add up");
    let r = resolve(&ssh(&["-F", &f, "-l", "l", "-p", "2100", "alias"]), &h.env()).unwrap();
    assert_eq!((r.options.user.as_str(), r.options.destination.port), ("l", 2100));
    let r = resolve(&ssh(&["-F", &f, "-o", "User=o", "-o", "Port=2050", "alias"]), &h.env()).unwrap();
    assert_eq!((r.options.user.as_str(), r.options.destination.port), ("o", 2050));
}

#[test]
fn the_default_file_is_read_and_none_reads_nothing() {
    let h = Home::new("default");
    h.file(".ssh/config", "Host alias\n  Port 2222\n");
    assert_eq!(resolve(&ssh(&["alias"]), &h.env()).unwrap().options.destination.port, 2222);
    for none in ["none", "/dev/null", "NUL"] {
        assert_eq!(resolve(&ssh(&["-F", none, "alias"]), &h.env()).unwrap().options.destination.port, 22, "{none}");
    }
    // The variable names a file, as -F does; -F wins.
    let other = h.file("other", "Host alias\n  Port 2300\n");
    let with = Env { ssh_config: Some(other), ..h.env() };
    assert_eq!(resolve(&ssh(&["alias"]), &with).unwrap().options.destination.port, 2300);
    assert_eq!(resolve(&ssh(&["-F", "none", "alias"]), &with).unwrap().options.destination.port, 22);
}

#[test]
fn a_missing_given_file_is_78_and_a_missing_default_is_nothing() {
    let h = Home::new("missing");
    let gone = h.0.join("gone").display().to_string();
    let err = resolve_or_refuse(&ssh(&["-F", &gone, "alias"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(err.message.contains("gone"), "{}", err.message);
    // No ~/.ssh/config at all: no error.
    assert_eq!(resolve(&ssh(&["alias"]), &h.env()).unwrap().options.destination.port, 22);
}

#[test]
fn match_and_include_are_refused_with_file_and_line() {
    let h = Home::new("match");
    let f = h.file("match", "Host alias\n  Port 2222\nMatch host alias\n  HostName elsewhere\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(err.message.contains(&format!("{f}:3: Match")), "{}", err.message);
    let f = h.file("include", "Include other\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.message.contains(&format!("{f}:1: Include")), "{}", err.message);
    // In a block that does not apply, Include is not reached; Match always is.
    let f = h.file("other", "Host other\n  Include more\nHost alias\n  Port 2223\n");
    assert_eq!(resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap().options.destination.port, 2223);
}

#[test]
fn an_unknown_keyword_is_refused_unless_ignore_unknown_names_it_first() {
    let h = Home::new("unknown");
    let f = h.file("unknown", "Host alias\n  NoSuchThing yes\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.message.contains(&format!("{f}:2:")) && err.message.contains("unknown option"), "{}", err.message);
    let f = h.file("ignored", "IgnoreUnknown NoSuch*\nHost alias\n  NoSuchThing yes\n  Port 2222\n");
    assert_eq!(resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap().options.destination.port, 2222);
    // The first IgnoreUnknown holds, as in OpenSSH; the command line's is first.
    let f = h.file("twice", "IgnoreUnknown Foo*\nIgnoreUnknown Bar*\nHost alias\n  BarThing yes\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.message.contains(&format!("{f}:4:")), "{}", err.message);
    resolve(&ssh(&["-F", &f, "-o", "IgnoreUnknown=Bar*", "alias"]), &h.env()).unwrap_or_else(|e| panic!("{e}"));
    // A keyword that -o refuses is refused in a file too, with its place.
    let f = h.file("refused", "Host alias\n  LocalForward 8080 db:5432\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.message.contains(&format!("{f}:2:")) && err.message.contains("local listener"), "{}", err.message);
}

#[test]
fn a_comment_may_follow_a_value_and_host_name_takes_the_host_as_typed() {
    let h = Home::new("comment");
    let f = h.file("comment", "Host alias # the alias\n  HostName %h.Example.org\n  Port 2222 # the port\n");
    let r = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((r.options.destination.host.as_str(), r.options.destination.port), ("alias.Example.org", 2222));
    assert!(dump::lines(&r).contains(&"hostname alias.example.org".to_string()), "OpenSSH lowercases it");
    let f = h.file("token", "Host alias\n  HostName %p.example.org\n");
    let err = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.contains("%p") && err.contains("%h"), "{err}");
}

#[test]
fn a_proxy_command_that_runs_podssh_proxy_is_accepted() {
    let h = Home::new("proxy");
    for line in ["podssh proxy %h %p", "exec /usr/local/bin/podssh proxy %h %p", r"C:\bin\podssh.exe proxy %h %p"] {
        let f = h.file("podssh", &format!("Host alias\n  ProxyCommand {line}\n  Port 2222\n"));
        let r = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(r.options.destination.port, 2222, "{line}");
    }
    let f = h.file("flags", "Host alias\n  ProxyCommand podssh proxy --relay-host r.example %h %p\n");
    let err = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
    assert!(err.contains(&format!("{f}:2:")) && err.contains("podssh proxy %h %p"), "{err}");
    let f = h.file("other", "Host alias\n  ProxyCommand nc %h %p\n");
    assert!(resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err().contains(&format!("{f}:2:")));
}

/// OpenSSH checks the owner and the mode of `~/.ssh/config` alone, on the
/// file that a link names: measured with OpenSSH 10.3p1 on Linux.
#[cfg(unix)]
#[test]
fn the_default_file_must_be_closed_to_others_and_a_link_is_followed() {
    use std::os::unix::fs::PermissionsExt;
    let h = Home::new("mode");
    let real = h.file("real", "Host alias\n  Port 2222\n");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&real, h.0.join(".ssh/config")).unwrap();
    assert_eq!(resolve(&ssh(&["alias"]), &h.env()).unwrap().options.destination.port, 2222);
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o664)).unwrap();
    let err = resolve_or_refuse(&ssh(&["alias"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(err.message.contains("bad owner or permissions"), "{}", err.message);
    // A file that -F names is the user's choice, as in OpenSSH.
    assert_eq!(resolve(&ssh(&["-F", &real, "alias"]), &h.env()).unwrap().options.destination.port, 2222);
}

/// `User` and `RemoteCommand` with tokens (T-273), and what OpenSSH 10.3p1's
/// `ssh -G -F FILE` printed for each command line: a `User` of `-o` or of the
/// file is expanded, `-l` and `user@host` are taken as they are, `%r` is the
/// user, and `HostKeyAlias` is lowercased.
#[rustfmt::skip]
const TOKENS: &[(&[&str], &str, &str, &str)] = &[
    (&["alias"], "u-alias.example.org-2222-alias-alias", "2222",
        "echo alias.example.org 2222 u-alias.example.org-2222-alias-alias alias alias  %"),
    (&["-J", "jump.example", "alias"], "u-alias.example.org-2222-alias-alias", "2222",
        "echo alias.example.org 2222 u-alias.example.org-2222-alias-alias alias alias jump.example %"),
    (&["-o", "User=o-%h", "-p", "2300", "alias"], "o-alias.example.org", "2300",
        "echo alias.example.org 2300 o-alias.example.org alias alias  %"),
    (&["-l", "l-%h", "alias"], "l-%h", "2222", "echo alias.example.org 2222 l-%h alias alias  %"),
    (&["-o", "HostKeyAlias=Alias.K", "alias"], "u-alias.example.org-2222-alias-alias.k", "2222",
        "echo alias.example.org 2222 u-alias.example.org-2222-alias-alias.k alias alias.k  %"),
    (&["c@alias"], "c", "2222", "echo alias.example.org 2222 c alias alias  %"),
];

#[test]
fn user_and_remote_command_take_the_tokens_as_openssh_10_3_does() {
    let h = Home::new("tokens");
    let f = h.file(
        "tokens",
        "Host alias\n  HostName %h.example.org\n  Port 2222\n  User u-%h-%p-%n-%k\n  \
         RemoteCommand echo %h %p %r %n %k %j %%\n",
    );
    for (words, user, port, command) in TOKENS {
        let mut all = vec!["-G", "-F", f.as_str()];
        all.extend_from_slice(words);
        let lines = dump::lines(&resolve(&ssh(&all), &h.env()).unwrap_or_else(|e| panic!("{words:?}: {e}")));
        for line in [format!("user {user}"), format!("port {port}"), format!("remotecommand {command}")] {
            assert!(lines.contains(&line), "{words:?}: {line:?} in {lines:#?}");
        }
    }
    let lines =
        dump::lines(&resolve(&ssh(&["-G", "-F", &f, "-o", "HostKeyAlias=Alias.K", "alias"]), &h.env()).unwrap());
    assert!(lines.contains(&"hostkeyalias alias.k".to_string()), "{lines:#?}");
    // The tokens that OpenSSH refuses here, each by name.
    for (text, token) in [("User x-%r", "%r"), ("User x-%C", "%C"), ("RemoteCommand echo %T", "%T")] {
        let f = h.file("refused", &format!("Host alias\n  {text}\n"));
        let err = resolve(&ssh(&["-F", &f, "alias"]), &h.env()).unwrap_err();
        assert!(err.contains(token), "{text}: {err}");
    }
}

/// The fixture, and what OpenSSH 10.3p1 printed for it: `ssh -G -F FIXTURE`
/// with each case's words, kept to the keywords that podssh prints.
const FIXTURE: &str = "# A fixture of ssh_config, read by OpenSSH 10.3p1 and by podssh
IgnoreUnknown UseKeychain

Host alias
  HostName %h.example.org
  Port 2222 # a comment after a value
  User alice
  IdentityFile /keys/alias
  UseKeychain yes

Host MyHost
  Port 2300

Host *.internal !gate.internal
  ProxyJump gate.internal
  StrictHostKeyChecking=accept-new

Host *
  User bob
  Port 2200
  IdentityFile /keys/all
  ServerAliveInterval 30
  ConnectTimeout 7
  StrictHostKeyChecking yes
  UserKnownHostsFile /kh/user
  GlobalKnownHostsFile none
";

/// The lines that each case shares, between its own lines.
const SAME: &str = "addressfamily any
batchmode no
compression no
exitonforwardfailure no
identitiesonly no
kbdinteractiveauthentication yes
passwordauthentication yes
pubkeyauthentication true
requesttty auto
sessiontype default
stdinnull no";
const COUNTS: &str = "connectionattempts 1
numberofpasswordprompts 3
serveralivecountmax 3
serveraliveinterval 30
loglevel INFO";
const FILES: &str = "globalknownhostsfile none
userknownhostsfile /kh/user
connecttimeout 7
escapechar ~";

/// Each case: the words, then OpenSSH's lines before `SAME`, its
/// `stricthostkeychecking`, its identity files, and what follows `FILES`.
#[rustfmt::skip]
const CASES: &[(&[&str], &str, &str, &str, &str)] = &[
    (&["alias"], "host alias\nuser alice\nhostname alias.example.org\nport 2222", "true",
        "identityfile /keys/alias\nidentityfile /keys/all", ""),
    (&["MyHost"], "host MyHost\nuser bob\nhostname myhost\nport 2300", "true", "identityfile /keys/all", ""),
    (&["myhost"], "host myhost\nuser bob\nhostname myhost\nport 2200", "true", "identityfile /keys/all", ""),
    (&["db.internal"], "host db.internal\nuser bob\nhostname db.internal\nport 2200", "accept-new",
        "identityfile /keys/all", "proxyjump gate.internal"),
    (&["gate.internal"], "host gate.internal\nuser bob\nhostname gate.internal\nport 2200", "true",
        "identityfile /keys/all", ""),
    (&["-p", "2000", "-l", "carol", "-o", "StrictHostKeyChecking=no", "alias"],
        "host alias\nuser carol\nhostname alias.example.org\nport 2000", "false",
        "identityfile /keys/alias\nidentityfile /keys/all", ""),
];

#[test]
fn podssh_reads_the_fixture_as_openssh_10_3_reads_it() {
    let h = Home::new("fixture");
    let f = h.file("fixture", FIXTURE);
    for (words, head, strict, identities, tail) in CASES {
        let mut all = vec!["-G", "-F", f.as_str()];
        all.extend_from_slice(words);
        let ours = dump::lines(&resolve(&ssh(&all), &h.env()).unwrap_or_else(|e| panic!("{words:?}: {e}")));
        let theirs = format!("{head}\n{SAME}\nstricthostkeychecking {strict}\n{COUNTS}\n{identities}\n{FILES}\n{tail}");
        let theirs: Vec<&str> = theirs.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(ours, theirs, "{words:?}");
    }
}
