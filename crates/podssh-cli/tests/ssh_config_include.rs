//! `Include`, `Match all`, `Match final all` and the system's file (T-044),
//! against what OpenSSH 10.3p1's `ssh -G` gave for the same files, measured
//! in the build image on 2026-10-10 (`docs/cli.md`, section "ssh_config").
//! Nothing connects.

use std::path::PathBuf;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env};
use podssh_cli::tree::{parse, Parsed};

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

/// A scratch HOME and a system directory of one test, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-include-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ssh")).expect("a scratch home");
        std::fs::create_dir_all(dir.join("etc")).expect("a scratch system directory");
        Home(dir)
    }

    /// No system file.
    fn env(&self) -> Env {
        Env { home: Some(self.0.clone()), user: Some("lu0".into()), ..Default::default() }
    }

    /// With the system file `etc/ssh_config` of this home.
    fn env_system(&self) -> Env {
        Env { system_config: Some(self.0.join("etc").join("ssh_config")), ..self.env() }
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).expect("a config file");
        path.display().to_string().replace('\\', "/")
    }

    fn root(&self) -> String {
        self.0.display().to_string().replace('\\', "/")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn port(words: &[&str], env: &Env) -> u16 {
    resolve(&ssh(words), env).unwrap_or_else(|e| panic!("{words:?}: {e}")).options.destination.port
}

fn lines(words: &[&str], env: &Env) -> Vec<String> {
    let mut all = vec!["-G"];
    all.extend_from_slice(words);
    dump::lines(&resolve(&ssh(&all), env).unwrap_or_else(|e| panic!("{words:?}: {e}")))
}

#[test]
fn a_relative_include_starts_from_dot_ssh_for_a_file_of_f_and_for_the_users() {
    let h = Home::new("relative");
    h.file(".ssh/rel.conf", "Port 2101\n");
    let f = h.file("f1", "Include rel.conf\n");
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2101);
    h.file(".ssh/config", "Include rel.conf\n");
    assert_eq!(port(&["x"], &h.env()), 2101);
}

#[test]
fn an_include_takes_tilde_and_the_tokens() {
    let h = Home::new("tilde");
    h.file(".ssh/conf.d/x.conf", "Port 2102\n");
    let f = h.file("f2", "Include ~/.ssh/conf.d/%n.conf\n");
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2102);
}

#[test]
fn an_include_glob_reads_each_name_in_order_also_with_a_wildcard_in_a_directory() {
    let h = Home::new("glob");
    h.file("inc/d1/a.conf", "Port 2103\n");
    h.file("inc/d2/a.conf", "Port 2104\n");
    h.file("inc/d1/b.conf", "Port 2105\n");
    let r = h.root();
    let f = h.file("f3", &format!("Include {r}/inc/d*/a.conf\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2103);
    let f = h.file("f4a", &format!("Include {r}/inc/d1/b.conf {r}/inc/d1/a.conf\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2105, "the arguments in order");
    let f = h.file("f4b", &format!("Include {r}/inc/d1/*.conf\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2103, "the names of a glob, sorted");
    // A directory that the glob names is skipped; a missing file is no error.
    h.file("inc/d1/dir.conf/inner", "");
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2103);
    let f = h.file("f10", &format!("Include {r}/inc/no-such.conf\nPort 2114\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2114);
}

#[test]
fn an_include_applies_with_its_block_and_its_host_lines_end_with_its_file() {
    let h = Home::new("blocks");
    h.file("inc/b.conf", "Port 2105\n");
    h.file("inc/a.conf", "Port 2104\n");
    h.file("inc/host.conf", "Host y\n  Port 2106\n");
    let r = h.root();
    let f = h.file("f5", &format!("Host other\n  Include {r}/inc/b.conf\nHost x\n  Include {r}/inc/a.conf\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2104);
    let f = h.file("f6", &format!("Host x\n  Include {r}/inc/host.conf\n  Port 2107\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2107);
}

#[test]
fn a_loop_of_includes_is_refused_with_the_chain_and_include_needs_a_file() {
    let h = Home::new("loop");
    let f = h.file("f7", "");
    h.file("f7", &format!("Include {f}\n"));
    let err = resolve_or_refuse(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(err.message.contains("nested includes") && err.message.contains(" -> "), "{}", err.message);
    let f = h.file("fe", "Include\n");
    let err = resolve_or_refuse(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_err();
    assert!(err.message.contains(&format!("{f}:1:")), "{}", err.message);
}

#[test]
fn match_all_applies_where_it_stands_and_match_final_all_fills_what_is_unset() {
    let h = Home::new("final");
    let user_port = |words: &[&str]| {
        let o = resolve(&ssh(words), &h.env()).unwrap_or_else(|e| panic!("{e}")).options;
        (o.user, o.destination.port)
    };
    let f = h.file("f9a", "Match all\n  Port 2109\nHost x\n  Port 2110\n  User hu\n");
    assert_eq!(user_port(&["-F", &f, "x"]), ("hu".into(), 2109));
    let f = h.file("f9b", "Host x\n  User hu\nMatch final all\n  Port 2111\n  User fu\n");
    assert_eq!(user_port(&["-F", &f, "x"]), ("hu".into(), 2111));
    let f = h.file("f9c", "Match final all\n  Port 2112\nHost x\n  Port 2113\n");
    assert_eq!(user_port(&["-F", &f, "x"]), ("lu0".into(), 2113));
    // Each other Match is still refused by name.
    let f = h.file("f9d", "Match host x\n  Port 2114\n");
    assert!(resolve(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_err().contains(&format!("{f}:1: Match")));
}

#[test]
fn the_system_file_comes_after_the_users_and_its_relative_include_starts_from_its_directory() {
    let h = Home::new("system");
    h.file("etc/sys-rel.conf", "Port 2115\n");
    h.file("etc/ssh_config", "Include sys-rel.conf\n");
    assert_eq!(port(&["x"], &h.env_system()), 2115);
    h.file(".ssh/config", "Port 2200\n");
    assert_eq!(port(&["x"], &h.env_system()), 2200, "the user's file first");
    // -F reads no other file, and none reads nothing.
    let f = h.file("given", "User g\n");
    assert_eq!(port(&["-F", &f, "x"], &h.env_system()), 22);
    assert_eq!(port(&["-F", "none", "x"], &h.env_system()), 22);
}

#[test]
fn the_system_files_of_fedora_42_and_debian_13_are_read() {
    let h = Home::new("distros");
    // Fedora 42, as its packages write them, with the crypto policy's
    // keywords of the GSSAPI patch.
    h.file("etc/ssh_config", "Include ssh_config.d/*.conf\n");
    h.file(
        "etc/ssh_config.d/50-redhat.conf",
        &format!(
            "Match final all\n\tInclude {}/etc/openssh.config\n\tGSSAPIAuthentication yes\n\tForwardX11Trusted yes\n",
            h.root()
        ),
    );
    h.file(
        "etc/openssh.config",
        "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n\
         MACs hmac-sha2-256-etm@openssh.com\n\
         GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-nistp256-sha256-\n\
         KexAlgorithms curve25519-sha256\n\
         PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-256\n\
         HostbasedAcceptedAlgorithms ssh-ed25519\n\
         CASignatureAlgorithms ssh-ed25519\n\
         RequiredRSASize 2048\n",
    );
    assert_eq!(port(&["x"], &h.env_system()), 22);
    // Debian 13.
    h.file(
        "etc/ssh_config",
        "Include /nonexistent/ssh_config.d/*.conf\nHost *\n    SendEnv LANG LC_* COLORTERM NO_COLOR\n    \
         HashKnownHosts yes\n    GSSAPIAuthentication yes\n",
    );
    let r = resolve(&ssh(&["x"]), &h.env_system()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.options.send_env, ["LANG", "LC_*", "COLORTERM", "NO_COLOR"]);
}

/// The tokens of an `Include` take the values of the moment, as OpenSSH's
/// did: each file sets `IdentityAgent` to its own name, and `-G` says which
/// one was read.
#[test]
fn the_tokens_of_an_include_take_the_values_of_the_moment() {
    let h = Home::new("moment");
    for v in ["22", "2201", "2222", "lu0", "lu", "fu", "Other.Example", "Alias.K", "jh"] {
        h.file(&format!("inc/v-{v}.conf"), &format!("IdentityAgent /agent-{v}\n"));
    }
    let r = h.root();
    // The file holds `text`, then the Include of the file of the token's value.
    let agent = |text: &str, token: &str, words: &[&str]| -> String {
        let f = h.file("main", &format!("{text}Include {r}/inc/v-%{token}.conf\n"));
        let mut all = vec!["-F", f.as_str()];
        all.extend_from_slice(words);
        lines(&all, &h.env()).into_iter().find(|l| l.starts_with("identityagent ")).unwrap_or_default()
    };
    assert_eq!(agent("", "p", &["x"]), "identityagent /agent-22");
    assert_eq!(agent("", "p", &["-p", "2201", "x"]), "identityagent /agent-2201");
    assert_eq!(agent("Port 2222\n", "p", &["x"]), "identityagent /agent-2222");
    assert_eq!(agent("", "r", &["x"]), "identityagent /agent-lu0");
    assert_eq!(agent("", "r", &["-l", "lu", "x"]), "identityagent /agent-lu");
    assert_eq!(agent("User fu\n", "r", &["x"]), "identityagent /agent-fu");
    assert_eq!(agent("HostName Other.Example\n", "h", &["x"]), "identityagent /agent-Other.Example");
    assert_eq!(agent("HostKeyAlias Alias.K\n", "k", &["x"]), "identityagent /agent-Alias.K");
    assert_eq!(agent("", "j", &["-J", "jh", "x"]), "identityagent /agent-jh");
}

/// OpenSSH checks each file that an `Include` reads, also from a file of
/// `-F`: measured with OpenSSH 10.3p1 on Linux.
#[cfg(unix)]
#[test]
fn an_included_file_that_others_can_change_is_refused_also_from_f() {
    use std::os::unix::fs::PermissionsExt;
    let h = Home::new("open");
    let open = h.file("inc/open.conf", "Port 2108\n");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    let f = h.file("f8", &format!("Include {open}\n"));
    assert_eq!(port(&["-F", &f, "x"], &h.env()), 2108);
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = resolve_or_refuse(&ssh(&["-F", &f, "x"]), &h.env()).unwrap_err();
    assert_eq!(err.code, 78, "{}", err.message);
    assert!(err.message.contains("bad owner or permissions") && err.message.contains("open.conf"), "{}", err.message);
}
