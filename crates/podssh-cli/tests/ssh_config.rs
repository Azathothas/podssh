//! `podssh ssh -G` (T-046) against what OpenSSH 10.3p1's `ssh -G -F none`
//! printed for the same arguments, captured on a host with it: for each
//! keyword that podssh prints, the same line, but for the defaults that
//! differ on purpose. Nothing connects.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve, Env};
use podssh_cli::tree::{parse, Parsed};

/// OpenSSH's lines for each setting that podssh applies, set on the command
/// line: `ssh -G -F none` with `EVERY`, for the keywords that podssh prints.
#[rustfmt::skip]
const EVERY: &[&str] = &[
    "-p", "2222", "-l", "alice", "-i", "/tmp/podssh-k1", "-o", "UserKnownHostsFile=/tmp/podssh-kh",
    "-o", "GlobalKnownHostsFile=none", "-o", "ServerAliveInterval=30", "-o", "ConnectTimeout=7",
    "-o", "StrictHostKeyChecking=accept-new", "-o", "SendEnv=LANG", "-o", "SetEnv=A=1", "-o", "LogLevel=VERBOSE",
    "-o", "HostKeyAlias=al", "-J", "u@b:2200,c", "-e", "%", "-4", "-o", "RemoteCommand=uptime",
    "-o", "PreferredAuthentications=password,publickey", "-o", "IdentityAgent=none", "-o", "Compression=yes",
    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "NumberOfPasswordPrompts=2",
    "-o", "ConnectionAttempts=3", "-o", "ServerAliveCountMax=5", "-o", "StdinNull=yes", "-o", "RequestTTY=force",
    "-o", "PubkeyAuthentication=no", "EXAMPLE.org",
];
const EVERY_OPENSSH: &str = "host EXAMPLE.org
user alice
hostname example.org
port 2222
addressfamily inet
batchmode yes
compression yes
identitiesonly yes
kbdinteractiveauthentication yes
passwordauthentication yes
pubkeyauthentication false
requesttty force
sessiontype default
stdinnull yes
stricthostkeychecking accept-new
connectionattempts 3
numberofpasswordprompts 2
serveralivecountmax 5
serveraliveinterval 30
hostkeyalias al
identityagent none
remotecommand uptime
loglevel VERBOSE
preferredauthentications password,publickey
identityfile /tmp/podssh-k1
globalknownhostsfile none
userknownhostsfile /tmp/podssh-kh
sendenv LANG
setenv A=1
connecttimeout 7
escapechar %
proxyjump u@b:2200,c";

/// The defaults, with the user and the known_hosts files named so that no
/// line holds a path of the host where OpenSSH ran.
#[rustfmt::skip]
const DEFAULTS: &[&str] = &[
    "-l", "alice", "-o", "UserKnownHostsFile=/tmp/podssh-kh",
    "-o", "GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2", "example.org",
];
const DEFAULTS_OPENSSH: &str = "host example.org
user alice
hostname example.org
port 22
addressfamily any
batchmode no
compression no
identitiesonly no
kbdinteractiveauthentication yes
passwordauthentication yes
pubkeyauthentication true
requesttty auto
sessiontype default
stdinnull no
stricthostkeychecking ask
connectionattempts 1
numberofpasswordprompts 3
serveralivecountmax 3
serveraliveinterval 0
loglevel INFO
identityfile ~/.ssh/id_rsa
identityfile ~/.ssh/id_ecdsa
identityfile ~/.ssh/id_ecdsa_sk
identityfile ~/.ssh/id_ed25519
identityfile ~/.ssh/id_ed25519_sk
globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2
userknownhostsfile /tmp/podssh-kh
connecttimeout none
escapechar ~";

/// The lines that differ on purpose, podssh's first: keepalives keep the
/// relay's idle cut away (`docs/relay.md`), the handshake has a limit, and
/// podssh has no security keys, so it tries no `_sk` identity file.
const ON_PURPOSE: &[(&str, &str)] = &[
    ("serveraliveinterval 60", "serveraliveinterval 0"),
    ("connecttimeout 60", "connecttimeout none"),
    ("", "identityfile ~/.ssh/id_ecdsa_sk"),
    ("", "identityfile ~/.ssh/id_ed25519_sk"),
];

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> =
        ["ssh", "-G", "-F", "none"].into_iter().chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

fn printed(words: &[&str]) -> Vec<String> {
    let env = Env { home: Some(PathBuf::from("/home/u")), user: Some("envuser".into()), ..Env::default() };
    let args = ssh(words);
    assert!(args.print_config);
    dump::lines(&resolve(&args, &env).unwrap_or_else(|e| panic!("{words:?}: {e}")))
}

#[test]
fn print_config_gives_openssh_s_line_for_each_setting_given() {
    let want: Vec<&str> = EVERY_OPENSSH.lines().collect();
    assert_eq!(printed(EVERY), want);
}

#[test]
fn print_config_gives_openssh_s_defaults_but_those_that_differ_on_purpose() {
    let ours = printed(DEFAULTS);
    let theirs: Vec<&str> = DEFAULTS_OPENSSH.lines().collect();
    for (podssh, openssh) in ON_PURPOSE {
        if !podssh.is_empty() {
            assert!(ours.iter().any(|l| l == podssh), "podssh's own default {podssh:?}: {ours:#?}");
        }
        assert!(theirs.contains(openssh), "{openssh:?} is OpenSSH's");
    }
    let differ = |line: &str| ON_PURPOSE.iter().any(|(a, b)| line == *a || line == *b);
    let ours_kept: Vec<&str> = ours.iter().map(String::as_str).filter(|l| !differ(l)).collect();
    let theirs_kept: Vec<&str> = theirs.into_iter().filter(|l| !differ(l)).collect();
    assert_eq!(ours_kept, theirs_kept);
}

#[test]
fn print_config_writes_the_settings_and_connects_to_nothing() {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["ssh", "-G", "-F", "none", "-p", "2222", "-l", "alice", "example.org"])
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::null())
        .output()
        .expect("podssh runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    for line in ["port 2222", "user alice", "hostname example.org"] {
        assert!(stdout.lines().any(|l| l == line), "{line}: {stdout}");
    }
}
