//! The notes of each command: what its flag table cannot say. The tests check
//! each flag, `-o` keyword and variable that a note names, so a note cannot
//! keep a name that the code has dropped. Numbers are not repeated here; the
//! tables that hold them are in the manual already.

/// The notes of the verb `name`, one paragraph each.
pub fn for_verb(name: &str) -> &'static [&'static str] {
    match name {
        "ssh" => SSH,
        "proxy" => PROXY,
        "doctor" => DOCTOR,
        "keygen" => KEYGEN,
        "man" => MAN,
        "ts" => TS,
        _ => &[],
    }
}

const SSH: &[&str] = &[
    "podssh ssh reaches the host through the relay (see THE RELAY), or over TCP with --direct. It needs \
     no installed ssh, no pty and no user database entry.",
    "Host keys are checked against the known_hosts files. On a terminal, podssh asks about an unknown \
     key. With no terminal and no SSH_ASKPASS, it refuses the key and names the remedy: \
     -o StrictHostKeyChecking=accept-new records a new key with no question. A changed key is always \
     refused, and podssh shows both fingerprints.",
    "Authentication tries the agent and the identity files, then keyboard-interactive and password. \
     Prompts go to the terminal or to SSH_ASKPASS. With -o BatchMode=yes, each prompt is an error.",
    "-t asks for a pty when there is a local terminal. -tt asks for one also when there is none, so \
     interactive programs work from a host with no pty. In a session with a pty, ~. at the start of a \
     line ends the session (see -e).",
    "-L and -D are refused by name: each needs a local listener, and podssh never listens on a port. \
     Use -W HOST:PORT, which carries one connection over the session. -R is refused by name too: \
     remote forwarding is not implemented yet.",
    "-P is the tag of OpenSSH on ssh, not a port, and podssh ignores it. On scp and sftp, -P is the port. \
     Use -p for the port of ssh.",
    "Paths in -i and in the IdentityFile, UserKnownHostsFile, GlobalKnownHostsFile and IdentityAgent \
     keywords take the tokens of OpenSSH: %% %C %d %h %i %j %k %L %l %n %p %r %u, with OpenSSH's values. \
     %u is the local user and %r the remote one. An unknown token is refused (exit 64). -E FILE is opened \
     as typed.",
    "A repeated value follows OpenSSH: the first -p and -l, the last -e, -E and -F, and the first value \
     of each -o keyword. A second -J or -W is refused, and so is a second --relay-host, --relay-addr or \
     --ca-file: give several hops, hosts or addresses as one comma list.",
    "podssh sends keepalives (ServerAliveInterval), so the relay does not close an idle session.",
    "podssh reads options before and after the host, as OpenSSH does, so a host that a script did not \
     write can be read as a flag. Put -- before it: podssh ssh -- \"$HOST\" uptime. A host, or a \
     -o HostName=VALUE, that starts with - is refused (exit 64), as OpenSSH refuses it.",
    "An IPv6 address needs brackets only before a port: user@2001:db8::1 is port 22, and \
     user@[2001:db8::1]:2222 or -p 2222 gives another port. -4 or -6 with an address of the other family \
     is refused. The relay takes an IPv6 address, but when this version was measured, its way out \
     reached no IPv6 host: such a session ends at once, and podssh says so. --direct needs no relay.",
];

const PROXY: &[&str] = &[
    "podssh proxy sends stdin to the target through the relay, and the target's bytes to stdout. It is \
     not an SSH client. Its main use is as the ProxyCommand of OpenSSH: \
     ssh -o ProxyCommand='podssh proxy %h %p' user@host. It also carries each TCP protocol that a \
     program can speak over stdin and stdout.",
    "With OpenSSH, set -o ServerAliveInterval=60: the relay closes a session with no traffic (see THE \
     RELAY).",
    "The session ends when the target closes the connection or when stdout closes; both are a success. \
     An error is one line on stderr; the codes are in EXIT STATUS.",
    "HOST can be an IPv6 address, bare (as OpenSSH gives %h) or in brackets. In one word, the form is \
     [ADDRESS]:PORT. Through the relay, see the IPv6 note of ssh.",
    "Put -- before a HOST that a script did not write: podssh proxy -- \"$HOST\" 22. Else a HOST that \
     starts with - is read as a flag.",
];

const DOCTOR: &[&str] = &[
    "Each line is ok, FAIL or ????, the check, and what podssh found. ok: podssh can work with it; a \
     missing pty, listener, DNS or user database entry is ok, because podssh is made for them. FAIL: \
     something that podssh needs is broken. ????: the check could not run, and it does not fail the run.",
    "The checks: this host (the user database entry, where host keys and tokens can be written, /proc, \
     a pty, a socket bind that is closed at once, the directories that can run programs, the terminal); \
     the egress (the proxy setting, TLS and the trust store, what the proxy allows, the system resolver, \
     DNS over HTTPS); and the relay (each relay host, a token, a session to github.com port 22 that must \
     show the published host key of GitHub, and the clock).",
    "podssh doctor connects to the relay hosts and, through the relay, to github.com. The report goes to \
     stdout; the exit codes are in EXIT STATUS.",
];

const KEYGEN: &[&str] = &[
    "The keys are in the formats of OpenSSH. The private key has mode 0600 and never replaces a file \
     that exists; the public key goes to FILE.pub. podssh prints the SHA-256 fingerprint.",
    "podssh asks for the passphrase two times, on the terminal or through SSH_ASKPASS. -N '' makes a key \
     with no passphrase. A passphrase given with -N is refused, because each process on the host can \
     read a command line. With no terminal and no SSH_ASKPASS, podssh stops at once and names -N ''.",
    "DSA keys are refused: OpenSSH 10 removed them. The default comment is USER@HOST from the \
     environment, never from the user database.",
];

const MAN: &[&str] = &[
    "On a terminal, podssh man shows the manual through the program in PAGER; else through less, when \
     PATH has it and TERM names a terminal (not on Windows); else through its own pager (Enter: the next \
     page, q: quit). With --no-pager or --roff, or when stdin or stdout is not a terminal, the manual \
     goes to stdout with no pager.",
    "podssh man --roff > podssh.1 makes a man page; man -l podssh.1 shows it.",
    "The manual is the same in each environment: it shows no setting of this host.",
];

const TS: &[&str] = &[
    "Experimental. podssh ts joins a tailnet, with DERP over a WebSocket relay. The live test with two \
     nodes has not passed yet.",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{verb_for, VERBS};
    use crate::ssh::keywords;

    /// The words of a note, split at spaces and at the punctuation around
    /// names (but not at `-`, `_` or `=`).
    fn words(note: &str) -> Vec<&str> {
        note.split(|c: char| c.is_whitespace() || "(),;:.'".contains(c))
            .filter(|w| !w.is_empty())
            .collect()
    }

    fn flag_exists(verb: &str, flag: &str) -> bool {
        let rows = |v: &str| verb_for(v).map(|v| v.flags).unwrap_or(&[]);
        let names = |r: &crate::flags::FlagRow| {
            let mut n = vec![format!("--{}", r.long)];
            if let Some(c) = r.short {
                n.push(format!("-{c}"));
            }
            n
        };
        // A note may also name a flag of ssh (OpenSSH's), and -tt is -t twice.
        flag == "-tt"
            || flag == "--help"
            || flag == "--"
            || rows(verb).iter().chain(rows("ssh")).any(|r| names(r).iter().any(|n| n == flag))
    }

    fn keyword_exists(name: &str) -> bool {
        keywords::known_names().chain(keywords::IGNORED.iter().copied()).any(|k| k.eq_ignore_ascii_case(name))
    }

    fn problems() -> Vec<String> {
        let variables: Vec<&str> = super::super::facts::VARIABLES.iter().flat_map(|(n, _)| n.iter().copied()).collect();
        let mut out = Vec::new();
        for verb in VERBS {
            for note in for_verb(verb.name) {
                out.extend(problems_in(verb.name, note, &variables));
            }
        }
        out
    }

    fn problems_in(verb: &str, note: &str, variables: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        for w in words(note) {
            let flag_shaped = w.starts_with('-') && w.len() > 1 && w.chars().nth(1).is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
            if flag_shaped && !w.contains('=') && !flag_exists(verb, w) {
                out.push(format!("{verb}: the flag {w} does not exist"));
            }
            if let Some((name, _)) = w.split_once('=') {
                if name.starts_with(|c: char| c.is_ascii_uppercase()) && !keyword_exists(name) {
                    out.push(format!("{verb}: the keyword {name} does not exist"));
                }
            }
            let variable_shaped = w.contains('_') && w.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            if variable_shaped && !variables.contains(&w) {
                out.push(format!("{verb}: the variable {w} is not in ENVIRONMENT"));
            }
        }
        out
    }

    /// -R needs no local listener: the server listens. Its sentence must not
    /// borrow the cause of -L and -D.
    #[test]
    fn the_note_about_r_names_no_listener() {
        let sentences: Vec<&str> =
            for_verb("ssh").iter().flat_map(|n| n.split(". ")).filter(|s| s.contains("-R")).collect();
        assert_eq!(sentences.len(), 1, "{sentences:#?}");
        assert!(sentences[0].contains("not implemented yet"), "{}", sentences[0]);
        for word in ["never", "listen", "bind", "-W"] {
            assert!(!sentences[0].contains(word), "{word}: {}", sentences[0]);
        }
    }

    #[test]
    fn each_name_in_a_note_exists() {
        let p = problems();
        assert!(p.is_empty(), "{p:#?}");
    }

    /// The control: a note with a dropped flag, keyword or variable fails.
    #[test]
    fn a_planted_name_is_found() {
        let variables = ["SSH_ASKPASS"];
        let p = problems_in("ssh", "use --no-such-flag, -o NoSuchKeyword=yes and NO_SUCH_VAR", &variables);
        assert_eq!(p.len(), 3, "{p:#?}");
        assert!(problems_in("ssh", "use -W HOST:PORT, BatchMode=yes and SSH_ASKPASS", &variables).is_empty());
    }
}
