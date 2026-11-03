//! The notes under a verb's options in `--help`: what its flags cannot say.
//! Apart from `help.rs` so that each file stays short (T-512).

use crate::flags::Verb;

/// The proxy of an SSH server, as `pipe --help` and the manual's examples
/// show it: one copy, which the examples' test parses (T-483).
pub const PROXY_OF_SSH: &str = "podssh pipe http-listen:3128 ssh:user@bastion.example.org";

/// The notes under a verb's options: what its flags cannot say.
pub fn verb_notes(verb: &Verb) -> String {
    let mut s = String::new();
    if verb.name == "pipe" {
        // The form of ssh: on the other side of a proxy is the one that a
        // user finds by trial (GitHub #93); a client on the port shows it.
        s.push('\n');
        s.push_str("An HTTP CONNECT proxy whose connections go on from an SSH server, and a client:\n");
        s.push_str(&format!("  {PROXY_OF_SSH}\n"));
        s.push_str("  curl --proxy http://127.0.0.1:3128 https://example.org/\n");
        s.push_str("ssh:HOPS with no target takes each CONNECT's %h:%p; a program that reads\n");
        s.push_str("  HTTPS_PROXY takes HTTPS_PROXY=http://127.0.0.1:3128.\n");
    }
    if verb.name == "ssh" {
        s.push('\n');
        s.push_str("-L and -D listen here, and each connection that they take goes on from\n");
        s.push_str("  the server; -W HOST:PORT carries one connection, with no listener.\n");
        s.push_str("-R [BIND:]PORT:HOST:HOSTPORT: the server listens, and each connection\n");
        s.push_str("  reaches HOST:HOSTPORT from here, through HTTPS_PROXY when it is set; a\n");
        s.push_str("  socket path in place of either side, or [BIND:]PORT alone for SOCKS.\n");
        s.push_str("-P on ssh is OpenSSH's Tag, which Match tagged reads, not a port. On\n");
        s.push_str("  scp and sftp, -P is the port. The meaning is per-verb.\n");
    }
    if verb.name == "keygen" {
        s.push('\n');
        s.push_str("-V here is the validity of a certificate, with -s; podssh -V prints the version.\n");
        s.push_str("-n, -s, -I, -O and -U mean one thing with -Y and another with -s, as in ssh-keygen.\n");
    }
    if matches!(verb.name, "cp" | "mv" | "scp" | "sftp" | "edit") {
        s.push('\n');
        s.push_str("-P here is the port, as on scp and sftp. On ssh it is a Tag.\n");
    }
    if matches!(verb.name, "cp" | "mv" | "scp") {
        // Where a broken copy keeps its state, which a user found only by
        // trial (the report of 2026-11-02, T-512).
        s.push_str("A copy that broke goes on when the same command runs again, while the\n");
        s.push_str("  source is as it was: a side file in the cache, podssh-cp-*.resume, keeps\n");
        s.push_str("  the offset, never a byte of the file (podssh man files).\n");
    }
    if verb.name == "run" {
        // What never goes, and that an exclude removes nothing, which a user
        // could not tell from a defect of the copy (GitHub #103, T-475).
        s.push('\n');
        s.push_str("target/, node_modules/ and .git/ never go, at any depth, nor what the\n");
        s.push_str("  project's .podsshignore names (a pattern a line); --no-ignore sends them.\n");
        s.push_str("  The summary counts what they left out, and -v names each.\n");
        s.push_str("An exclude removes nothing on the host: what an earlier run sent stays.\n");
        s.push_str("podssh cp -r has no default excludes, and reads no .podsshignore.\n");
    }
    if verb.name == "job" {
        // The ID's form and fetch's 75, which the rows cannot say (T-512).
        s.push('\n');
        s.push_str("ID is the 8 hex digits that start or submit printed, as list shows it.\n");
        s.push_str("fetch of a job that is queued or running exits 75, as its output is not\n");
        s.push_str("  whole: podssh job wait HOST ID first.\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::VERBS;
    use crate::help::verb_help;

    fn verb(name: &str) -> &'static Verb {
        VERBS.iter().find(|v| v.name == name).unwrap()
    }

    #[test]
    fn ssh_help_says_p_is_a_tag_here_and_a_port_on_scp() {
        let ssh = verb_help(verb("ssh"));
        // The notes of cp, which its help shows once cp works.
        let cp = verb_notes(verb("cp"));
        assert!(ssh.contains("-P on ssh is OpenSSH's Tag"), "{ssh}");
        assert!(cp.contains("-P here is the port"), "{cp}");
    }

    /// `pipe --help` shows the proxy of an SSH server and its client, below
    /// the options, so that no line of them is read as a flag (T-483).
    #[test]
    fn pipe_help_shows_the_proxy_of_an_ssh_server_with_its_client() {
        let pipe = verb_help(verb("pipe"));
        assert!(pipe.contains(&format!("\n  {PROXY_OF_SSH}\n")), "{pipe}");
        assert!(pipe.contains("curl --proxy http://127.0.0.1:3128 https://example.org/"), "{pipe}");
        // The block of the options ends at its first blank line.
        let at = pipe.find("OPTIONS:\n").expect("an OPTIONS: block");
        let end = at + pipe[at..].find("\n\n").expect("the end of the block");
        assert!(!pipe[..end].contains(PROXY_OF_SSH) && pipe[end..].contains(PROXY_OF_SSH), "{pipe}");
    }

    /// `cp --help` says that a broken copy goes on from its side file, and
    /// where that file is, below the options (T-512).
    #[test]
    fn cp_help_says_where_a_broken_copy_goes_on() {
        for name in ["cp", "mv", "scp"] {
            let help = verb_help(verb(name));
            let at = help.find("OPTIONS:\n").expect("an OPTIONS: block");
            let notes = &help[at + help[at..].find("\n\n").expect("the end of the block")..];
            assert!(notes.contains("goes on when the same command runs again"), "{name}: {help}");
            assert!(notes.contains("podssh-cp-*.resume"), "{name}: {help}");
        }
        assert!(!verb_notes(verb("sftp")).contains("podssh-cp-*.resume"));
    }

    /// `run --help` names what never goes and the file that adds to it, the
    /// flag that sends them, its dry run, and that an exclude removes
    /// nothing (T-475).
    #[test]
    fn run_help_names_the_default_excludes_and_the_ignore_file() {
        let help = verb_help(verb("run"));
        for word in [".podsshignore", "target/", "--no-ignore", "--dry-run", "removes nothing on the host"] {
            assert!(help.contains(word), "{word}: {help}");
        }
        let notes = verb_notes(verb("run"));
        assert!(notes.contains("podssh cp -r has no default excludes"), "{notes}");
        assert!(help.ends_with(&notes), "the notes below the options: {help}");
    }

    /// `job --help` says what an ID is, in its about and below the options,
    /// and that fetch of a job that runs exits 75 (T-512).
    #[test]
    fn job_help_names_the_id_and_the_75_of_fetch() {
        let help = verb_help(verb("job"));
        let first = help.lines().next().unwrap_or_default();
        assert!(first.contains("8 hex digits that start or submit printed"), "{first}");
        let notes = verb_notes(verb("job"));
        assert!(notes.contains("ID is the 8 hex digits that start or submit printed"), "{notes}");
        assert!(notes.contains("fetch of a job that is queued or running exits 75"), "{notes}");
        assert!(help.ends_with(&notes), "{help}");
    }
}
