//! `podssh keygen -F`, `-R` and `-H` (T-019): find, remove and hash the
//! lines of a `known_hosts` file, where OpenSSH's `ssh-keygen` does not run.
//! The lines and the messages are those of `ssh-keygen` (OpenSSH for Windows
//! 10.0p2, measured on 2026-10-11). The file is `-f FILE`, else
//! `~/.ssh/known_hosts`. `-R` and `-H` keep the old text in `FILE.old`, and
//! put the new one in place whole, under the lock that `podssh ssh` takes to
//! record a key.
//!
//! Two calls differ from OpenSSH's, both to lose nothing: `-R` keeps a line
//! that names the host through a wildcard, as its key stands for other hosts
//! too, and says so; and a line that is no line of a host key is kept as it
//! is, where OpenSSH refuses to rewrite the file.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use podssh_ssh::known_hosts::edit;
use podssh_ssh::known_hosts::{Marker, MAX_FILE};

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};

/// `-F HOST`, `-R HOST` or `-H`, on the file of `-f`, else
/// `~/.ssh/known_hosts`.
pub fn run(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let path = match &args.file {
        Some(file) => PathBuf::from(file),
        None => match crate::ssh::resolve::Env::from_process().home {
            Some(home) => podssh_ssh::options::default_user_known_hosts(&home).remove(0),
            None => {
                let _ = writeln!(
                    err,
                    "podssh keygen: HOME is not set, so there is no ~/.ssh/known_hosts: give the file with -f FILE"
                );
                return EXIT_USAGE;
            }
        },
    };
    let shown = path.display().to_string();
    if !path.exists() {
        let _ = writeln!(err, "podssh keygen: {shown}: no such file");
        return EXIT_FAILED;
    }
    if let Some(host) = &args.find_host {
        find(&path, &shown, host, args, out, err)
    } else if let Some(host) = &args.remove_host {
        remove(&path, &shown, host, args.quiet, out, err)
    } else {
        hash(&path, &shown, out, err)
    }
}

/// `-F`: each line that names the host, after a line that says which, as
/// `ssh-keygen -F` prints them; `-H` prints each line hashed, `-q` the lines
/// alone. Exit 1 when no line names the host.
fn find(path: &Path, shown: &str, host: &str, args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let raw = match read(path) {
        Ok(raw) => raw,
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {shown}: {e}");
            return EXIT_FAILED;
        }
    };
    let found = edit::find(&raw, host, &mut rand::random::<[u8; 20]>);
    for line in &found {
        if !args.quiet {
            let marker = match line.marker {
                Some(Marker::CertAuthority) => "CA",
                Some(Marker::Revoked) => "REVOKED",
                None => "",
            };
            // OpenSSH's line, a space before the marker even when there is none.
            let _ = writeln!(out, "# Host {host} found: line {} {marker}", line.line);
        }
        if args.hash_hosts {
            for hashed in &line.hashed {
                let _ = writeln!(out, "{hashed}");
            }
        } else {
            let _ = writeln!(out, "{}", line.text);
        }
    }
    if found.is_empty() {
        port_hint(host, err);
        return EXIT_FAILED;
    }
    0
}

/// `-R`: the file without the lines of the host, its old text in
/// `FILE.old`.
fn remove(path: &Path, shown: &str, host: &str, quiet: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let done = edit::rewrite(path, podssh_relay::cache::create_new_private, |raw| {
        let removed = edit::remove(raw, host);
        (removed.text.clone(), removed)
    });
    let (rewritten, removed) = match done {
        Ok(done) => done,
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {shown} is unchanged: {e}");
            return EXIT_FAILED;
        }
    };
    for line in &removed.other {
        let _ = writeln!(err, "{shown}:{line}: not a line of a host key; kept as it is");
    }
    for (line, patterns) in &removed.kept {
        let _ = writeln!(
            err,
            "{shown}:{line}: kept: {host} matches its pattern {patterns}, whose key is for other hosts too; \
             remove the line by hand to forget them all"
        );
    }
    let Some(rewritten) = rewritten else {
        if removed.kept.is_empty() {
            let _ = writeln!(err, "Host {host} not found in {shown}");
            port_hint(host, err);
        }
        return 0;
    };
    if !quiet {
        for line in &removed.removed {
            let _ = writeln!(out, "# Host {host} found: line {line}");
        }
    }
    let _ = writeln!(out, "{shown} updated.");
    let _ = writeln!(out, "Original contents retained as {}", rewritten.old.display());
    0
}

/// `-H`: each host name hashed, its old text in `FILE.old`, which still
/// holds the names.
fn hash(path: &Path, shown: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let done = edit::rewrite(path, podssh_relay::cache::create_new_private, |raw| {
        let hashed = edit::hash(raw, &mut rand::random::<[u8; 20]>);
        (hashed.text.clone(), hashed)
    });
    let (rewritten, hashed) = match done {
        Ok(done) => done,
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {shown} is unchanged: {e}");
            return EXIT_FAILED;
        }
    };
    for (line, patterns) in &hashed.wildcard {
        let _ = writeln!(err, "{shown}:{line}: ignoring host name with wildcard: {patterns}");
    }
    for line in &hashed.other {
        let _ = writeln!(err, "{shown}:{line}: not a line of a host key; kept as it is");
    }
    let Some(rewritten) = rewritten else {
        let _ = writeln!(err, "{shown} has no host name to hash; it is unchanged");
        return 0;
    };
    let old = rewritten.old.display();
    let _ = writeln!(out, "{shown} updated.");
    let _ = writeln!(out, "Original contents retained as {old}");
    let _ = writeln!(err, "WARNING: {old} contains unhashed entries");
    let _ = writeln!(err, "Delete this file to ensure privacy of hostnames");
    0
}

/// A host typed as `HOST:PORT` is filed as `[HOST]:PORT`.
fn port_hint(host: &str, err: &mut dyn Write) {
    if let Some((name, port)) = host.rsplit_once(':') {
        if !host.starts_with('[') && !name.contains(':') && port.parse::<u16>().is_ok() {
            let _ = writeln!(err, "podssh keygen: a host on port {port} is filed as [{name}]:{port}");
        }
    }
}

/// The file's bytes, as many as a `known_hosts` file has at most.
fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?.take(MAX_FILE + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_FILE {
        return Err(std::io::Error::other(format!("larger than {} MiB, which no known_hosts file is", MAX_FILE >> 20)));
    }
    Ok(raw)
}
