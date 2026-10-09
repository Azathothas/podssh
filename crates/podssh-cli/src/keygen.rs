//! `podssh keygen`: make an SSH key pair, or print a key file's public key
//! (`-y`) or fingerprint (`-l`), on hosts with no `ssh-keygen` or none that
//! runs (OpenSSH's refuses to run without a user database entry). It takes
//! the `ssh-keygen` flags scripts use, and writes OpenSSH's own formats.
//!
//! A passphrase is asked for (terminal or `SSH_ASKPASS`) and never taken
//! from the command line, where every process on the host can read it; `-N ''`
//! makes a key without one. A private key is never printed, and an existing
//! key is never overwritten.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use podssh_ssh::keygen::{self, KeyFile, KeyKind};
use podssh_ssh::prompt;
use zeroize::Zeroizing;

use crate::exit_codes::EXIT_USAGE;

/// The exit when a key could not be made or read, as `ssh-keygen` exits.
pub const EXIT_FAILED: i32 = 1;

/// `-N` as given. The text of a non-empty passphrase is not kept, because it
/// is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NewPassphrase {
    #[default]
    Absent,
    Empty,
    Given,
}

/// Every value `podssh keygen` accepts, as typed. The field names follow
/// the rows of [`crate::flags::KEYGEN_FLAGS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeygenArgs {
    pub key_type: Option<String>,
    pub bits: Option<String>,
    pub file: Option<String>,
    pub passphrase: NewPassphrase,
    pub comment: Option<String>,
    pub quiet: bool,
    pub print_public: bool,
    pub fingerprint: bool,
}

impl KeygenArgs {
    /// Read the values out of `keygen`'s matches; ids the table does not
    /// declare read as absent.
    pub fn from_matches(m: &ArgMatches) -> Self {
        let one = |id: &str| m.try_get_one::<String>(id).ok().flatten().cloned();
        let flag = |id: &str| m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        let passphrase = match m.try_get_one::<String>("new-passphrase").ok().flatten() {
            None => NewPassphrase::Absent,
            Some(p) if p.is_empty() => NewPassphrase::Empty,
            Some(_) => NewPassphrase::Given,
        };
        KeygenArgs {
            key_type: one("type"),
            bits: one("bits"),
            file: one("file"),
            passphrase,
            comment: one("comment"),
            quiet: m.try_get_one::<u8>("quiet").ok().flatten().is_some_and(|n| *n > 0),
            print_public: flag("print-public"),
            fingerprint: flag("fingerprint"),
        }
    }
}

/// Run the verb; returns the process exit code.
pub fn run_keygen(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.passphrase == NewPassphrase::Given {
        let _ = writeln!(
            err,
            "podssh keygen: a passphrase on the command line is refused: every process on this host can read it.\n  \
             Leave -N out to be asked for one (terminal or SSH_ASKPASS), or use -N '' for a key without one."
        );
        return EXIT_USAGE;
    }
    if args.print_public || args.fingerprint {
        if args.print_public && args.fingerprint {
            let _ = writeln!(err, "podssh keygen: -y and -l cannot be combined");
            return EXIT_USAGE;
        }
        let Some(file) = &args.file else {
            let _ = writeln!(err, "podssh keygen: -y and -l read the key in -f FILE");
            return EXIT_USAGE;
        };
        let path = Path::new(file);
        return if args.print_public { print_public(path, out, err) } else { print_fingerprint(path, out, err) };
    }
    generate(args, out, err)
}

fn generate(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let kind = match KeyKind::parse(args.key_type.as_deref(), args.bits.as_deref()) {
        Ok(kind) => kind,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_USAGE;
        }
    };
    let comment = args.comment.clone().unwrap_or_else(default_comment);
    if comment.chars().any(char::is_control) {
        let _ = writeln!(err, "podssh keygen: the comment must be one line of text");
        return EXIT_USAGE;
    }
    let path = match &args.file {
        Some(file) => PathBuf::from(file),
        None => match crate::ssh::resolve::Env::from_process().home {
            Some(home) => home.join(".ssh").join(format!("id_{}", kind.name())),
            None => {
                let _ =
                    writeln!(err, "podssh keygen: HOME is not set, so there is no ~/.ssh: give a file with -f FILE");
                return EXIT_USAGE;
            }
        },
    };
    // Before asking for a passphrase that would then be thrown away.
    if path.exists() {
        let _ = writeln!(
            err,
            "podssh keygen: {} already exists; podssh keygen never overwrites a key (remove it, or choose another -f)",
            path.display()
        );
        return EXIT_FAILED;
    }
    let passphrase = match args.passphrase {
        NewPassphrase::Absent => match ask_new_passphrase() {
            Ok(p) => p,
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                return EXIT_FAILED;
            }
        },
        NewPassphrase::Empty | NewPassphrase::Given => Zeroizing::new(String::new()),
    };
    if !args.quiet {
        let _ = writeln!(out, "Generating public/private {} key pair.", kind.name());
    }
    let made = keygen::generate(kind, &comment).and_then(|key| keygen::protect(key, &passphrase));
    let key = match made {
        Ok(key) => key,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    match keygen::write_pair(&key, &path) {
        Ok(public) => {
            if !args.quiet {
                let _ = writeln!(out, "Your identification has been saved in {}", path.display());
                let _ = writeln!(out, "Your public key has been saved in {}", public.display());
                let _ = writeln!(out, "The key fingerprint is:");
                let _ = writeln!(out, "{} {comment}", podssh_ssh::known_hosts::fingerprint(key.public_key()));
            }
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

/// A new passphrase, asked twice. Empty means none.
fn ask_new_passphrase() -> Result<Zeroizing<String>, String> {
    if !prompt::can_ask() {
        return Err(
            "there is no terminal and no SSH_ASKPASS to ask for a passphrase; use -N '' for a key without one".into()
        );
    }
    let why = |e: prompt::PromptError| match e {
        prompt::PromptError::NoTerminal | prompt::PromptError::NoAnswer => {
            format!("the passphrase: {e}; use -N '' for a key without one")
        }
        _ => format!("the passphrase: {e}"),
    };
    let first = prompt::ask("Enter passphrase (empty for no passphrase): ", false).map_err(why)?;
    let second = prompt::ask("Enter same passphrase again: ", false).map_err(why)?;
    if *first != *second {
        return Err("the passphrases do not match".into());
    }
    Ok(first)
}

/// `-y`: the public key of the private key in `path`, decrypted first when
/// it is encrypted, so the line printed is derived from the private key.
fn print_public(path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let key = match keygen::read_key_file(path) {
        Ok(KeyFile::Private(key)) => key,
        Ok(KeyFile::Public(_)) => {
            let _ = writeln!(err, "podssh keygen: {} holds a public key; -y reads a private key", path.display());
            return EXIT_FAILED;
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    let key = if key.is_encrypted() {
        let passphrase = match prompt::ask("Enter passphrase: ", false) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(err, "podssh keygen: {} is encrypted, and its passphrase: {e}", path.display());
                return EXIT_FAILED;
            }
        };
        match key.decrypt(passphrase.as_bytes()) {
            Ok(key) => key,
            Err(_) => {
                let _ = writeln!(err, "podssh keygen: {}: incorrect passphrase", path.display());
                return EXIT_FAILED;
            }
        }
    } else {
        key
    };
    match key.public_key().to_openssh() {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
            0
        }
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: could not encode the public key: {e}");
            EXIT_FAILED
        }
    }
}

/// `-l`: the fingerprint line `ssh-keygen -l` prints, for a public key line
/// or the public half of a private key.
fn print_fingerprint(path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match keygen::read_key_file(path) {
        Ok(key) => {
            let _ = writeln!(out, "{}", keygen::fingerprint_line(key.public_key()));
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

/// `user@host`, as `ssh-keygen` names a key, from the environment (never the
/// user database, which some hosts lack).
fn default_comment() -> String {
    match (crate::ssh::resolve::Env::from_process().user, crate::ssh::tokens::local_host_name()) {
        (Some(user), Some(host)) => format!("{user}@{host}"),
        (Some(user), None) => user,
        (None, Some(host)) => host,
        (None, None) => String::new(),
    }
}
