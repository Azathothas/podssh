//! `podssh keygen -p` and `-c` (T-018): change the passphrase or the comment
//! of a key, where OpenSSH's `ssh-keygen` does not run. The key is read in
//! each format that `podssh ssh -i` reads, and written in OpenSSH's. The
//! file is replaced only with the same key: the new text goes to a new
//! private file beside it, which is read back, opened with the new
//! passphrase and compared by its public key, and only then renamed over the
//! file. No copy of the old file is kept: it holds the key under the
//! passphrase, or the lack of one, that the user wants gone.

use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_ssh::keygen;
use podssh_ssh::prompt;
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, NewPassphrase, EXIT_FAILED};

/// `-p` or `-c` on the key in `path`.
pub fn change(args: &KeygenArgs, path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match run(args, path, out, err) {
        Ok(()) => 0,
        Err((code, why)) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            code
        }
    }
}

type Failed = (i32, String);

fn run(args: &KeygenArgs, path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Failed> {
    let failed = |why: String| (EXIT_FAILED, why);
    let shown = path.display();
    // A comment that cannot be used is refused before any question.
    if let Some(comment) = &args.comment {
        check_comment(comment)?;
    }
    let text = std::fs::read_to_string(path).map(Zeroizing::new).map_err(|e| failed(format!("{shown}: {e}")))?;
    let (key, old) = open(path, &text, args.old_passphrase)?;
    let original = key.public_key().clone();
    let (mut key, passphrase) = (key, old);
    let passphrase = if args.change_passphrase {
        match args.passphrase {
            NewPassphrase::Absent => {
                crate::keygen::ask_new_passphrase("Enter new passphrase (empty for no passphrase): ").map_err(failed)?
            }
            NewPassphrase::Empty | NewPassphrase::Given => Zeroizing::new(String::new()),
        }
    } else {
        let comment = match &args.comment {
            Some(comment) => comment.clone(),
            None => {
                let asked = prompt::ask("Enter new comment: ", true)
                    .map_err(|e| failed(format!("the new comment: {e}; give it with -C COMMENT")))?;
                check_comment(&asked)?;
                asked.to_string()
            }
        };
        let before = key.comment().as_str_lossy().to_string();
        key.set_comment(comment.as_str());
        if !args.quiet {
            let _ = writeln!(out, "Old comment: {}", podssh_ws::text::one_line(&before));
        }
        passphrase
    };
    let format = args.format.as_deref().and_then(|f| podssh_ssh::convert::Format::parse(f).ok());
    let text = crate::keygen_convert::private_text(&key, format, &passphrase, err).map_err(failed)?;
    replace(path, &text, &original, &passphrase).map_err(failed)?;
    if args.change_comment {
        let line =
            key.public_key().to_openssh().map_err(|e| failed(format!("could not encode the public key: {e}")))?;
        keygen::write_public(path, &line, crate::keygen::KEY_FILES).map_err(|(public, e)| {
            failed(format!(
                "the key in {shown} has the new comment, but {} could not be written: {e}",
                public.display()
            ))
        })?;
        if !args.quiet {
            let _ = writeln!(out, "Comment '{}' applied", podssh_ws::text::one_line(key.comment().as_str_lossy()));
        }
    } else if !args.quiet {
        let _ = writeln!(out, "Your identification has been saved with the new passphrase.");
    }
    Ok(())
}

fn check_comment(comment: &str) -> Result<(), Failed> {
    if comment.chars().any(char::is_control) {
        return Err((EXIT_USAGE, "the comment must be one line of text".into()));
    }
    Ok(())
}

/// The private key of `text`, opened, and the passphrase that opened it
/// (empty for none): an OpenSSH key, or another format that `podssh ssh -i`
/// reads. The old passphrase is asked on the terminal or through
/// `SSH_ASKPASS`, or `-P ''` says that there is none.
fn open(path: &Path, text: &str, given: NewPassphrase) -> Result<(PrivateKey, Zeroizing<String>), Failed> {
    let shown = path.display();
    match podssh_ssh::key_file::decode(text, None) {
        Ok(key) => return Ok((key, Zeroizing::new(String::new()))),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) => return Err((EXIT_FAILED, format!("{shown}: not a private key that podssh reads: {e}"))),
    }
    let old = match given {
        NewPassphrase::Empty => Zeroizing::new(String::new()),
        _ if !prompt::can_ask() => {
            return Err((
                EXIT_FAILED,
                format!(
                    "{shown} is encrypted, and there is no terminal and no SSH_ASKPASS to ask for its passphrase \
                     (-P '' is for a key with none, and -N '' for a new key with none)"
                ),
            ))
        }
        _ => prompt::ask("Enter old passphrase: ", false)
            .map_err(|e| (EXIT_FAILED, format!("{shown} is encrypted, and its passphrase: {e}")))?,
    };
    podssh_ssh::key_file::decode(text, Some(old.as_str()))
        .map(|key| (key, old))
        .map_err(|_| (EXIT_FAILED, format!("{shown}: incorrect passphrase")))
}

/// Put `key` in place of the file at `path`, whole or not at all, and only
/// when it is the key of `original`: a new private file beside it, read back,
/// opened with `passphrase` and compared, then renamed over the file. `text`
/// is the key in OpenSSH's format, or in that of `-m` (T-022).
fn replace(path: &Path, text: &str, original: &PublicKey, passphrase: &str) -> Result<(), String> {
    let shown = path.display();
    let new = beside(path);
    let mut file = podssh_relay::cache::create_new_private(&new)
        .map_err(|e| format!("{shown} is unchanged: {} could not be made: {e}", new.display()))?;
    let written = file.write_all(text.as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    let checked = written.map_err(|e| e.to_string()).and_then(|()| same_key(&new, original, passphrase));
    if let Err(why) = checked {
        let _ = std::fs::remove_file(&new);
        return Err(format!("{shown} is unchanged: {why}"));
    }
    std::fs::rename(&new, path).map_err(|e| {
        let _ = std::fs::remove_file(&new);
        format!("{shown} is unchanged: the new file could not take its place: {e}")
    })
}

/// The new file beside `path`: `.NAME.podssh-new-PID`.
fn beside(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.podssh-new-{}", std::process::id()))
}

/// Whether the file at `new` holds the key of `original`, opened with
/// `passphrase`.
fn same_key(new: &Path, original: &PublicKey, passphrase: &str) -> Result<(), String> {
    let text = Zeroizing::new(std::fs::read_to_string(new).map_err(|e| format!("the new file cannot be read: {e}"))?);
    let key = match podssh_ssh::key_file::decode(&text, (!passphrase.is_empty()).then_some(passphrase)) {
        Ok(key) => key,
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {
            return Err("the new passphrase does not open the new file".into());
        }
        Err(_) if !passphrase.is_empty() => return Err("the new passphrase does not open the new file".into()),
        Err(e) => return Err(format!("the new file is no key: {e}")),
    };
    if key.public_key().key_data() != original.key_data() {
        return Err("the new file holds another key".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ssh::keygen::{generate, KeyKind};
    use podssh_ssh::russh::keys::ssh_key::LineEnding;

    /// A directory of the test's own, private, removed at the end.
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("podssh-keygen-change-{:016x}", rand::random::<u64>()));
        podssh_relay::cache::private_dir(&dir).unwrap();
        dir
    }

    /// The file is replaced only with its own key: another key, or one that
    /// the new passphrase does not open, leaves it as it was, and nothing is
    /// left beside it.
    #[test]
    fn only_the_same_key_replaces_the_file() {
        let dir = scratch();
        let path = dir.join("k");
        let key = generate(KeyKind::Ed25519, "mine").unwrap();
        let text = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&path, text.as_bytes()).unwrap();
        let other = generate(KeyKind::Ed25519, "mine").unwrap();
        let other = other.to_openssh(LineEnding::LF).unwrap();
        let refused = replace(&path, &other, key.public_key(), "").unwrap_err();
        assert!(refused.contains("another key"), "{refused}");
        let locked = keygen::protect(key.clone(), "right").unwrap();
        let locked = locked.to_openssh(LineEnding::LF).unwrap();
        let refused = replace(&path, &locked, key.public_key(), "wrong").unwrap_err();
        assert!(refused.contains("does not open"), "{refused}");
        assert_eq!(std::fs::read(&path).unwrap(), text.as_bytes(), "the file changed");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "a file was left beside the key");
        replace(&path, &locked, key.public_key(), "right").unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), text.as_bytes());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
