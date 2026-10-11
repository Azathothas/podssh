//! `podssh keygen -e` and `-i` (T-022): a public key in the formats of other
//! systems, RFC 4716 (the default), PKCS#8 and PEM, as `ssh-keygen -e` and
//! `-i` convert them. `-i` imports public keys only: podssh never prints a
//! private key, and `-p` writes one in another format. Here too are the
//! reading of a key in each format, for `-y`, `-l` and `-e`, and the text
//! of a private key in the format of `-m`.

use std::io::Write;
use std::path::Path;

use podssh_ssh::convert::{self, Format};
use podssh_ssh::keygen::{self, KeyFile};
use podssh_ssh::prompt;
use podssh_ssh::russh::keys::ssh_key::LineEnding;
use podssh_ssh::russh::keys::PrivateKey;
use zeroize::Zeroizing;

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};

/// `-e -f FILE [-m FORMAT]`: the public key of FILE (a public key, or the
/// half of a private key) in FORMAT, on stdout.
pub fn export(args: &KeygenArgs, format: Option<Format>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(file) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -e exports the key in -f FILE");
        return EXIT_USAGE;
    };
    let key = match load_key(Path::new(file), false) {
        Ok(KeyFile::Public(key)) => key,
        Ok(KeyFile::Private(key)) => key.public_key().clone(),
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    match convert::export(&key, format.unwrap_or(Format::Rfc4716), &crate::keygen::default_comment()) {
        Ok(text) => {
            let _ = out.write_all(text.as_bytes());
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

/// `-i -f FILE [-m FORMAT]`: the public key of FILE, in FORMAT, as a line of
/// OpenSSH on stdout.
pub fn import(args: &KeygenArgs, format: Option<Format>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(file) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -i imports the key in -f FILE");
        return EXIT_USAGE;
    };
    let text = match std::fs::read(file) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {file}: {e}");
            return EXIT_FAILED;
        }
    };
    match convert::import(&text, format).and_then(|key| key.to_openssh().map_err(|e| e.to_string())) {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {file}: {why}");
            EXIT_FAILED
        }
    }
}

/// The text of a private key in the format of `-m` (T-022): PEM or PKCS#8
/// through `podssh_ssh::convert`; else, and for an Ed25519 key, which has no
/// other form, OpenSSH's, encrypted with `passphrase` unless it is empty.
pub(crate) fn private_text(
    key: &PrivateKey,
    format: Option<Format>,
    passphrase: &str,
    err: &mut dyn Write,
) -> Result<Zeroizing<String>, String> {
    if let Some(format) = format {
        if let Some(text) = convert::private_text(key, format, passphrase)? {
            return Ok(text);
        }
        if format != Format::Rfc4716 {
            let _ = writeln!(
                err,
                "podssh keygen: an {} key has no form of -m {}: it is written in the format of OpenSSH, as \
                 ssh-keygen writes it",
                podssh_ssh::known_hosts::key_type(key.public_key()),
                args_format_name(format)
            );
        }
    }
    keygen::protect(key.clone(), passphrase)?
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("could not encode the key: {e}"))
}

fn args_format_name(format: Format) -> &'static str {
    match format {
        Format::Rfc4716 => "RFC4716",
        Format::Pkcs8 => "PKCS8",
        Format::Pem => "PEM",
    }
}

/// The key of `path` for `-y` (`private`), `-l` and `-e`: a public key
/// line; for `-l` and `-e` also the public half of an OpenSSH private key,
/// encrypted or not, and `FILE.pub`; else the private key, in each format
/// that `podssh ssh -i` reads (T-022), its passphrase asked when it has one.
pub(crate) fn load_key(path: &Path, private: bool) -> Result<KeyFile, String> {
    let shown = path.display();
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?);
    if let Some(public) = crate::keygen_sign::public_line(&text) {
        if private {
            return Err(format!("{shown} holds a public key; -y reads a private key"));
        }
        return Ok(KeyFile::Public(public));
    }
    if !private {
        if let Ok(key) = PrivateKey::from_openssh(text.trim_start()) {
            return Ok(KeyFile::Public(key.public_key().clone()));
        }
        let beside = std::fs::read_to_string(keygen::public_path(path)).unwrap_or_default();
        if let Some(public) = crate::keygen_sign::public_line(&beside) {
            return Ok(KeyFile::Public(public));
        }
    }
    match podssh_ssh::key_file::decode(&text, None) {
        Ok(key) => Ok(KeyFile::Private(key)),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {
            let passphrase = prompt::ask("Enter passphrase: ", false)
                .map_err(|e| format!("{shown} is encrypted, and its passphrase: {e}"))?;
            podssh_ssh::key_file::decode(&text, Some(passphrase.as_str()))
                .map(KeyFile::Private)
                .map_err(|_| format!("{shown}: incorrect passphrase"))
        }
        Err(e) => Err(format!("{shown}: not a key that podssh reads: {e}")),
    }
}
