//! Making and reading SSH keys without `ssh-keygen`, which some hosts lack
//! and which refuses to run on a host with no user database entry. Keys are
//! written in OpenSSH's own formats, so OpenSSH reads them (the interop
//! harness checks them with OpenSSH's `ssh-keygen -y` and `-l`, and logs in
//! with them). A private key is never printed.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// A key podssh can make, with its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    Ecdsa(EcdsaCurve),
    /// The modulus size in bits.
    Rsa(usize),
    /// A key of a security key (T-229), which the device makes: never here.
    Sk(crate::sk::Alg),
}

impl KeyKind {
    /// `-t TYPE` and `-b BITS` as `ssh-keygen` takes them: Ed25519 by
    /// default; ECDSA P-256 and RSA 3072 when no size is given.
    pub fn parse(kind: Option<&str>, bits: Option<&str>) -> Result<KeyKind, String> {
        let bits = match bits {
            None => None,
            Some(text) => Some(text.trim().parse::<u32>().map_err(|_| format!("-b {text:?} is not a number of bits"))?),
        };
        let kind = kind.unwrap_or("ed25519").to_ascii_lowercase();
        match (kind.as_str(), bits) {
            ("ed25519", None | Some(256)) => Ok(KeyKind::Ed25519),
            ("ed25519", Some(b)) => Err(format!("an ed25519 key has 256 bits, not {b}")),
            ("ecdsa", None | Some(256)) => Ok(KeyKind::Ecdsa(EcdsaCurve::NistP256)),
            ("ecdsa", Some(384)) => Ok(KeyKind::Ecdsa(EcdsaCurve::NistP384)),
            ("ecdsa", Some(521)) => Ok(KeyKind::Ecdsa(EcdsaCurve::NistP521)),
            ("ecdsa", Some(b)) => Err(format!("an ecdsa key has 256, 384 or 521 bits, not {b}")),
            ("rsa", None) => Ok(KeyKind::Rsa(3072)),
            ("rsa", Some(b @ (2048 | 3072 | 4096 | 8192))) => Ok(KeyKind::Rsa(b as usize)),
            ("rsa", Some(b)) => Err(format!("an rsa key has 2048, 3072, 4096 or 8192 bits here, not {b}")),
            ("ed25519-sk", None | Some(256)) => Ok(KeyKind::Sk(crate::sk::Alg::Ed25519)),
            ("ecdsa-sk", None | Some(256)) => Ok(KeyKind::Sk(crate::sk::Alg::EcdsaP256)),
            (sk @ ("ed25519-sk" | "ecdsa-sk"), Some(b)) => Err(format!("an {sk} key has 256 bits, not {b}")),
            ("dsa", _) => Err("DSA keys are not made: OpenSSH 10 removed DSA".into()),
            (other, _) => {
                Err(format!("unknown key type {other:?}: ed25519 (the default), ecdsa, rsa, ed25519-sk or ecdsa-sk"))
            }
        }
    }

    /// The name that `ssh-keygen -t` takes.
    pub fn name(self) -> &'static str {
        match self {
            KeyKind::Ed25519 => "ed25519",
            KeyKind::Ecdsa(_) => "ecdsa",
            KeyKind::Rsa(_) => "rsa",
            KeyKind::Sk(crate::sk::Alg::Ed25519) => "ed25519-sk",
            KeyKind::Sk(crate::sk::Alg::EcdsaP256) => "ecdsa-sk",
        }
    }

    /// The default file of the type, as OpenSSH names it: `id_ed25519`,
    /// `id_ecdsa_sk`.
    pub fn default_file(self) -> String {
        format!("id_{}", self.name().replace('-', "_"))
    }
}

/// A new key of `kind`, from the thread's cryptographic generator (seeded
/// by the operating system), carrying `comment`.
pub fn generate(kind: KeyKind, comment: &str) -> Result<PrivateKey, String> {
    let mut rng = rand::rng();
    let failed = |e: russh::keys::ssh_key::Error| format!("could not make the key: {e}");
    let mut key = match kind {
        KeyKind::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(failed)?,
        KeyKind::Ecdsa(curve) => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve }).map_err(failed)?,
        // aws-lc-rs makes it, never the `rsa` crate (T-257).
        KeyKind::Rsa(bits) => PrivateKey::from(crate::rsa_key::generate(bits)?),
        KeyKind::Sk(_) => return Err("a key of a security key is made in its device, not here".into()),
    };
    key.set_comment(comment);
    Ok(key)
}

/// `key` encrypted with `passphrase` as OpenSSH encrypts keys (bcrypt-pbkdf
/// and AES-256-CTR); unchanged when the passphrase is empty. Its public half
/// keeps the comment, which ssh-key's `encrypt` drops: the file holds the
/// comment only inside the encrypted part, but `FILE.pub` is written from the
/// public half.
pub fn protect(key: PrivateKey, passphrase: &str) -> Result<PrivateKey, String> {
    if passphrase.is_empty() {
        return Ok(key);
    }
    let mut locked =
        key.encrypt(&mut rand::rng(), passphrase).map_err(|e| format!("could not encrypt the key: {e}"))?;
    locked.set_comment(key.comment().clone());
    Ok(locked)
}

/// `FILE.pub` for `FILE`.
pub fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// How the files of a key pair are made (T-288): the private key a new file
/// that only its owner may open, `FILE.pub` a new file that each may read
/// and only its owner may change, and a missing directory private. On Unix
/// the modes 0600, 0644 and 0700; on Windows access lists of their own, as
/// OpenSSH's `ssh-keygen` makes them. podssh-relay makes them
/// (`create_new_private`, `create_new_public` and `private_dir` of its
/// `cache`), and this crate does not depend on it: the caller passes them.
#[derive(Clone, Copy)]
pub struct KeyFiles {
    pub private: fn(&Path) -> std::io::Result<File>,
    pub public: fn(&Path) -> std::io::Result<File>,
    pub dir: fn(&Path) -> std::io::Result<()>,
}

/// Write `key` to `path` (never over an existing file) and its public half
/// to `path.pub` (in place of one that is there, as `ssh-keygen` does), each
/// made by `files`, which also makes a missing directory.
pub fn write_pair(key: &PrivateKey, path: &Path, files: KeyFiles) -> Result<PathBuf, String> {
    let private = key.to_openssh(LineEnding::LF).map_err(|e| format!("could not encode the key: {e}"))?;
    let line = key.public_key().to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;
    write_texts(path, &private, &line, files)
}

/// [`write_pair`] of a private key's text in any format (`-m`, T-022) and a
/// public key's line.
pub fn write_texts(path: &Path, private: &str, line: &str, files: KeyFiles) -> Result<PathBuf, String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
        (files.dir)(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    }
    let mut file = (files.private)(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            format!(
                "{} already exists; podssh keygen never overwrites a key (remove it, or choose another -f)",
                path.display()
            )
        }
        _ => format!("could not create {}: {e}", path.display()),
    })?;
    if let Err(e) = file.write_all(private.as_bytes()).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write {}: {e}", path.display()));
    }
    write_public(path, line, files).map_err(|(public, e)| {
        format!("the private key is in {}, but {} could not be written: {e}", path.display(), public.display())
    })
}

/// Write `line` to `FILE.pub` for the key at `path`: a new file made by
/// `files`, in place of one that is there, so that it never keeps an
/// access list that lets others change it, and never writes through a link.
pub fn write_public(path: &Path, line: &str, files: KeyFiles) -> Result<PathBuf, (PathBuf, std::io::Error)> {
    let public = public_path(path);
    let written = match std::fs::remove_file(&public) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => (files.public)(&public).and_then(|mut f| f.write_all(format!("{line}\n").as_bytes())),
    };
    match written {
        Ok(()) => Ok(public),
        Err(e) => Err((public, e)),
    }
}

/// What a key file holds.
// A file is read once for each run: boxing the large variant would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum KeyFile {
    /// An OpenSSH private key, perhaps encrypted (its public half is readable
    /// either way).
    Private(PrivateKey),
    /// One public key line, `TYPE BASE64 [COMMENT]`.
    Public(PublicKey),
}

impl KeyFile {
    /// The public key either way.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            KeyFile::Private(key) => key.public_key(),
            KeyFile::Public(key) => key,
        }
    }
}

/// Read a key file: an OpenSSH private key, or a public key line.
pub fn read_key_file(path: &Path) -> Result<KeyFile, String> {
    let shown = path.display();
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?);
    let start = text.trim_start();
    if start.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return PrivateKey::from_openssh(start.as_bytes())
            .map(KeyFile::Private)
            .map_err(|e| format!("{shown}: not a usable OpenSSH private key: {e}"));
    }
    if start.starts_with("-----BEGIN") || start.starts_with("PuTTY-User-Key-File-") {
        // Each other format that `podssh ssh -i` reads (T-022).
        return match crate::key_file::decode(start, None) {
            Ok(key) => Ok(KeyFile::Private(key)),
            Err(russh::keys::Error::KeyIsEncrypted) => {
                Err(format!("{shown} is encrypted: podssh keygen -y asks for its passphrase"))
            }
            Err(e) => Err(format!("{shown}: not a key that podssh reads: {e}")),
        };
    }
    let line = start
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| format!("{shown}: no key in the file"))?;
    PublicKey::from_openssh(line).map(KeyFile::Public).map_err(|e| format!("{shown}: not a public key: {e}"))
}

/// The key size `ssh-keygen -l` prints.
pub fn bits(key: &PublicKey) -> u32 {
    match key.key_data() {
        KeyData::Rsa(rsa) => rsa.key_size(),
        _ => match key.algorithm() {
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 } => 384,
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 } => 521,
            _ => 256,
        },
    }
}

/// The line `ssh-keygen -l` prints for a key: size, SHA-256 fingerprint,
/// comment (`no comment` when there is none) and type.
pub fn fingerprint_line(key: &PublicKey) -> String {
    let comment = key.comment().as_str_lossy();
    let comment = if comment.is_empty() { "no comment" } else { comment };
    format!(
        "{} {} {} ({})",
        bits(key),
        key.fingerprint(HashAlg::Sha256),
        podssh_ws::text::one_line(comment),
        crate::known_hosts::key_type(key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // GitHub's host keys (api.github.com/meta) and the lines OpenSSH 10.3p1's
    // `ssh-keygen -l -f` printed for them on 2026-10-08.
    const GITHUB: [(&str, &str); 3] = [
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            "256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU no comment (ED25519)",
        ),
        (
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
            "256 SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM no comment (ECDSA)",
        ),
        (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
            "3072 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s no comment (RSA)",
        ),
    ];

    #[test]
    fn fingerprint_lines_are_the_ones_openssh_prints() {
        for (key, line) in GITHUB {
            let key = PublicKey::from_openssh(key).unwrap();
            assert_eq!(fingerprint_line(&key), line);
        }
        let named = PublicKey::from_openssh(&format!("{} github.com", GITHUB[0].0)).unwrap();
        assert_eq!(
            fingerprint_line(&named),
            "256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)"
        );
    }

    #[test]
    fn types_and_sizes_parse_as_ssh_keygen_takes_them() {
        assert_eq!(KeyKind::parse(None, None).unwrap(), KeyKind::Ed25519);
        assert_eq!(KeyKind::parse(Some("ECDSA"), Some("384")).unwrap(), KeyKind::Ecdsa(EcdsaCurve::NistP384));
        assert_eq!(KeyKind::parse(Some("rsa"), None).unwrap(), KeyKind::Rsa(3072));
        assert_eq!(KeyKind::parse(Some("rsa"), Some("4096")).unwrap(), KeyKind::Rsa(4096));
        assert_eq!(KeyKind::parse(Some("ed25519-sk"), None).unwrap(), KeyKind::Sk(crate::sk::Alg::Ed25519));
        assert_eq!(KeyKind::parse(Some("ECDSA-SK"), Some("256")).unwrap(), KeyKind::Sk(crate::sk::Alg::EcdsaP256));
        assert_eq!(KeyKind::parse(Some("ecdsa-sk"), None).unwrap().default_file(), "id_ecdsa_sk");
        assert!(generate(KeyKind::Sk(crate::sk::Alg::Ed25519), "").is_err(), "made in a device only");
        for (t, b) in [
            ("ed25519", "255"),
            ("ecdsa", "300"),
            ("rsa", "1024"),
            ("rsa", "2500"),
            ("rsa", "16384"),
            ("dsa", "1024"),
            ("ecdsa-sk", "384"),
            ("x", "1"),
            ("rsa", "z"),
        ] {
            assert!(KeyKind::parse(Some(t), Some(b)).is_err(), "{t} {b}");
        }
    }

    /// Makers of std's for the tests of this crate, which does not depend on
    /// podssh-relay: the CLI's own tests check the makers that it passes.
    fn std_files() -> KeyFiles {
        fn private(path: &Path) -> std::io::Result<File> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.open(path)
        }
        fn public(path: &Path) -> std::io::Result<File> {
            std::fs::OpenOptions::new().write(true).create_new(true).open(path)
        }
        fn dir(path: &Path) -> std::io::Result<()> {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder.create(path)
        }
        KeyFiles { private, public, dir }
    }

    #[test]
    fn a_pair_is_written_once_readable_and_never_over_an_existing_key() {
        let dir = std::env::temp_dir().join(format!("podssh-keygen-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("id_ed25519");
        let key = generate(KeyKind::Ed25519, "test@podssh").unwrap();
        let public = write_pair(&key, &path, std_files()).unwrap();
        assert_eq!(public, dir.join("sub").join("id_ed25519.pub"));
        let KeyFile::Private(read) = read_key_file(&path).unwrap() else { panic!("not a private key") };
        assert_eq!(read.public_key(), key.public_key());
        let KeyFile::Public(read) = read_key_file(&public).unwrap() else { panic!("not a public key") };
        assert_eq!(read.key_data(), key.public_key().key_data());
        assert_eq!(read.comment().as_str_lossy(), "test@podssh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // The planted mistake: a second key over the first.
        let before = std::fs::read(&path).unwrap();
        let again = write_pair(&generate(KeyKind::Ed25519, "").unwrap(), &path, std_files()).unwrap_err();
        assert!(again.contains("already exists"), "{again}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_encrypted_key_needs_its_passphrase() {
        let key = generate(KeyKind::Ed25519, "").unwrap();
        let locked = protect(key.clone(), "open sesame").unwrap();
        assert!(locked.is_encrypted());
        assert!(locked.decrypt("wrong").is_err());
        assert_eq!(locked.decrypt("open sesame").unwrap().public_key(), key.public_key());
        assert!(!protect(key, "").unwrap().is_encrypted());
    }

    /// The public half of an encrypted key keeps its comment, so `FILE.pub`
    /// has it; the file itself carries the comment in its encrypted part.
    #[test]
    fn an_encrypted_key_keeps_its_comment() {
        let key = generate(KeyKind::Ed25519, "kept@podssh").unwrap();
        let locked = protect(key.clone(), "open sesame").unwrap();
        assert_eq!(locked.comment().as_str_lossy(), "kept@podssh");
        assert!(locked.public_key().to_openssh().unwrap().ends_with(" kept@podssh"));
        let text = locked.to_openssh(LineEnding::LF).unwrap();
        let read = PrivateKey::from_openssh(text.as_bytes()).unwrap();
        assert_eq!(read.comment().as_str_lossy(), "", "the comment is only inside the encrypted part");
        assert_eq!(read.decrypt("open sesame").unwrap().public_key(), key.public_key());
    }
}
