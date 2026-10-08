//! Making and reading SSH keys without `ssh-keygen`, which some hosts lack
//! and which refuses to run on a host with no user database entry. Keys are
//! written in OpenSSH's own formats, so OpenSSH reads them (the interop
//! harness checks them with OpenSSH's `ssh-keygen -y` and `-l`, and logs in
//! with them). A private key is never printed.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use russh::keys::ssh_key::private::RsaKeypair;
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
}

impl KeyKind {
    /// `-t TYPE` and `-b BITS` as `ssh-keygen` takes them: Ed25519 by
    /// default; ECDSA P-256 and RSA 3072 when no size is given.
    pub fn parse(kind: Option<&str>, bits: Option<&str>) -> Result<KeyKind, String> {
        let bits = match bits {
            None => None,
            Some(text) => {
                Some(text.trim().parse::<u32>().map_err(|_| format!("-b {text:?} is not a number of bits"))?)
            }
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
            ("rsa", Some(b @ 2048..=16384)) => Ok(KeyKind::Rsa(b as usize)),
            ("rsa", Some(b)) => Err(format!("an rsa key has 2048 to 16384 bits here, not {b}")),
            ("dsa", _) => Err("DSA keys are not made: OpenSSH 10 removed DSA".into()),
            (other, _) => Err(format!("unknown key type {other:?}: ed25519 (the default), ecdsa or rsa")),
        }
    }

    /// The name `ssh-keygen` uses, as in the default file `id_<name>`.
    pub fn name(self) -> &'static str {
        match self {
            KeyKind::Ed25519 => "ed25519",
            KeyKind::Ecdsa(_) => "ecdsa",
            KeyKind::Rsa(_) => "rsa",
        }
    }
}

/// A new key of `kind`, from the thread's cryptographic generator (seeded
/// by the operating system), carrying `comment`.
pub fn generate(kind: KeyKind, comment: &str) -> Result<PrivateKey, String> {
    let mut rng = rand::rng();
    let made = match kind {
        KeyKind::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519),
        KeyKind::Ecdsa(curve) => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve }),
        KeyKind::Rsa(bits) => RsaKeypair::random(&mut rng, bits).map(PrivateKey::from),
    };
    let mut key = made.map_err(|e| format!("could not make the key: {e}"))?;
    key.set_comment(comment);
    Ok(key)
}

/// `key` encrypted with `passphrase` as OpenSSH encrypts keys (bcrypt-pbkdf
/// and AES-256-CTR); unchanged when the passphrase is empty.
pub fn protect(key: PrivateKey, passphrase: &str) -> Result<PrivateKey, String> {
    if passphrase.is_empty() {
        return Ok(key);
    }
    key.encrypt(&mut rand::rng(), passphrase).map_err(|e| format!("could not encrypt the key: {e}"))
}

/// `FILE.pub` for `FILE`.
pub fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Write `key` to `path` (mode 0600, never over an existing file) and its
/// public half to `path.pub` (mode 0644, replacing one that is there, as
/// `ssh-keygen` does). A missing directory is created with mode 0700.
pub fn write_pair(key: &PrivateKey, path: &Path) -> Result<PathBuf, String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    }
    let private = key.to_openssh(LineEnding::LF).map_err(|e| format!("could not encode the key: {e}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            format!("{} already exists; podssh keygen never overwrites a key (remove it, or choose another -f)", path.display())
        }
        _ => format!("could not create {}: {e}", path.display()),
    })?;
    if let Err(e) = file.write_all(private.as_bytes()).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write {}: {e}", path.display()));
    }
    let public = public_path(path);
    let line = key.public_key().to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
    options
        .open(&public)
        .and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()))
        .map_err(|e| format!("the private key is in {}, but {} could not be written: {e}", path.display(), public.display()))?;
    Ok(public)
}

/// What a key file holds.
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
    if start.starts_with("-----BEGIN") {
        return Err(format!(
            "{shown}: a PEM key; podssh keygen reads OpenSSH private keys (`ssh-keygen -p -f FILE` converts one)"
        ));
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
        for (t, b) in [("ed25519", "255"), ("ecdsa", "300"), ("rsa", "1024"), ("dsa", "1024"), ("x", "1"), ("rsa", "z")] {
            assert!(KeyKind::parse(Some(t), Some(b)).is_err(), "{t} {b}");
        }
    }

    #[test]
    fn a_pair_is_written_once_readable_and_never_over_an_existing_key() {
        let dir = std::env::temp_dir().join(format!("podssh-keygen-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("id_ed25519");
        let key = generate(KeyKind::Ed25519, "test@podssh").unwrap();
        let public = write_pair(&key, &path).unwrap();
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
        let again = write_pair(&generate(KeyKind::Ed25519, "").unwrap(), &path).unwrap_err();
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
}
