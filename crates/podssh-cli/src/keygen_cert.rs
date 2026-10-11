//! `podssh keygen -s` and `-L` (T-021): user and host certificates, signed
//! by a CA key, and printed. The validity, the options, the lines and the
//! messages are those of the `ssh-keygen` of OpenSSH for Windows 10.0p2
//! (measured on 2026-10-11); a failure exits 1, where OpenSSH exits 255,
//! and a usage error 64. As OpenSSH does, `FILE-cert.pub` replaces one that
//! is there: a certificate is public, and is made again at each renewal.

use std::io::Write;
use std::path::Path;

use podssh_ssh::cert::{self, Request};
use podssh_ssh::options::Agent;
use podssh_ssh::russh::keys::ssh_key::{Certificate, HashAlg};
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};
use crate::keygen_sign::{block_on, open_private, public_key};

/// The CA that signs: a private key, or the agent's key (`-U`).
enum Ca {
    Key(Box<PrivateKey>),
    Agent(PublicKey),
}

/// `-s CA -I ID [-n PRINCIPALS] [-V VALIDITY] [-z SERIAL] [-O OPTION]
/// [-h] [-U] FILE...`: each FILE, a public key, to `FILE-cert.pub`.
pub fn sign(args: &KeygenArgs, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write, why: &str| {
        let _ = writeln!(err, "podssh keygen: {why}");
        EXIT_USAGE
    };
    let Some(key_id) = args.identity.as_deref() else {
        return usage(err, "Must specify key id (-I) when certifying");
    };
    if args.files.is_empty() {
        return usage(err, "-s signs each FILE, a public key: give one");
    }
    let mut request = Request::new(key_id, args.host_certificate);
    if let Some(principals) = &args.namespace {
        request.principals = principals.split(',').filter(|p| !p.is_empty()).map(str::to_string).collect();
    }
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if let Some(spec) = &args.validity {
        match cert::validity(spec, now) {
            Ok((after, before)) => (request.valid_after, request.valid_before) = (after, before),
            Err(why) => return usage(err, &why),
        }
    }
    if let Some(text) = &args.serial {
        match cert::serial(text) {
            Ok(serial) => request.serial = serial,
            Err(why) => return usage(err, &why),
        }
    }
    for option in &args.options {
        if let Err(why) = request.option(option) {
            return usage(err, &why);
        }
    }
    let rsa_hash = match args.key_type.as_deref() {
        None | Some("rsa-sha2-512") => HashAlg::Sha512,
        Some("rsa-sha2-256") => HashAlg::Sha256,
        Some(other) => {
            return usage(
                err,
                &format!("-t {other}: with -s, -t names the signature of an RSA CA: rsa-sha2-256 or rsa-sha2-512"),
            )
        }
    };
    let ca_path = Path::new(args.signature_file.as_deref().unwrap_or_default());
    let ca = match ca(ca_path, args.agent_key) {
        Ok(ca) => ca,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    let mut code = 0;
    for file in &args.files {
        match certify_one(file, &ca, &request, rsa_hash) {
            Ok((target, certificate)) => {
                if !args.quiet {
                    let kind = if certificate.cert_type().is_host() { "host" } else { "user" };
                    let principals = args.namespace.as_deref().map(|p| format!(" for {p}")).unwrap_or_default();
                    let _ = writeln!(
                        err,
                        "Signed {kind} key {target}: id \"{key_id}\" serial {}{principals} valid {}",
                        certificate.serial(),
                        cert::format_validity(certificate.valid_after(), certificate.valid_before())
                    );
                }
            }
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                code = EXIT_FAILED;
            }
        }
    }
    code
}

/// The CA of `-s`: its private key, its passphrase asked; with `-U`, its
/// public key, for the agent that holds it.
fn ca(path: &Path, agent: bool) -> Result<Ca, String> {
    let shown = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
    if agent {
        return public_key(path, &text)
            .map(Ca::Agent)
            .ok_or_else(|| format!("{shown} holds no public key for the agent to sign with"));
    }
    open_private(path, &text).map(|key| Ca::Key(Box::new(key)))
}

/// FILE, a public key, certified and written to `FILE-cert.pub` (FILE
/// without `.pub`): the path and the certificate.
fn certify_one(file: &str, ca: &Ca, request: &Request, rsa_hash: HashAlg) -> Result<(String, Certificate), String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or_default();
    let public = PublicKey::from_openssh(line).map_err(|_| format!("{file}: not a public key"))?;
    let certificate = match ca {
        Ca::Key(key) => cert::certify(key, &public, request, rsa_hash)?,
        Ca::Agent(ca) => block_on(cert::certify_with_agent(&Agent::FromEnvironment, ca, &public, request, rsa_hash))?,
    };
    let target = match file.strip_suffix(".pub") {
        Some(stem) => format!("{stem}-cert.pub"),
        None => format!("{file}-cert.pub"),
    };
    let line = certificate.to_openssh().map_err(|e| format!("could not encode the certificate: {e}"))?;
    replace(Path::new(&target), format!("{line}\n").as_bytes()).map_err(|e| format!("{target}: {e}"))?;
    Ok((target, certificate))
}

/// `bytes` in place of the file at `path`, whole: a new file beside it,
/// then a rename.
fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let new = path.with_file_name(format!(".{name}.podssh-new-{}", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&new)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()));
    if let Err(e) = written.and_then(|()| std::fs::rename(&new, path)) {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    Ok(())
}

/// `-L -f FILE`: each certificate of FILE, as `ssh-keygen -L` prints it.
pub fn print(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh keygen: -L prints the certificate in -f FILE");
        return EXIT_USAGE;
    };
    let text = match std::fs::read(path) {
        Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {path}: {e}");
            return EXIT_FAILED;
        }
    };
    let mut any = false;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let certificate = match Certificate::from_openssh(line) {
            Ok(certificate) => certificate,
            Err(_) if PublicKey::from_openssh(line).is_ok() => {
                let _ = writeln!(err, "{path}:{number} is not a certificate");
                continue;
            }
            Err(e) => {
                let _ = writeln!(err, "{path}:{number}: invalid key: {e}");
                continue;
            }
        };
        any = true;
        if number == 1 {
            let _ = writeln!(out, "{path}:");
        } else {
            let _ = writeln!(out, "{path}:{number}:");
        }
        for line in cert::describe(&certificate) {
            let _ = writeln!(out, "{line}");
        }
    }
    if any {
        0
    } else {
        EXIT_FAILED
    }
}
