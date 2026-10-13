//! `podssh keygen -Y` (T-020): sign files with an SSH key, and check SSH
//! signatures against an allowed-signers file, as `ssh-keygen -Y` does for
//! git's signing among others. The lines, the messages and their streams are
//! those of the `ssh-keygen` of OpenSSH for Windows 10.0p2 (measured on
//! 2026-10-11); a failure exits 1, where OpenSSH exits 255, and a usage
//! error 64.
//!
//! `sign` takes the public key of `-f FILE` (the file's, `FILE.pub`, or the
//! private key's) and signs through the agent when it holds the key, as
//! OpenSSH does; else with the private key in FILE, whose passphrase is
//! asked. `-U` asks for the agent alone. A signature never replaces a file.
//!
//! A certificate signs when `-f` names it, `-f KEY-cert.pub`, with the
//! private key KEY, as OpenSSH's; and a `cert-authority` line allows the
//! signatures of the certificates of its CA (T-289).

use std::io::{Read, Write};
use std::path::Path;

use podssh_ssh::known_hosts::{fingerprint, key_type};
use podssh_ssh::options::Agent;
use podssh_ssh::russh::keys::ssh_key::{Certificate, HashAlg, SshSig};
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};
use podssh_ssh::sshsig::{self, Line, Signed};
use podssh_ssh::sshsig_cert;

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{KeygenArgs, EXIT_FAILED};

/// What `-O` set.
struct Options {
    hash: HashAlg,
    verify_time: Option<i64>,
    print_pubkey: bool,
}

/// `-Y OP`.
pub fn run(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut options = Options { hash: HashAlg::Sha512, verify_time: None, print_pubkey: false };
    for option in &args.options {
        let ok = match option.split_once('=') {
            Some(("hashalg", value)) => sshsig::hash_alg(value).map(|hash| options.hash = hash).is_some(),
            Some(("verify-time", value)) => sshsig::parse_time(value).map(|t| options.verify_time = Some(t)).is_some(),
            None if option == "print-pubkey" => {
                options.print_pubkey = true;
                true
            }
            _ => false,
        };
        if !ok {
            let _ = writeln!(
                err,
                "podssh keygen: -O {option}: with -Y, -O takes hashalg=sha256 or sha512, \
                 verify-time=YYYYMMDD[HHMM[SS]][Z] and print-pubkey"
            );
            return EXIT_USAGE;
        }
    }
    let op = args.signature_op.as_deref().unwrap_or_default();
    let needs = |what: &[(&str, bool)]| -> Option<String> {
        let missing: Vec<&str> = what.iter().filter(|(_, given)| !given).map(|(flag, _)| *flag).collect();
        (!missing.is_empty()).then(|| format!("-Y {op} needs {}", missing.join(", ")))
    };
    let f = args.file.is_some();
    let n = args.namespace.is_some();
    let s = args.signature_file.is_some();
    let i = args.identity.is_some();
    let missing = match op {
        "sign" => needs(&[("-f FILE (the key)", f), ("-n NAMESPACE", n)]),
        "verify" => {
            needs(&[("-f FILE (allowed signers)", f), ("-I PRINCIPAL", i), ("-n NAMESPACE", n), ("-s FILE", s)])
        }
        "check-novalidate" => needs(&[("-n NAMESPACE", n), ("-s FILE", s)]),
        "find-principals" => needs(&[("-f FILE (allowed signers)", f), ("-s FILE", s)]),
        "match-principals" => needs(&[("-f FILE (allowed signers)", f), ("-I PRINCIPAL", i)]),
        other => Some(format!(
            "-Y {other}: the operations are sign, verify, check-novalidate, find-principals and match-principals"
        )),
    };
    if let Some(why) = missing {
        let _ = writeln!(err, "podssh keygen: {why}");
        return EXIT_USAGE;
    }
    if op != "sign" && !args.files.is_empty() {
        let _ =
            writeln!(err, "podssh keygen: -Y {op} reads the data on standard input; FILE arguments are for -Y sign");
        return EXIT_USAGE;
    }
    let now = options.verify_time.unwrap_or_else(now);
    match op {
        "sign" => sign(args, &options, out, err),
        "verify" => verify(args, &options, now, out, err),
        "check-novalidate" => check_novalidate(args, out, err),
        "find-principals" => find_principals(args, now, out, err),
        _ => match_principals(args, out, err),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// What signs: the agent with a key, or a private key.
enum Signing {
    Agent(PublicKey),
    Key(Box<PrivateKey>),
}

/// `-Y sign -f KEY -n NAMESPACE [FILE...]`: each FILE to `FILE.sig`, or
/// standard input to standard output.
fn sign(args: &KeygenArgs, options: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let key_path = Path::new(args.file.as_deref().unwrap_or_default());
    let namespace = args.namespace.as_deref().unwrap_or_default();
    let (signing, certificate) = match signer(key_path, args.agent_key) {
        Ok(found) => found,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    let make = |reader: &mut dyn Read| -> Result<String, String> {
        let prehash = sshsig::digest(reader, options.hash).map_err(|e| e.to_string())?;
        let signature = match &signing {
            Signing::Key(key) => sshsig::sign(key, namespace, options.hash, &prehash)?,
            Signing::Agent(public) => with_agent(public, namespace, options.hash, &prehash)?,
        };
        sshsig::armour(&signature, certificate.as_ref())
    };
    let files: Vec<&String> = args.files.iter().filter(|f| f.as_str() != "-").collect();
    if files.is_empty() {
        if !args.quiet {
            let _ = writeln!(err, "Signing data on standard input");
        }
        return match make(&mut std::io::stdin().lock()) {
            Ok(text) => {
                let _ = out.write_all(text.as_bytes());
                0
            }
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                EXIT_FAILED
            }
        };
    }
    let mut code = 0;
    for file in files {
        let target = format!("{file}.sig");
        if Path::new(&target).exists() {
            let _ = writeln!(err, "podssh keygen: {target} already exists; podssh keygen never writes over it");
            code = EXIT_FAILED;
            continue;
        }
        if !args.quiet {
            let _ = writeln!(err, "Signing file {file}");
        }
        let made = std::fs::File::open(file).map_err(|e| format!("{file}: {e}")).and_then(|mut f| make(&mut f));
        let written = made.and_then(|text| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .and_then(|mut f| f.write_all(text.as_bytes()))
                .map_err(|e| format!("{target}: {e}"))
        });
        match written {
            Ok(()) if !args.quiet => {
                let _ = writeln!(err, "Write signature to {target}");
            }
            Ok(()) => {}
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                code = EXIT_FAILED;
            }
        }
    }
    code
}

/// The key that signs for `-f KEY`: the agent when it holds the public key
/// of KEY (and only the agent with `-U`), else the private key in KEY. A
/// certificate in `-f` is the key of the signature (T-289).
fn signer(path: &Path, agent_only: bool) -> Result<(Signing, Option<Certificate>), String> {
    let shown = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
    if let Some(certificate) = certificate_line(&text) {
        return certified(path, &certificate, agent_only).map(|signing| (signing, Some(certificate)));
    }
    let public = public_key(path, &text);
    if let Some(public) = &public {
        if agent_has(public) {
            return Ok((Signing::Agent(public.clone()), None));
        }
    }
    if agent_only {
        return Err(match public {
            Some(_) => "the agent does not hold the key of -f (-U signs with the agent alone)".into(),
            None => format!("{shown} holds no public key for the agent to sign with"),
        });
    }
    if public.is_some() && public_line(&text).is_some() {
        return Err(format!("{shown} is a public key, and no agent holds its private key"));
    }
    open_private(path, &text).map(|key| (Signing::Key(Box::new(key)), None))
}

/// The certificate in `-f`, when its first line is one.
fn certificate_line(text: &str) -> Option<Certificate> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    Certificate::from_openssh(line).ok()
}

/// The key that signs for `-f KEY-cert.pub`, as OpenSSH's `load_sign_key`
/// finds it: the agent when it holds the certificate's key, else the
/// private key at the path without `-cert.pub` (or `.pub`), which must be
/// the certificate's key.
fn certified(path: &Path, certificate: &Certificate, agent_only: bool) -> Result<Signing, String> {
    let public = PublicKey::new(certificate.public_key().clone(), "");
    if agent_has(&public) {
        return Ok(Signing::Agent(public));
    }
    if agent_only {
        return Err("the agent does not hold the key of -f (-U signs with the agent alone)".into());
    }
    let shown = path.to_string_lossy();
    let private = ["-cert.pub", ".pub"].iter().find_map(|suffix| shown.strip_suffix(suffix)).unwrap_or(&shown);
    let private = Path::new(private);
    if !private.exists() {
        return Err(format!("No private key found for public key \"{shown}\""));
    }
    let text = std::fs::read_to_string(private).map_err(|e| format!("{}: {e}", private.display()))?;
    let key = open_private(private, &text)?;
    if key.public_key().key_data() != certificate.public_key() {
        return Err(format!("Public key {shown} doesn't match private {}", private.display()));
    }
    Ok(Signing::Key(Box::new(key)))
}

/// The public key of `-f`: the file's when it is one, else `FILE.pub`, else
/// the half of a private key that needs no passphrase to read.
pub(crate) fn public_key(path: &Path, text: &str) -> Option<PublicKey> {
    if let Some(key) = public_line(text) {
        return Some(key);
    }
    let pub_path = podssh_ssh::keygen::public_path(path);
    if let Some(key) = std::fs::read_to_string(pub_path).ok().as_deref().and_then(public_line) {
        return Some(key);
    }
    PrivateKey::from_openssh(text.trim_start()).ok().map(|key| PublicKey::new(key.public_key().key_data().clone(), ""))
}

pub(crate) fn public_line(text: &str) -> Option<PublicKey> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    PublicKey::from_openssh(line).ok()
}

/// The private key of `-f`, its passphrase asked when it has one.
pub(crate) fn open_private(path: &Path, text: &str) -> Result<PrivateKey, String> {
    let shown = path.display();
    match podssh_ssh::key_file::decode(text, None) {
        Ok(key) => return Ok(key),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) => return Err(format!("{shown}: not a private key that podssh reads: {e}")),
    }
    if !podssh_ssh::prompt::can_ask() {
        return Err(format!(
            "{shown} is encrypted, and there is no terminal and no SSH_ASKPASS to ask for its passphrase"
        ));
    }
    let question = format!("Enter passphrase for \"{shown}\": ");
    let passphrase = podssh_ssh::prompt::ask(&question, false).map_err(|e| format!("{shown}: {e}"))?;
    podssh_ssh::key_file::decode(text, Some(passphrase.as_str())).map_err(|_| format!("{shown}: incorrect passphrase"))
}

/// Whether the agent of the environment holds `public`.
fn agent_has(public: &PublicKey) -> bool {
    block_on(async {
        match podssh_ssh::keys::agent_keys(&Agent::FromEnvironment).await {
            Ok(keys) => keys.iter().any(|k| k.key_data() == public.key_data()),
            Err(_) => false,
        }
    })
}

fn with_agent(public: &PublicKey, namespace: &str, hash: HashAlg, prehash: &[u8]) -> Result<SshSig, String> {
    block_on(sshsig::sign_with_agent(&Agent::FromEnvironment, public, namespace, hash, prehash))
}

pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime").block_on(future)
}

/// The signature of `-s FILE`, or what `ssh-keygen` says when there is none.
fn signature_file(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> Option<Signed> {
    let path = args.signature_file.as_deref().unwrap_or_default();
    let read = std::fs::read(path).map_err(|e| format!("Couldn't read signature file: {path}: {e}"));
    match read.and_then(|text| sshsig::read_signature(&text)) {
        Ok(signed) => Some(signed),
        Err(why) => {
            let _ = writeln!(err, "{why}");
            let _ = writeln!(out, "Could not verify signature.");
            None
        }
    }
}

/// The signature of `-s` over standard input, checked: `None`, said, when
/// it does not hold.
fn checked(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> Option<Signed> {
    let signed = signature_file(args, out, err)?;
    let namespace = args.namespace.as_deref().unwrap_or_default();
    let held = sshsig::digest(&mut std::io::stdin().lock(), signed.signature.hash_alg())
        .map_err(|e| format!("Couldn't read the data: {e}"))
        .and_then(|prehash| sshsig::check(&signed.signature, namespace, &prehash));
    match held {
        Ok(()) => Some(signed),
        Err(why) => {
            let _ = writeln!(err, "{why}");
            let _ = writeln!(out, "Could not verify signature.");
            None
        }
    }
}

/// The allowed-signers file of `-f`.
fn allowed(args: &KeygenArgs, err: &mut dyn Write) -> Option<(String, Vec<Line>)> {
    let path = args.file.as_deref().unwrap_or_default();
    match std::fs::read(path) {
        Ok(raw) => Some((path.to_string(), sshsig::allowed_signers(&String::from_utf8_lossy(&raw)))),
        Err(e) => {
            let _ = writeln!(err, "podssh keygen: {path}: {e}");
            None
        }
    }
}

/// The type and the fingerprint of the key that made `signed`, as
/// `ssh-keygen` prints them: `ED25519-CERT` for a certificate, with the
/// fingerprint of its key (T-289).
fn signed_by(signed: &Signed) -> (String, String) {
    let key = PublicKey::new(signed.signature.public_key().clone(), "");
    let kind = if signed.certificate.is_some() { format!("{}-CERT", key_type(&key)) } else { key_type(&key) };
    (kind, fingerprint(&key))
}

/// `-Y verify`: the signature holds, and a line of the allowed signers
/// names the principal with the key, in the namespace and the time; a
/// `cert-authority` line names the CA of a certificate that lists the
/// principal (T-289).
fn verify(args: &KeygenArgs, options: &Options, now: i64, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(signed) = checked(args, out, err) else { return EXIT_FAILED };
    let Some((path, lines)) = allowed(args, err) else {
        let _ = writeln!(out, "Could not verify signature.");
        return EXIT_FAILED;
    };
    let principal = args.identity.as_deref().unwrap_or_default();
    let namespace = args.namespace.as_deref().unwrap_or_default();
    for line in &lines {
        match line {
            Line::Bad { line, principals, why } if sshsig::pattern_list(principals, principal) => {
                let _ = writeln!(err, "{path}:{line}: {why}");
            }
            Line::Signer(signer) if sshsig::pattern_list(&signer.principals, principal) => {
                if !sshsig::names_key(signer, &signed) {
                    continue;
                }
                // As OpenSSH checks a line: the certificate first, then the
                // line's namespaces and times.
                let ca = signer.key.key_data();
                let refused =
                    signed.certificate.as_ref().and_then(|c| sshsig_cert::not_authorized(c, ca, Some(principal), now));
                if let Some(why) = refused {
                    let _ = writeln!(err, "{path}:{}: certificate not authorized: {why}", signer.line);
                    continue;
                }
                if let Some(why) = sshsig::refuses(signer, namespace, now) {
                    let _ = writeln!(err, "{path}:{}: {why}", signer.line);
                    continue;
                }
                if !args.quiet {
                    let (kind, fp) = signed_by(&signed);
                    let _ = writeln!(out, "Good \"{namespace}\" signature for {principal} with {kind} key {fp}");
                    if options.print_pubkey {
                        let text = match &signed.certificate {
                            Some(certificate) => certificate.to_openssh(),
                            None => PublicKey::new(signed.signature.public_key().clone(), "").to_openssh(),
                        };
                        let _ = writeln!(out, "{}", text.unwrap_or_default());
                    }
                }
                return 0;
            }
            _ => {}
        }
    }
    let _ = writeln!(out, "Could not verify signature.");
    EXIT_FAILED
}

/// `-Y check-novalidate`: the signature holds, whoever made it.
fn check_novalidate(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(signed) = checked(args, out, err) else { return EXIT_FAILED };
    if !args.quiet {
        let (kind, fp) = signed_by(&signed);
        let namespace = args.namespace.as_deref().unwrap_or_default();
        let _ = writeln!(out, "Good \"{namespace}\" signature with {kind} key {fp}");
    }
    0
}

/// `-Y find-principals`: each principal of each line that allows the key of
/// the signature, in its namespace (or `-n`'s) and the time; of a
/// `cert-authority` line, the principals of the certificate that its
/// patterns allow (T-289).
fn find_principals(args: &KeygenArgs, now: i64, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(signed) = signature_file(args, &mut std::io::sink(), err) else { return EXIT_FAILED };
    let Some((path, lines)) = allowed(args, err) else { return EXIT_FAILED };
    let namespace = args.namespace.as_deref().unwrap_or(signed.signature.namespace());
    let mut found = false;
    for line in &lines {
        match line {
            Line::Bad { line, why, .. } => {
                let _ = writeln!(err, "{path}:{line}: {why}");
            }
            Line::Signer(signer) if sshsig::names_key(signer, &signed) => {
                let mut principals: Vec<String> =
                    signer.principals.split(',').filter(|p| !p.is_empty()).map(String::from).collect();
                if let Some(certificate) = &signed.certificate {
                    match sshsig_cert::principals(certificate, signer.key.key_data(), &signer.principals, now) {
                        Ok(listed) => principals = listed,
                        Err(why) => {
                            let _ = writeln!(err, "{path}:{}: {why}", signer.line);
                            continue;
                        }
                    }
                }
                // A line that refuses the namespace or the time is passed
                // over in silence, as OpenSSH passes it.
                if sshsig::refuses(signer, namespace, now).is_some() {
                    continue;
                }
                for principal in principals {
                    let _ = writeln!(out, "{principal}");
                }
                found = true;
            }
            _ => {}
        }
    }
    if found {
        return 0;
    }
    let _ = writeln!(err, "No principal matched.");
    EXIT_FAILED
}

/// `-Y match-principals`: the principals of each line that names `-I`.
fn match_principals(args: &KeygenArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some((path, lines)) = allowed(args, err) else { return EXIT_FAILED };
    let principal = args.identity.as_deref().unwrap_or_default();
    let mut found = false;
    for line in &lines {
        match line {
            Line::Bad { line, principals, why } if sshsig::pattern_list(principals, principal) => {
                let _ = writeln!(err, "{path}:{line}: {why}");
            }
            Line::Signer(signer) if sshsig::pattern_list(&signer.principals, principal) => {
                let _ = writeln!(out, "{}", signer.principals);
                found = true;
            }
            _ => {}
        }
    }
    if found {
        return 0;
    }
    let _ = writeln!(err, "No principal matched.");
    EXIT_FAILED
}
