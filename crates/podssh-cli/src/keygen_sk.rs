//! `podssh keygen -t ed25519-sk` and `-t ecdsa-sk` (T-229): a key made in a
//! FIDO2 device, as OpenSSH's `ssh-keygen` makes it. Its file holds the
//! device's handle of the key, the application and the flags, and no
//! private key; the device keeps that. The `-O` options are those of
//! `ssh-keygen`. The probe runs before anything else: with no device that
//! podssh may reach, it refuses with the reason, and asks and writes
//! nothing.

use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_ssh::sk::{self, Alg, Ask, Enroll};
use zeroize::Zeroizing;

use crate::exit_codes::EXIT_USAGE;
use crate::keygen::{ask_new_passphrase, tell_saved, KeygenArgs, NewPassphrase, EXIT_FAILED, KEY_FILES};

/// What `-O` asks of a new key.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    application: String,
    user: Vec<u8>,
    resident: bool,
    touch: bool,
    verify: bool,
    device: Option<PathBuf>,
}

/// The options of a new key, as `ssh-keygen` takes them.
fn options(list: &[String]) -> Result<Options, String> {
    let mut options = Options {
        application: "ssh:".into(),
        user: vec![0; 32],
        resident: false,
        touch: true,
        verify: false,
        device: None,
    };
    for option in list {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (option.as_str(), None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("resident", None) => options.resident = true,
            ("no-touch-required", None) => options.touch = false,
            ("verify-required", None) => options.verify = true,
            ("application", Some(app)) if app.starts_with("ssh:") => options.application = app.to_string(),
            ("application", Some(app)) => return Err(format!("-O application={app}: an application starts with ssh:")),
            // The user id of OpenSSH: the name, then zeros to 32 bytes.
            ("user", Some(user)) if !user.is_empty() && user.len() <= 32 => {
                options.user = user.as_bytes().to_vec();
                options.user.resize(32, 0);
            }
            ("user", Some(user)) => return Err(format!("-O user={user}: a user of 1 to 32 bytes")),
            ("device", Some(path)) if !path.is_empty() => options.device = Some(PathBuf::from(path)),
            ("challenge" | "write-attestation", _) => {
                return Err(format!("-O {name}: podssh keeps no attestation of the device, and takes no challenge"))
            }
            _ => {
                return Err(format!(
                    "-O {option}: a new key of a security key takes resident, application=ssh:NAME, user=NAME, \
                     no-touch-required, verify-required and device=PATH"
                ))
            }
        }
    }
    Ok(options)
}

/// Make the key of `alg` in a device, and write its file to `path` (which
/// does not exist) and `path.pub`.
pub(crate) fn make(
    args: &KeygenArgs,
    alg: Alg,
    path: &Path,
    comment: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let options = match options(&args.options) {
        Ok(options) => options,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_USAGE;
        }
    };
    if args.format.is_some() {
        let _ = writeln!(err, "podssh keygen: -m: a key of a security key has the format of OpenSSH only");
        return EXIT_USAGE;
    }
    // The probe: with no device, nothing is asked and nothing is written.
    let device = match sk::probe(options.device.as_deref()) {
        Ok(device) => device,
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            return EXIT_FAILED;
        }
    };
    // Before the touch, so that a run with nobody to ask stops before it.
    let passphrase = match args.passphrase {
        NewPassphrase::Absent => match ask_new_passphrase("Enter passphrase (empty for no passphrase): ") {
            Ok(passphrase) => passphrase,
            Err(why) => {
                let _ = writeln!(err, "podssh keygen: {why}");
                return EXIT_FAILED;
            }
        },
        NewPassphrase::Empty | NewPassphrase::Given => Zeroizing::new(String::new()),
    };
    if !args.quiet {
        let name = if alg == Alg::Ed25519 { "ed25519-sk" } else { "ecdsa-sk" };
        let _ = writeln!(out, "Generating public/private {name} key pair.");
    }
    let request = Enroll {
        alg,
        application: options.application,
        user: options.user,
        resident: options.resident,
        touch: options.touch,
        verify: options.verify,
    };
    let said = std::cell::RefCell::new(err);
    let say = |line: &str| {
        let _ = writeln!(said.borrow_mut(), "{line}");
    };
    let pin = |prompt: &str| sk::ask_pin(prompt, true);
    let made = sk::enroll(&device, &request, &Ask { say: &say, pin: &pin });
    let err = said.into_inner();
    let written = made.and_then(|made| {
        let key = sk::private_key(alg, &made, &request.application, request.flags(), comment)?;
        let text = crate::keygen_convert::private_text(&key, None, &passphrase, &mut *err)?;
        let line = key.public_key().to_openssh().map_err(|e| format!("could not encode the public key: {e}"))?;
        let public = podssh_ssh::keygen::write_texts(path, &text, &line, KEY_FILES)?;
        Ok((key, public))
    });
    match written {
        Ok((key, public)) => {
            if !args.quiet {
                tell_saved(out, path, &public, key.public_key(), comment);
            }
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh keygen: {why}");
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(list: &[&str]) -> Result<Options, String> {
        options(&list.iter().map(|o| o.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_options_of_ssh_keygen_are_read() {
        let plain = given(&[]).unwrap();
        assert_eq!((plain.application.as_str(), plain.user, plain.touch), ("ssh:", vec![0; 32], true));
        let all = ["resident", "verify-required", "no-touch-required", "application=ssh:git", "user=me"];
        let all = given(&all).unwrap();
        assert!(all.resident && all.verify && !all.touch);
        assert_eq!(all.application, "ssh:git");
        assert_eq!(&all.user[..3], b"me\0");
        assert_eq!(all.user.len(), 32);
        assert_eq!(given(&["device=/dev/hidraw3"]).unwrap().device, Some(PathBuf::from("/dev/hidraw3")));
        for bad in ["application=git", "user=", "challenge=FILE", "write-attestation=FILE", "hashalg=sha256", "rk"] {
            assert!(given(&[bad]).is_err(), "{bad}");
        }
        let long = format!("user={}", "u".repeat(33));
        assert!(given(&[long.as_str()]).is_err());
    }
}
