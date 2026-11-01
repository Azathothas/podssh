//! RSA keys through aws-lc-rs: a key that aws-lc-rs made reads back through
//! OpenSSH's file format, its CRT exponents are aws-lc-rs's own, its
//! signatures verify, and a key, a size or a hash that aws-lc-rs does not
//! take is refused. A key of 1024 bits comes from the `rsa` crate, which only
//! a test may use.

use aws_lc_rs::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};
use russh::keys::ssh_key::LineEnding;
use russh::Signer;

use super::*;

fn identity(key: &PrivateKey) -> AgentIdentity {
    AgentIdentity::PublicKey { key: key.public_key().clone(), comment: String::new() }
}

/// The signature that `auth_sign` put after `data`: its name and its bytes.
fn signature_after(signed: &[u8], data: &[u8]) -> (String, Vec<u8>) {
    let word = |b: &[u8]| u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    assert!(signed.starts_with(data), "the data is not kept in front");
    let rest = &signed[data.len()..];
    let blob = &rest[4..];
    assert_eq!(blob.len(), word(rest), "the length of the signature");
    let name_len = word(blob);
    let name = String::from_utf8(blob[4..4 + name_len].to_vec()).unwrap();
    let sig = &blob[4 + name_len..];
    assert_eq!(sig.len(), 4 + word(sig), "the length of the signature's bytes");
    (name, sig[4..].to_vec())
}

fn rsa_of(key: &PrivateKey) -> &RsaKeypair {
    match key.key_data() {
        KeypairData::Rsa(rsa) => rsa,
        _ => panic!("not an RSA key"),
    }
}

/// A key that aws-lc-rs made, through OpenSSH's format and back, signs with
/// SHA-512 and SHA-256, and aws-lc-rs's verifier takes each signature.
#[tokio::test]
async fn rsa_key_made_here_reads_back_and_signs_with_sha2() {
    let key = PrivateKey::from(generate(2048).unwrap());
    let text = key.to_openssh(LineEnding::LF).unwrap();
    let read = PrivateKey::from_openssh(text.as_bytes()).unwrap();
    assert_eq!(read.public_key(), key.public_key());
    assert_eq!(rsa_of(&read).key_size(), 2048);
    let public = rsa_of(&read).public();
    let components = RsaPublicKeyComponents {
        n: public.n().as_positive_bytes().unwrap(),
        e: public.e().as_positive_bytes().unwrap(),
    };
    let mut signer = RsaSigner::of(&read).unwrap();
    let data = b"a session identifier and a request to log in".to_vec();
    for (hash, name, params) in [
        (HashAlg::Sha512, "rsa-sha2-512", &RSA_PKCS1_2048_8192_SHA512),
        (HashAlg::Sha256, "rsa-sha2-256", &RSA_PKCS1_2048_8192_SHA256),
    ] {
        let signed = signer.auth_sign(&identity(&read), Some(hash), data.clone()).await.unwrap();
        let (got, signature) = signature_after(&signed, &data);
        assert_eq!(got, name);
        components.verify(params, &data, &signature).unwrap();
        assert!(components.verify(params, b"other data", &signature).is_err());
    }
}

/// `d mod (p - 1)` and `d mod (q - 1)` are those that aws-lc-rs wrote in
/// the PKCS#8 of the key that it made.
#[test]
fn rsa_key_crt_exponents_are_those_of_aws_lc_rs() {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let pkcs8: Pkcs8V1Der<'static> = pair.as_der().unwrap();
    let [_, _, d, p, q, dp, dq, _] = pkcs8_integers(pkcs8.as_ref()).unwrap();
    assert_eq!(crt_exponent(&d, &p).unwrap().as_bytes(), dp.as_bytes());
    assert_eq!(crt_exponent(&d, &q).unwrap().as_bytes(), dq.as_bytes());
}

/// A key whose private exponent does not match its primes: aws-lc-rs checks
/// the key it is given, and refuses this one.
#[test]
fn rsa_key_that_does_not_hold_together_is_refused() {
    let key = generate(2048).unwrap();
    let private = key.private();
    let mut d = private.d().as_bytes().to_vec();
    *d.last_mut().unwrap() ^= 0x02;
    let wrong = RsaPrivateKey::new(
        Mpint::from_bytes(&d).unwrap(),
        private.iqmp().clone(),
        private.p().clone(),
        private.q().clone(),
    )
    .unwrap();
    let wrong = RsaKeypair::new(key.public().clone(), wrong).unwrap();
    let why = RsaSigner::of(&PrivateKey::from(wrong)).err().unwrap();
    assert!(why.contains("aws-lc-rs refused"), "{why}");
}

/// SHA-1 (`ssh-rsa`) is never signed.
#[tokio::test]
async fn rsa_key_never_signs_with_sha1() {
    let key = PrivateKey::from(generate(2048).unwrap());
    let mut signer = RsaSigner::of(&key).unwrap();
    let refused = signer.auth_sign(&identity(&key), None, b"data".to_vec()).await;
    assert!(matches!(refused, Err(SignError::Sha1)));
}

/// A key of 1024 bits, which the `rsa` crate would sign, is refused, and so
/// are the sizes that aws-lc-rs does not make.
#[test]
fn rsa_key_sizes_outside_aws_lc_rs_are_refused() {
    let small = RsaKeypair::random(&mut rand::rng(), 1024).unwrap();
    let why = RsaSigner::of(&PrivateKey::from(small)).err().unwrap();
    assert!(why.contains("1024 bits"), "{why}");
    for bits in [1024, 2047, 2500, 16384] {
        assert!(generate(bits).unwrap_err().contains(&bits.to_string()));
    }
}

/// A server that takes one key, and counts the keys offered to it.
struct Takes {
    key: russh::keys::PublicKey,
    offered: Arc<std::sync::Mutex<u32>>,
}

impl russh::server::Handler for Takes {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<russh::server::Auth, Self::Error> {
        *self.offered.lock().unwrap() += 1;
        Ok(self.judge(offer.public_key))
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(self.judge(key.public_key))
    }
}

impl Takes {
    fn judge(&self, key: &russh::keys::PublicKey) -> russh::server::Auth {
        if key.key_data() == self.key.key_data() {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        }
    }
}

/// Log in with the key file of `key` to a server in this process that takes
/// it, and lists `algorithms` for the keys of users (`server-sig-algs`):
/// whether the login passed, how many keys were offered, and the log at
/// `-v`.
async fn log_in_with(key: &PrivateKey, algorithms: Vec<russh::keys::Algorithm>, tag: &str) -> (bool, u32, String) {
    use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};
    use std::time::Duration;
    let dir = std::env::temp_dir().join(format!("podssh-rsa-login-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id_rsa");
    std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = russh::server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap());
    config.preferred.key = std::borrow::Cow::Owned(algorithms);
    config.methods = russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]);
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let offered = Arc::new(std::sync::Mutex::new(0));
    let server = Takes { key: key.public_key().clone(), offered: offered.clone() };
    tokio::spawn(async move {
        if let Ok(session) = russh::server::run_stream(Arc::new(config), server_end, server).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "rsa.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identity_files = vec![path];
    let log_path = dir.join("log");
    let log = Arc::new(crate::log::Log::to_file(LogLevel::Verbose, &log_path).unwrap());
    let run = crate::run::connect(client_end, &hop, true, &opts, &log);
    let passed = tokio::time::timeout(Duration::from_secs(30), run).await.expect("an end within 30 s").is_ok();
    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let count = *offered.lock().unwrap();
    (passed, count, text)
}

fn rsa_with(hash: Option<HashAlg>) -> russh::keys::Algorithm {
    russh::keys::Algorithm::Rsa { hash }
}

/// A key file's RSA key logs in through aws-lc-rs with the best hash that
/// the server lists, SHA-512 or SHA-256; russh's server checks that the
/// signature has the algorithm of the request, and verifies it.
#[tokio::test]
async fn rsa_key_logs_in_with_sha2() {
    let key = PrivateKey::from(generate(2048).unwrap());
    let ed25519 = russh::keys::Algorithm::Ed25519;
    let both = vec![ed25519.clone(), rsa_with(Some(HashAlg::Sha512)), rsa_with(Some(HashAlg::Sha256))];
    let (passed, offered, log) = log_in_with(&key, both, "512").await;
    assert!(passed && offered == 1, "{log}");
    let (passed, offered, log) = log_in_with(&key, vec![ed25519, rsa_with(Some(HashAlg::Sha256))], "256").await;
    assert!(passed && offered == 1, "{log}");
}

/// A server that lists only `ssh-rsa`, SHA-1, is offered no RSA key file,
/// and the log says why; nor is a key of 1024 bits offered anywhere.
#[tokio::test]
async fn rsa_key_is_not_offered_for_sha1_or_at_1024_bits() {
    let ed25519 = russh::keys::Algorithm::Ed25519;
    let key = PrivateKey::from(generate(2048).unwrap());
    let (passed, offered, log) = log_in_with(&key, vec![ed25519.clone(), rsa_with(None)], "sha1").await;
    assert!(!passed && offered == 0, "{log}");
    assert!(log.contains("only ssh-rsa (SHA-1) signatures"), "{log}");
    let small = PrivateKey::from(RsaKeypair::random(&mut rand::rng(), 1024).unwrap());
    let all = vec![ed25519, rsa_with(Some(HashAlg::Sha512)), rsa_with(Some(HashAlg::Sha256))];
    let (passed, offered, log) = log_in_with(&small, all, "1024").await;
    assert!(!passed && offered == 0, "{log}");
    assert!(log.contains("RSA key of 1024 bits"), "{log}");
}
