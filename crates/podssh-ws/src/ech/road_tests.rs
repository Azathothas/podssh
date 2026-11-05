//! What follows a sealed hello that failed, read from rustls's own error: a
//! refusal with retry configs gives them back as the list that the server
//! sent, byte for byte; a refusal with none, and any other failure, is a
//! refusal in words, after which the plain hello goes.

use std::io::ErrorKind;

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::EchConfigPayload;

use super::*;

/// The list of Cloudflare's resolvers for `crypto.cloudflare.com`, captured
/// on 2026-11-05 (`resolve/https_tests.rs`).
const LIST: &str = "0045fe0d0041e200200020746a214267a677d30d5e006df143d7c9f3fa35ebcf191ca7cf31dfae982e641b\
                    0004000100010012636c6f7564666c6172652d6563682e636f6d0000";

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// The error that tokio-rustls gives for rustls's `error`.
fn ended(error: rustls::Error) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, error)
}

fn rejected(configs: Option<Vec<EchConfigPayload>>) -> std::io::Error {
    ended(rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(configs)))
}

/// The retry configs come back as the ECHConfigList that held them: rustls
/// reads the captured list, and the configs read are that list again.
#[test]
fn a_refusal_with_retry_configs_gives_them_as_a_list() {
    let list = unhex(LIST);
    let configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&list)).expect("rustls reads the list");
    assert_eq!(configs.len(), 1);
    assert_eq!(after(&rejected(Some(configs))), Next::Retry(list));
}

/// A refusal with no retry configs, or an empty list of them, is a refusal;
/// so is a certificate that no root signs, in rustls's words with what to
/// do, and a reset.
#[test]
fn a_refusal_with_none_or_another_failure_is_a_refusal_in_words() {
    let none = Next::Refused("the server refused the sealed hello and sent no retry configs".into());
    assert_eq!(after(&rejected(None)), none);
    assert_eq!(after(&rejected(Some(Vec::new()))), none);
    let unknown = ended(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
    match after(&unknown) {
        Next::Refused(why) => assert!(why.contains("UnknownIssuer") && why.contains("--ca-file"), "{why}"),
        other => panic!("an unknown issuer is no retry: {other:?}"),
    }
    let reset = std::io::Error::from(ErrorKind::ConnectionReset);
    assert!(matches!(after(&reset), Next::Refused(_)));
}
