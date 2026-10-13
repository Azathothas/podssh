//! The formats of `sk-` keys, against bytes that OpenSSH wrote. The
//! signatures and public keys are the test vectors of ssh-key 0.7.0-rc.11
//! (`tests/examples/sshsig_sk_ed25519`, `id_sk_ed25519_2.pub` and
//! `id_sk_ecdsa_p256_2.pub`, and the wire signatures of its `src/signature.rs`
//! and `tests/sshsig.rs`): an SSH signature of OpenSSH's `ssh-keygen -Y
//! sign`, and one that an agent of OpenSSH gave, each of the message
//! "testing". Their source does not say which device made them; their
//! counters (9 and 236) are those of a device in use.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use russh::keys::ssh_key::{Signature, SshSig};
use russh::keys::PublicKey;
use signature::Verifier;

use super::super::soft::{attested, auth_data as soft_auth_data, unhex, SoftKey};
use super::*;

const SK_ED25519_PUBLIC: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAINSoElFleH+nN83FoLqqepJjN+y7Gs5lrn7qXjBqQZyuAAAABHNzaDo= user@example.com";

const SK_ED25519_SSHSIG: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAg1KgSUW
V4f6c3zcWguqp6kmM37LsazmWufupeMGpBnK4AAAAEc3NoOgAAAAdleGFtcGxlAAAAAAAA
AAZzaGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQC9WcLb5NG
XRdCOHinQIS/MxdnAx7SQMYnyOt5q4+huTWh/Zk/UvWhP+wXl/ikNPlDpgliRq6o3VyKqS
LLo9lQYBAAAACQ==
-----END SSH SIGNATURE-----
";

/// The signature inside [`SK_ED25519_SSHSIG`]: the name, 64 bytes, the
/// flags 0x01 and the counter 9.
const SK_ED25519_WIRE: &str = "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000040
    2f5670b6f93465d17423878a74084bf331767031ed240c627c8eb79ab8fa1b935a1fd993f52f5a13fec1797f8a434f943a
    6096246aea8dd5c8aa922cba3d95060100000009";

const SK_ECDSA_PUBLIC: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBNdo6XfhTK080uz5UbGyOcNMo+R3nPXMBxurwH2M1bDtQYbDT6qBE7EdQGkcy/EJDXbzT0KlU9rROjcX+JsgtGAAAAAEc3NoOg== user@example.com";

/// A signature of "testing" by the key of [`SK_ECDSA_PUBLIC`]: the name, r
/// and s as mpints in a string, the flags 0x01 and the counter 236.
const SK_ECDSA_WIRE: &str = "00000022736b2d65636473612d736861322d6e69737470323536406f70656e73
    73682e636f6d00000049000000201b35a1c6469a43a3d09d490d6ff8ca1bc248
    6a2edeb8aa7d119e4c70b9c1811000000021009724a2a4449a90357485ed1df0
    161274d20083342b02756794bc3f068fcdc15e01000000ec";

/// A DER INTEGER of a positive number.
fn der_int(n: &[u8]) -> Vec<u8> {
    let pad = n[0] & 0x80 != 0;
    let mut out = vec![0x02, (n.len() + usize::from(pad)) as u8];
    if pad {
        out.push(0);
    }
    out.extend_from_slice(n);
    out
}

/// What a device answers for r and s: X9.62's DER.
fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let body = [der_int(r), der_int(s)].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

/// A device's Ed25519 answer, made into SSH's signature, is byte for byte
/// the one that OpenSSH wrote, and it verifies.
#[test]
fn sk_signature_ed25519_is_the_one_openssh_wrote() {
    let wire = unhex(SK_ED25519_WIRE);
    assert_eq!(wire.len(), 103);
    let sshsig = SshSig::from_pem(SK_ED25519_SSHSIG).unwrap();
    assert_eq!(Vec::<u8>::try_from(sshsig.signature().clone()).unwrap(), wire, "the vector is the SSHSIG's");
    let public = PublicKey::from_openssh(SK_ED25519_PUBLIC).unwrap();
    public.verify("example", b"testing", &sshsig).expect("OpenSSH's signature verifies");

    // What the device gave: its authenticator data for "ssh:", the flags
    // 0x01 and the counter 9, and the 64 bytes of Ed25519.
    let device = soft_auth_data("ssh:", 0x01, 9);
    let signed = signed("ssh:", &device, wire[34..98].to_vec()).unwrap();
    assert_eq!((signed.flags, signed.counter), (0x01, 9));
    assert_eq!(signature_blob(Alg::Ed25519, &signed).unwrap(), wire);
}

/// A device's ECDSA answer (DER, whose s has a leading zero) is OpenSSH's
/// signature byte for byte, and ssh-key verifies OpenSSH's.
#[test]
fn sk_signature_ecdsa_is_the_one_openssh_wrote() {
    let wire = unhex(SK_ECDSA_WIRE);
    assert_eq!(wire.len(), 120);
    let public = PublicKey::from_openssh(SK_ECDSA_PUBLIC).unwrap();
    let theirs = Signature::try_from(&wire[..]).unwrap();
    public.key_data().verify(b"testing", &theirs).expect("OpenSSH's signature verifies");

    let (r, s) = (&wire[46..78], &wire[83..115]);
    let device = soft_auth_data("ssh:", 0x01, 0xec);
    let signed = signed("ssh:", &device, der_signature(r, s)).unwrap();
    assert_eq!(signature_blob(Alg::EcdsaP256, &signed).unwrap(), wire);
}

/// A device in software signs as a device does, and ssh-key verifies what
/// podssh made of each answer with the key file's public key; with another
/// message, or another counter, it does not.
#[test]
fn sk_signature_of_a_software_device_verifies() {
    for alg in [Alg::Ed25519, Alg::EcdsaP256] {
        let device = SoftKey::new(alg);
        let enrolled = Enrolled { public: device.point(), key_handle: vec![7; 64] };
        let key = private_key(alg, &enrolled, "ssh:", USER_PRESENCE_REQUIRED, "test").unwrap();
        let public = key.public_key().key_data();
        let (auth, signature) = device.assert("ssh:", 0x01, 41, b"the data of a login");
        let blob = signature_blob(alg, &signed("ssh:", &auth, signature).unwrap()).unwrap();
        let ssh = Signature::try_from(&blob[..]).unwrap();
        public.verify(b"the data of a login", &ssh).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        assert!(public.verify(b"other data", &ssh).is_err(), "{alg:?}: another message");
        let mut later = blob.clone();
        let at = later.len() - 1;
        later[at] ^= 1;
        let later = Signature::try_from(&later[..]).unwrap();
        assert!(public.verify(b"the data of a login", &later).is_err(), "{alg:?}: another counter");
    }
}

/// A new key's file holds, field by field, what PROTOCOL.key and
/// PROTOCOL.u2f give, read here without ssh-key; and ssh-key reads it back.
#[test]
fn a_key_file_holds_the_fields_of_openssh() {
    let device = SoftKey::new(Alg::EcdsaP256);
    let enrolled = Enrolled { public: device.point(), key_handle: (1..=48).collect() };
    let flags = USER_PRESENCE_REQUIRED | super::super::RESIDENT_KEY;
    let key = private_key(Alg::EcdsaP256, &enrolled, "ssh:podssh", flags, "a comment").unwrap();
    let text = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let bytes = STANDARD.decode(body).unwrap();
    let mut rest = bytes.strip_prefix(b"openssh-key-v1\0".as_slice()).expect("the magic");
    let take = |rest: &mut &[u8]| -> Vec<u8> {
        let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let value = rest[4..4 + length].to_vec();
        *rest = &rest[4 + length..];
        value
    };
    assert_eq!(take(&mut rest), b"none", "the cipher");
    assert_eq!(take(&mut rest), b"none", "the KDF");
    assert_eq!(take(&mut rest), b"", "the KDF's options");
    assert_eq!(&rest[..4], &[0, 0, 0, 1], "one key");
    rest = &rest[4..];
    assert_eq!(take(&mut rest), public_blob(Alg::EcdsaP256, &enrolled.public, "ssh:podssh"), "the public key");
    let private = take(&mut rest);
    assert!(rest.is_empty());
    let mut p = private.as_slice();
    assert_eq!(p[..4], p[4..8], "the two check numbers");
    p = &p[8..];
    assert_eq!(take(&mut p), b"sk-ecdsa-sha2-nistp256@openssh.com");
    assert_eq!(take(&mut p), b"nistp256");
    assert_eq!(take(&mut p), enrolled.public);
    assert_eq!(take(&mut p), b"ssh:podssh");
    assert_eq!(p[0], flags, "the flags");
    p = &p[1..];
    assert_eq!(take(&mut p), enrolled.key_handle, "the key handle");
    assert_eq!(take(&mut p), b"", "the reserved string");
    assert_eq!(take(&mut p), b"a comment");
    assert!(p.iter().enumerate().all(|(i, b)| usize::from(*b) == i + 1), "the padding: {p:?}");

    let read = PrivateKey::from_openssh(text.as_bytes()).unwrap();
    let sk = SkKey::of(read.key_data()).unwrap();
    let want = SkKey { alg: Alg::EcdsaP256, application: "ssh:podssh".into(), flags, key_handle: enrolled.key_handle };
    assert_eq!(sk, want);
    assert!(sk.touch() && !sk.verify());
    assert!(is_sk(read.public_key()));
}

/// A new key is read from the device's authenticator data, and an answer
/// for another application, or with extensions, is refused.
#[test]
fn answers_of_a_device_are_read_and_checked() {
    for alg in [Alg::Ed25519, Alg::EcdsaP256] {
        let device = SoftKey::new(alg);
        let data = attested("ssh:", 0x01, b"the handle", &device.cose());
        let made = enrolled(alg, "ssh:", &data, Some(b"the handle".as_slice())).unwrap();
        assert_eq!((made.public, made.key_handle), (device.point(), b"the handle".to_vec()));
        assert!(enrolled(alg, "ssh:other", &data, None).unwrap_err().contains("another application"));
        assert!(enrolled(alg, "ssh:", &data, Some(b"another".as_slice())).unwrap_err().contains("two different keys"));
        let other = if alg == Alg::Ed25519 { Alg::EcdsaP256 } else { Alg::Ed25519 };
        assert!(enrolled(other, "ssh:", &data, None).is_err(), "{alg:?} read as {other:?}");
    }
    let plain = soft_auth_data("ssh:", 0x01, 3);
    assert!(signed("ssh:", &plain, vec![0; 64]).is_ok());
    assert!(signed("ssh:x", &plain, vec![0; 64]).unwrap_err().contains("another application"));
    let mut extended = soft_auth_data("ssh:", 0x81, 3);
    extended.extend_from_slice(&[0xa0]);
    assert!(signed("ssh:", &extended, vec![0; 64]).unwrap_err().contains("extensions"));
    assert!(signed("ssh:", &plain[..36], vec![0; 64]).unwrap_err().contains("short"));
}

#[test]
fn an_ecdsa_signature_that_is_no_der_is_refused() {
    let good = der_signature(&[1; 32], &[0x80; 32]);
    assert_eq!(der_ecdsa(&good).unwrap(), (vec![1; 32], vec![0x80; 32]));
    for bad in [&good[..good.len() - 1], &[0x31, 0x00][..], &[0x30, 0x02, 0x02, 0x00][..], &[][..]] {
        assert!(der_ecdsa(bad).is_err(), "{bad:02x?}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(der_ecdsa(&trailing).is_err(), "a byte after the signature");
    let long = der_signature(&[1; 33], &[1; 32]);
    assert!(der_ecdsa(&long).unwrap_err().contains("P-256"));
}
