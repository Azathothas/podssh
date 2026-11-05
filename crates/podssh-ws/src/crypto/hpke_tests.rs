//! HPKE against RFC 9180's vectors of the base mode (appendix A.1.1 and
//! A.2.1, read from the RFC's text on 2026-11-05): each step apart, so that a
//! wrong key pair, a wrong KEM and a wrong schedule fail in tests of their own,
//! then each sealed message the RFC lists, at sequence numbers 0 to 256.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

/// One suite's vector of the base mode.
struct Vector {
    suite: &'static X25519Hpke,
    ikm_e: &'static str,
    pk_em: &'static str,
    sk_em: &'static str,
    ikm_r: &'static str,
    pk_rm: &'static str,
    sk_rm: &'static str,
    shared_secret: &'static str,
    key: &'static str,
    base_nonce: &'static str,
    /// The sequence numbers that the RFC lists, and the ciphertext of each.
    sealed: [(u64, &'static str); 6],
}

/// `info` of both vectors: "Ode on a Grecian Urn".
const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
/// The plaintext of each message: "Beauty is truth, truth beauty".
const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

/// A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
static A1: Vector = Vector {
    suite: X25519_SHA256_AES_128_GCM,
    ikm_e: "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
    pk_em: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    ikm_r: "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
    pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    shared_secret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    key: "4531685d41d65f03dc48f6b8302c05b0",
    base_nonce: "56d890e5accaaf011cff4b7d",
    sealed: [
        (0, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        (1, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
        (2, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
        (4, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
        (255, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
        (256, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
    ],
};

/// A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
static A2: Vector = Vector {
    suite: X25519_SHA256_CHACHA20_POLY1305,
    ikm_e: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    pk_em: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    ikm_r: "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
    pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    shared_secret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    base_nonce: "5c4d98150661b848853b547f",
    sealed: [
        (0, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
        (1, "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
        (2, "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b"),
        (4, "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16"),
        (255, "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c"),
        (256, "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b"),
    ],
};

/// The AAD of the message at `seq`: "Count-" and the number in decimal.
fn aad(seq: u64) -> Vec<u8> {
    format!("Count-{seq}").into_bytes()
}

/// `DeriveKeyPair` gives each vector's two key pairs from their `ikm`.
#[test]
fn each_key_pair_derives_from_its_ikm() {
    for v in [&A1, &A2] {
        let (sk_e, pk_e) = derive_key_pair(&unhex(v.ikm_e)).expect("the sender's pair");
        assert_eq!((*sk_e, pk_e), (unhex32(v.sk_em), unhex32(v.pk_em)), "{:?}", v.suite);
        let (sk_r, pk_r) = derive_key_pair(&unhex(v.ikm_r)).expect("the recipient's pair");
        assert_eq!((*sk_r, pk_r), (unhex32(v.sk_rm), unhex32(v.pk_rm)), "{:?}", v.suite);
    }
}

/// `Encap` with the vector's ephemeral key gives its `enc` (the sender's
/// public key) and its shared secret, and `Decap` the same secret.
#[test]
fn the_kem_gives_each_vector_s_shared_secret() {
    for v in [&A1, &A2] {
        let (shared, enc) = encap(&unhex(v.pk_rm), &StaticSecret::from(unhex32(v.sk_em))).expect("encap");
        assert_eq!((&shared[..], enc), (&unhex(v.shared_secret)[..], unhex(v.pk_em)), "{:?}", v.suite);
        let opened = decap(&unhex(v.pk_em), &StaticSecret::from(unhex32(v.sk_rm))).expect("decap");
        assert_eq!(&opened[..], &unhex(v.shared_secret)[..], "{:?}", v.suite);
    }
}

/// The key schedule gives each vector's key and base nonce from its shared
/// secret and `info`.
#[test]
fn the_schedule_gives_each_vector_s_key_and_nonce() {
    for v in [&A1, &A2] {
        let (key, nonce) = v.suite.schedule(&unhex(v.shared_secret), &unhex(INFO)).expect("the schedule");
        assert_eq!((&key[..], &nonce[..]), (&unhex(v.key)[..], &unhex(v.base_nonce)[..]), "{:?}", v.suite);
    }
}

/// Each message that the RFC lists is sealed to its ciphertext, at its
/// sequence number, and the recipient's context opens each in turn.
#[test]
fn each_listed_message_seals_to_the_rfc_s_ciphertext_and_opens_again() {
    for v in [&A1, &A2] {
        let (enc, mut sealer) =
            v.suite.sealer_with(&unhex(INFO), &unhex(v.pk_rm), &StaticSecret::from(unhex32(v.sk_em))).expect("setup");
        assert_eq!(enc, unhex(v.pk_em));
        let key = HpkePrivateKey::from(unhex(v.sk_rm));
        let mut opener = v.suite.opener(&enc, &unhex(INFO), &key).expect("the recipient's setup");
        for seq in 0..=256u64 {
            let sealed = sealer.seal(&aad(seq), &unhex(PT)).expect("seal");
            if let Some((_, ct)) = v.sealed.iter().find(|(at, _)| *at == seq) {
                assert_eq!(sealed, unhex(ct), "{:?} at sequence number {seq}", v.suite);
            }
            assert_eq!(opener.open(&aad(seq), &sealed).expect("open"), unhex(PT), "{:?} at {seq}", v.suite);
        }
    }
}

/// Through rustls's own interface: a sealed message opens with the right
/// key and AAD, and a changed byte, another AAD or another key is refused.
#[test]
fn rustls_s_interface_opens_what_it_seals_and_nothing_else() {
    for suite in [X25519_SHA256_AES_128_GCM, X25519_SHA256_CHACHA20_POLY1305] {
        let (pk, sk) = suite.generate_key_pair().expect("a key pair");
        let (enc, sealed) = suite.seal(b"info", b"aad", b"the inner hello", &pk).expect("seal");
        assert_eq!(suite.open(&enc, b"info", b"aad", &sealed, &sk).expect("open"), b"the inner hello");
        let mut changed = sealed.clone();
        changed[0] ^= 1;
        assert!(suite.open(&enc, b"info", b"aad", &changed, &sk).is_err(), "{suite:?}: a changed byte");
        assert!(suite.open(&enc, b"info", b"other", &sealed, &sk).is_err(), "{suite:?}: another AAD");
        assert!(suite.open(&enc, b"other", b"aad", &sealed, &sk).is_err(), "{suite:?}: another info");
        let (_, other) = suite.generate_key_pair().expect("another pair");
        assert!(suite.open(&enc, b"info", b"aad", &sealed, &other).is_err(), "{suite:?}: another key");
        // Two seals to one key never share an ephemeral key.
        let (again, _) = suite.seal(b"info", b"aad", b"the inner hello", &pk).expect("seal");
        assert_ne!(enc.0, again.0, "{suite:?}");
    }
}

/// A public key of small order gives an all-zero Diffie-Hellman output, which
/// section 7.1.4 refuses; a key of another length is refused too.
#[test]
fn a_public_key_of_small_order_or_another_length_is_refused() {
    let suite = X25519_SHA256_AES_128_GCM;
    for bad in [vec![0u8; 32], {
        let mut one = vec![0u8; 32];
        one[0] = 1;
        one
    }] {
        assert!(suite.setup_sealer(b"info", &HpkePublicKey(bad.clone())).is_err(), "{bad:?}");
    }
    assert!(suite.setup_sealer(b"info", &HpkePublicKey(vec![9u8; 31])).is_err());
}

/// The suites name rustls's identifiers, which an ECHConfig's are matched
/// against: X25519 and HKDF-SHA256, with AES-128-GCM first.
#[test]
fn the_suites_are_those_that_an_ech_config_names() {
    let first = SUITES[0].suite();
    assert_eq!(first.kem, HpkeKem::DHKEM_X25519_HKDF_SHA256);
    assert_eq!(first.sym.kdf_id, HpkeKdf::HKDF_SHA256);
    assert_eq!(first.sym.aead_id, HpkeAead::AES_128_GCM);
    assert_eq!(SUITES[1].suite().sym.aead_id, HpkeAead::CHACHA20_POLY_1305);
    assert!(SUITES.iter().all(|s| !s.fips()), "no suite here is FIPS's");
}
