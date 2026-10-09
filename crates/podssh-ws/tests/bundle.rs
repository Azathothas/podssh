//! ⛔ **The CA bundle, its resolution, and E03's first two plants.**
//!
//! ⛔ **A plant that has never failed is indistinguishable from a plant that
//! always passes.** Each of the two below asserts the *specific* failure, not
//! merely that something failed, so a defect that reddened the suite for an
//! unrelated reason cannot pass a plant that only looked at the outcome.

use std::path::{Path, PathBuf};

use podssh_ws::bundle;
use podssh_ws::error::Verdict;
use podssh_ws::{Endpoint, WsClientConfig};

/// A real certificate, in PEM, used to check the decoder against known bytes.
/// This is `webpki-roots`' own first entry — a DigiCert root — and the base64
/// below is checked against it in `plant_pem_decoding_is_byte_exact`.
const DIGICERT_ECC_ROOT_G5: &str = "-----BEGIN CERTIFICATE-----
MIICGTCCAZ+gAwIBAgIQCeCTZaz32ci5PhwLBCou8zAKBggqhkjOPQQDAzBOMQsw
CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURp
Z2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDExNTAwMDAwMFoXDTQ2
MDExNDIzNTk1OVowTjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
bmMuMSYwJAYDVQQDEx1EaWdpQ2VydCBUTFMgRUNDIFAzODQgUm9vdCBHNTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABMFEoc8Rl1Ca3iOCNQfN0MsYndLxf3c1TzvdlHJS
7cI7+Oz6e2tYIOyZrsn8aLN1udsJ7MgT9U7GCh1mMEy7H0cKPGEQQil8pQgO4CLp
0zVozptjn4S1mU1YoI71VOeVyaNCMEAwHQYDVR0OBBYEFMFRRVBZqz7nLFr6ICIS
B4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMDA2gAMGUCMQCJao1H5+z8blUD2WdsJk6Dxv3J+ysTvLd6jLRl0mlpYxNjOyZQ
LgGheQaRnUi/wr4CMEfDFXuxoJGZSZOoPHzoRgaLLPIxAJSdYsiJvRmEFOml+wG4
DXZDjC5Ty3zfDBeWUA==
-----END CERTIFICATE-----
";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── the PEM decoder ─────────────────────────────────────────────────────────

/// ⛔ **Byte-exact.** The first bytes of the decoded certificate are asserted
/// as hex, so a decoder that is off by one base64 character — the failure that
/// produces a certificate that parses as garbage and a chain error that reads
/// like an untrusted issuer — cannot pass.
#[test]
fn plant_pem_decoding_is_byte_exact() {
    let certs = bundle::pem_certificates(DIGICERT_ECC_ROOT_G5.as_bytes()).expect("a single PEM certificate");
    assert_eq!(certs.len(), 1);
    // ⛔ A DER SEQUENCE, tag 0x30. The whole length follows; the point is that
    // the first byte is right, which a shifted decoder gets wrong.
    assert_eq!(certs[0].as_ref()[0], 0x30);
    // ⛔ **The exact length and the exact first eight bytes**, measured from
    // the same PEM by decoding it independently. A decoder off by one base64
    // character produces a certificate of the wrong length that still starts
    // 0x30, so the length is the half that catches it.
    assert_eq!(certs[0].as_ref().len(), 541, "the certificate was mis-decoded");
    assert_eq!(hex(&certs[0].as_ref()[..8]), "308202193082019f");
}

#[test]
fn a_bundle_with_several_certificates_yields_all_of_them() {
    let two = format!("{DIGICERT_ECC_ROOT_G5}\n{DIGICERT_ECC_ROOT_G5}");
    let certs = bundle::pem_certificates(two.as_bytes()).expect("two certificates");
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0], certs[1], "the same input parsed two ways");
}

/// ⛔ **Comments and blank lines between blocks are ignored.** A real CA
/// bundle carries human-readable text, and a decoder that refused it would
/// reject bundles that work everywhere else.
#[test]
fn text_between_blocks_is_ignored() {
    let with_comments = format!(
        "# a bundle installed by an operator\n\n{DIGICERT_ECC_ROOT_G5}\n\
         # and a note between two certificates\n{DIGICERT_ECC_ROOT_G5}\n"
    );
    let certs = bundle::pem_certificates(with_comments.as_bytes()).expect("comments ignored");
    assert_eq!(certs.len(), 2);
}

/// ⛔ **A `PRIVATE KEY` block is not a certificate.** A trust bundle carrying
/// one holds a key in a world-readable file, and a parser that skipped it
/// silently would hide that.
#[test]
fn a_private_key_block_is_not_read_as_a_certificate() {
    let pem =
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
    let certs = bundle::pem_certificates(pem.as_bytes()).expect("an empty list is not an error");
    assert!(certs.is_empty(), "a private key was read as a certificate");
}

#[test]
fn a_begin_without_an_end_is_an_error() {
    let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n";
    let err = bundle::pem_certificates(pem.as_bytes()).expect_err("an unterminated block");
    assert!(err.contains("END"), "got {err}");
}

#[test]
fn non_base64_inside_a_block_is_an_error() {
    let pem = "-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n";
    assert!(bundle::pem_certificates(pem.as_bytes()).is_err());
}

// ── PLANT 1: a CA bundle path that does not exist ───────────────────────────

/// ⛔ **E03's first plant: a CA bundle path that does not exist must `FAIL`,
/// with the path it tried.**
#[test]
fn plant_a_missing_ca_bundle_fails_and_names_the_path() {
    let missing = PathBuf::from("/nonexistent/podssh-does-not-exist-ca.pem");
    let err = podssh_ws::tls::roots_from_bundle(&missing).expect_err("a missing bundle");

    match err {
        podssh_ws::WsError::Bundle { path, why } => {
            // ⛔ **The path must be in the message.** A deployment that cannot
            // find its trust store cannot be diagnosed from "TLS failed", and
            // naming the path is the whole point of this plant.
            assert_eq!(path, missing.display().to_string());
            assert!(
                why.to_lowercase().contains("no such file") || why.to_lowercase().contains("cannot find"),
                "the reason must name the OS error, got: {why}"
            );
        }
        other => panic!("expected a Bundle error, got {other:?}"),
    }
}

/// ⛔ **And the same defect seen through the doctor is `FAIL`, not `????` and
/// not `ok`.** A bundle that cannot be read is a check that *ran* and did not
/// hold; it is different from one that could not run at all.
#[tokio::test]
async fn plant_a_missing_bundle_is_fail_in_the_doctor() {
    let config = WsClientConfig {
        endpoint: Endpoint { host: "relay.invalid".into(), port: 443, path: "/v1/connect/x".into() },
        trust: podssh_ws::Trust::File(PathBuf::from("/nonexistent/podssh-ca.pem")),
        server_name: "relay.invalid".into(),
        timeout: std::time::Duration::from_millis(50),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    let report = podssh_ws::doctor(&config).await;
    let bundle_line = report.iter().find(|(name, _)| name == "trust store").expect("the doctor reports the bundle");

    match &bundle_line.1 {
        Verdict::Failed { detail } => {
            assert!(detail.contains("podssh-ca.pem"), "⛔ the failure must name the path it tried, got: {detail}");
            assert_eq!(bundle_line.1.label(), "FAIL");
        }
        other => panic!("a bundle that could not be read is FAIL, not {}: {other:?}", other.label()),
    }
}

/// ⛔ **The handshake that follows is `????`, not `FAIL`.** This is the case
/// that makes the three-valued report worth having: the handshake was never
/// attempted, because there was no trust anchor to verify a chain against.
/// Reporting it as a handshake failure would blame the relay for a local
/// misconfiguration — and reporting it as `ok` is the defect four sibling
/// projects shipped.
#[tokio::test]
async fn an_unattempted_handshake_is_unknown_never_ok() {
    let config = WsClientConfig {
        endpoint: Endpoint { host: "relay.invalid".into(), port: 443, path: "/v1/connect/x".into() },
        trust: podssh_ws::Trust::File(PathBuf::from("/nonexistent/podssh-ca.pem")),
        server_name: "relay.invalid".into(),
        timeout: std::time::Duration::from_millis(50),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    let report = podssh_ws::doctor(&config).await;
    let handshake = report.iter().find(|(name, _)| name == "TLS handshake").expect("the doctor reports the handshake");

    assert_eq!(handshake.1.label(), "????");
    assert!(!handshake.1.is_success(), "⛔ a handshake that never ran must never count as a success");
    match &handshake.1 {
        Verdict::Unknown { why } => {
            assert!(!why.is_empty(), "???? must say why");
            assert!(why.contains("not attempted"), "got: {why}");
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// ── the three-valued type itself ────────────────────────────────────────────

/// ⛔ **`Unknown` is never a success, and never prints as `ok`.** This is the
/// property the whole enum exists to hold, asserted directly so a later edit
/// to `is_success` cannot quietly break every caller at once.
#[test]
fn the_three_valued_type_holds_its_contract() {
    let ok = Verdict::Ok { detail: "d".into() };
    let failed = Verdict::Failed { detail: "d".into() };
    let unknown = Verdict::Unknown { why: "w".into() };

    assert_eq!(ok.label(), "ok");
    assert_eq!(failed.label(), "FAIL");
    assert_eq!(unknown.label(), "????");

    assert!(ok.is_success());
    assert!(!failed.is_success());
    // ⛔ **This one.** A doctor that exits 0 because a probe could not run is
    // the exact defect this repository has shipped three times.
    assert!(!unknown.is_success());

    assert!(!unknown.to_string().starts_with("ok"));
    assert!(unknown.to_string().contains("w"), "???? must say why");
}

// ── bundle resolution from /proc/self/exe ───────────────────────────────────

/// ⛔ **The bundle is resolved beside the executable, and the path is absolute.**
/// `argv[0]` is where the binary was launched from, not where it is: a binary
/// started through `PATH` or through a symlink resolves a different bundle
/// each way. The sibling project made exactly this mistake, and
/// `docs/decisions/toolchain-contract.md:82-93` names three tools it broke.
#[test]
fn the_default_bundle_path_is_beside_the_executable_and_absolute() {
    let exe = std::env::current_exe().expect("this test binary has a path");
    let bundle = bundle::default_bundle_path().expect("a bundle path");

    assert!(bundle.is_absolute(), "the bundle path must be absolute: {bundle:?}");
    assert_eq!(bundle.parent(), exe.parent(), "⛔ the bundle must sit beside the executable");
    assert_eq!(bundle.file_name().unwrap(), bundle::BUNDLE_FILE_NAME);
}

/// ⛔ **The default path names a file, and the doctor says so when it is
/// missing.** This is the control for plant 1: the path resolution itself is
/// exercised, and a deployment reading this learns exactly which file to
/// install.
#[tokio::test]
async fn the_default_path_is_what_the_doctor_reports_when_it_is_absent() {
    let exe = std::env::current_exe().expect("a path");
    let bundle = exe.parent().expect("a parent").join("podssh-ca-not-installed-for-this-test.pem");
    assert!(!bundle.exists(), "the planted path must not exist");

    let config = WsClientConfig {
        endpoint: Endpoint { host: "relay.invalid".into(), port: 443, path: "/v1/connect/x".into() },
        trust: podssh_ws::Trust::File(bundle.clone()),
        server_name: "relay.invalid".into(),
        timeout: std::time::Duration::from_millis(50),
        idle_timeout: None,
        proxy: podssh_ws::ProxyChoice::Direct,
    };
    let report = podssh_ws::doctor(&config).await;
    let line = report.iter().find(|(n, _)| n == "trust store").expect("a bundle line");
    assert_eq!(line.1.label(), "FAIL");
    match &line.1 {
        Verdict::Failed { detail } => {
            assert!(detail.contains("podssh-ca-not-installed-for-this-test.pem"))
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

// ── a bundle that parses but holds nothing usable ───────────────────────────

/// ⛔ **A PEM file with no CERTIFICATE block is an error, not an empty trust
/// store.** An empty `RootCertStore` rejects every chain with a message that
/// reads like a network fault, so the two must not be confusable.
#[test]
fn a_pem_file_with_no_certificate_is_an_error() {
    let path = Path::new("/tmp/podssh-empty-bundle.pem");
    let err = bundle::parse_bundle(path, b"# nothing but a comment\n").expect_err("a bundle with no certificate");
    assert!(err.contains("no CERTIFICATE block"), "the message must say what was wrong, got: {err}");
}

/// ⛔ **A file that is not UTF-8 is an error.** A binary trust store is a
/// deployment mistake, and "not a PEM bundle" is a far better report than a
/// chain error forty seconds later.
#[test]
fn a_binary_file_is_not_a_bundle() {
    let err = bundle::parse_bundle(Path::new("/tmp/x.pem"), &[0xff, 0xfe, 0x00, 0x01]).expect_err("binary is not PEM");
    assert!(err.contains("UTF-8"), "got {err}");
}

// ── the default trust store ─────────────────────────────────────────────────

/// With no explicit file, podssh still has trust anchors: the compiled-in set
/// is always there, so a host with no CA bundle can connect.
#[test]
fn the_default_trust_store_is_never_empty() {
    let roots = podssh_ws::tls::roots_for(&podssh_ws::Trust::Default).expect("default roots");
    assert!(roots.count >= 100, "only {} anchors", roots.count);
    assert!(roots.source.contains("compiled-in"), "{}", roots.source);
}

/// An explicit file is used alone: a missing one is an error naming the path,
/// never a silent fall back to the defaults.
#[test]
fn an_explicit_trust_file_is_never_widened() {
    let missing = PathBuf::from("/nonexistent/explicit-ca.pem");
    let err = podssh_ws::tls::roots_for(&podssh_ws::Trust::File(missing)).unwrap_err();
    assert!(err.to_string().contains("explicit-ca.pem"), "{err}");
}
