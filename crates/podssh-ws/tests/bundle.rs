//! **The CA bundle's resolution, and the doctor's verdicts on a bundle.** The
//! PEM reader and the trust store are `pod-tls`'s, whose tests are there.
//!
//! **A plant that has never failed is indistinguishable from a plant that
//! always passes.** Each one below asserts the *specific* failure, not
//! merely that something failed, so a defect that reddened the suite for an
//! unrelated reason cannot pass a plant that only looked at the outcome.

use std::path::PathBuf;

use podssh_ws::bundle;
use podssh_ws::error::Verdict;
use podssh_ws::{Endpoint, WsClientConfig};

// ── a CA bundle path that does not exist, through the doctor ───────────────

/// **A CA bundle that cannot be read is `FAIL` in the doctor, not `????` and
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
            assert!(detail.contains("podssh-ca.pem"), "the failure must name the path it tried, got: {detail}");
            assert_eq!(bundle_line.1.label(), "FAIL");
        }
        other => panic!("a bundle that could not be read is FAIL, not {}: {other:?}", other.label()),
    }
}

/// **The handshake that follows is `????`, not `FAIL`.** This is the case
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
    assert!(!handshake.1.is_success(), "a handshake that never ran must never count as a success");
    match &handshake.1 {
        Verdict::Unknown { why } => {
            assert!(!why.is_empty(), "???? must say why");
            assert!(why.contains("not attempted"), "got: {why}");
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// ── the three-valued type itself ────────────────────────────────────────────

/// **`Unknown` is never a success, and never prints as `ok`.** This is the
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
    // **This one.** A doctor that exits 0 because a probe could not run is
    // the exact defect this repository has shipped three times.
    assert!(!unknown.is_success());

    assert!(!unknown.to_string().starts_with("ok"));
    assert!(unknown.to_string().contains("w"), "???? must say why");
}

// ── bundle resolution from /proc/self/exe ───────────────────────────────────

/// **The bundle is resolved beside the executable, and the path is absolute.**
/// `argv[0]` is where the binary was launched from, not where it is: a binary
/// started through `PATH` or through a symlink resolves a different bundle
/// each way. The sibling project made exactly this mistake, and
/// its own record of the toolchain names three tools that it broke.
#[test]
fn the_default_bundle_path_is_beside_the_executable_and_absolute() {
    let exe = std::env::current_exe().expect("this test binary has a path");
    let bundle = bundle::default_bundle_path().expect("a bundle path");

    assert!(bundle.is_absolute(), "the bundle path must be absolute: {bundle:?}");
    assert_eq!(bundle.parent(), exe.parent(), "the bundle must sit beside the executable");
    assert_eq!(bundle.file_name().unwrap(), bundle::BUNDLE_FILE_NAME);
}

/// **The default path names a file, and the doctor says so when it is
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
