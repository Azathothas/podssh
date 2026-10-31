//! SigV4 in a query string against AWS's own vectors (T-351): three of the
//! signing test suite of awslabs/aws-c-auth
//! (`tests/aws-signing-test-suite/v4/*/query-*.txt`, read on 2026-10-31),
//! and four presigned URLs of an openTunnel that aws-cli's own EICE signer
//! (aws/aws-cli:awscli/customizations/ec2instanceconnect/eicesigner.py, on
//! the botocore 1.34.22 that gcloud bundles) made on this host at a fixed
//! time, with the example keys of AWS's documents.

use super::*;

const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const SUITE_TIME: &str = "20150830T123600Z";
const EICE_HOST: &str = "eice-0123456789example.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";
const EICE_TOKEN: &str = "IQoJb3JpZ2luX2VjEXAMPLE/Token+With=Signs";

fn suite<'a>(params: &'a [(&'a str, String)], token: Option<&'a str>) -> Presign<'a> {
    Presign {
        access_key_id: ACCESS,
        secret_access_key: SECRET,
        session_token: token,
        region: "us-east-1",
        service: "service",
        host: "example.amazonaws.com",
        path: "/",
        params,
        amz_date: SUITE_TIME,
        expires: 3600,
    }
}

/// `get-vanilla`: its canonical request, its string to sign and its
/// signature, each as the suite writes it.
#[test]
fn sigv4_get_vanilla_is_the_suite_s() {
    let p = suite(&[], None);
    assert_eq!(
        p.canonical_request().as_str(),
        "GET\n/\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice\
         %2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host\n\
         host:example.amazonaws.com\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        p.string_to_sign(),
        "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
         bb7705b4aa3cb8e8f5e1e0b3d4c0b64030797a313c8ceee43e33117cc43eadc5"
    );
    assert_eq!(p.signature(), "e93c787ed7f371d5c6b165c1b38ede9550f4dce4144713e844b25b7192d3865d");
}

#[test]
fn sigv4_with_a_session_token_is_the_suite_s() {
    let token = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267";
    let p = suite(&[], Some(token));
    assert_eq!(
        p.string_to_sign(),
        "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
         cb30434103085aa9e73780fc60dc9a9df818fd2a7b1de12a9f6f4d791f898761"
    );
    assert_eq!(p.signature(), "7ff2b50b376cb4d151970630573d6291dc128cc5c2a12ffb237f73cc53f67b6c");
}

#[test]
fn sigv4_unreserved_characters_are_the_suite_s() {
    let unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let params = [(unreserved, unreserved.to_string())];
    let p = suite(&params, None);
    assert_eq!(p.signature(), "8e76a88a7433637b12778d5592799b29ad21ecd6cf6325051c21d86f0acda2bf");
}

fn eice<'a>(params: &'a [(&'a str, String)], token: Option<&'a str>) -> Presign<'a> {
    Presign {
        access_key_id: ACCESS,
        secret_access_key: SECRET,
        session_token: token,
        region: "us-west-2",
        service: "ec2-instance-connect",
        host: EICE_HOST,
        path: "/openTunnel",
        params,
        amz_date: "20261031T120000Z",
        expires: 60,
    }
}

fn open_tunnel(duration: bool) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("instanceConnectEndpointId", "eice-0123456789example".to_string()),
        ("remotePort", "22".to_string()),
        ("privateIpAddress", "10.0.1.5".to_string()),
    ];
    if duration {
        params.push(("maxTunnelDuration", "3600".to_string()));
    }
    params
}

/// The four URLs of aws-cli's signer: with and without a session token,
/// and with and without `maxTunnelDuration`.
#[test]
fn sigv4_open_tunnel_is_signed_as_aws_cli_signs_it() {
    for (duration, token, signature) in [
        (false, None, "7b8db765446f716ec2233fc6a725e29469ea2164b5aebbf9d8eb21bbd40bd65d"),
        (true, None, "30bb3f7304482952959106b9e4f881f9af74a95dca3e3ab45c4f6349c0749358"),
        (false, Some(EICE_TOKEN), "15beeb8c041044a0903e9bb4b1643cb0850a274b04c476f2cfddbd492a46fdd4"),
        (true, Some(EICE_TOKEN), "137beeb6b557a992bbd44690d5965a17714e62ec7d6c40e3b60116d4b10d239f"),
    ] {
        let params = open_tunnel(duration);
        assert_eq!(eice(&params, token).signature(), signature, "duration {duration}, token {}", token.is_some());
    }
}

/// The whole query, in the order of aws-cli's URL, for the case with each
/// part.
#[test]
fn sigv4_open_tunnel_query_is_aws_cli_s() {
    let params = open_tunnel(true);
    let query = eice(&params, Some(EICE_TOKEN)).query();
    assert_eq!(
        query.as_str(),
        "instanceConnectEndpointId=eice-0123456789example&remotePort=22&privateIpAddress=10.0.1.5\
         &maxTunnelDuration=3600&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261031\
         %2Fus-west-2%2Fec2-instance-connect%2Faws4_request&X-Amz-Date=20261031T120000Z&X-Amz-Expires=60\
         &X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEXAMPLE%2FToken%2BWith%3DSigns\
         &X-Amz-Signature=137beeb6b557a992bbd44690d5965a17714e62ec7d6c40e3b60116d4b10d239f"
    );
}

/// The check proves something: another secret, another time, another
/// port, each gives another signature.
#[test]
fn sigv4_a_changed_part_changes_the_signature() {
    let params = open_tunnel(false);
    let good = eice(&params, None).signature();
    let other_secret = Presign { secret_access_key: "another", ..eice(&params, None) };
    let other_time = Presign { amz_date: "20261031T120001Z", ..eice(&params, None) };
    let mut port = open_tunnel(false);
    port[1].1 = "2222".to_string();
    for p in [other_secret, other_time, eice(&port, None)] {
        assert_ne!(p.signature(), good);
    }
}

#[test]
fn sigv4_time_and_escapes_are_aws_s() {
    assert_eq!(amz_date(1_793_448_000), "20261031T120000Z");
    assert_eq!(amz_date(1_440_938_160), SUITE_TIME);
    assert_eq!(amz_date(951_868_799), "20000229T235959Z");
    assert_eq!(escape("a/b+c=d e~f"), "a%2Fb%2Bc%3Dd%20e~f");
    assert_eq!(escape("2600:1f14::1"), "2600%3A1f14%3A%3A1");
}
