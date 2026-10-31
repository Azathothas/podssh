//! The EICE road's names, URL and upgrade (T-351): an endpoint by the DNS
//! names of AWS's documents; the presigned path that aws-cli's own signer
//! made for the same request and time; the upgrade of awscrt with aws-cli's
//! `User-Agent`; and no credential in a refusal or in `Debug`.

use super::*;

const DNS: &str = "eice-0123456789example.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";

fn credentials(token: bool) -> Credentials {
    Credentials {
        access_key_id: Zeroizing::new("AKIDEXAMPLE".into()),
        secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
        session_token: token.then(|| Zeroizing::new("IQoJb3JpZ2luX2VjEXAMPLE/Token+With=Signs".into())),
    }
}

#[test]
fn eice_endpoint_is_read_from_its_dns_name() {
    let endpoint = Endpoint::parse(DNS).unwrap();
    assert_eq!((endpoint.id.as_str(), endpoint.region.as_str()), ("eice-0123456789example", "us-west-2"));
    let fips = "eice-0123456789example.b67b86ba.fips.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";
    assert_eq!(Endpoint::parse(fips).unwrap().region, "us-west-2");
    assert_eq!(Endpoint::parse(&format!("{}.", DNS.to_ascii_uppercase())).unwrap().dns, DNS);
    for bad in [
        "",
        "ec2-instance-connect-endpoint.us-west-2.amazonaws.com",
        "vpce-0123.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com",
        "eice-0123.b67b86ba.example.com",
        "eice-0123.b67b86ba.ec2-instance-connect-endpoint",
        "eice-0123.b67b86ba.ec2-instance-connect-endpoint.uswest2.amazonaws.com",
        "eice-0123 x.ec2-instance-connect-endpoint.us-west-2.amazonaws.com",
        "eice-0123/x.ec2-instance-connect-endpoint.us-west-2.amazonaws.com",
    ] {
        assert!(Endpoint::parse(bad).is_err(), "{bad}");
    }
}

/// The path that aws-cli's signer presigned at 2026-10-31 12:00:00 UTC
/// with AWS's example key, to 10.0.1.5 port 22 with no duration.
#[test]
fn eice_presigned_path_is_aws_cli_s() {
    let endpoint = Endpoint::parse(DNS).unwrap();
    let target = Target { address: "10.0.1.5".parse().unwrap(), port: 22, max_duration: None };
    let path = presigned_path(&endpoint, &target, &credentials(false), 1_793_448_000);
    assert_eq!(
        path.as_str(),
        "/openTunnel?instanceConnectEndpointId=eice-0123456789example&remotePort=22&privateIpAddress=10.0.1.5\
         &X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261031%2Fus-west-2\
         %2Fec2-instance-connect%2Faws4_request&X-Amz-Date=20261031T120000Z&X-Amz-Expires=60\
         &X-Amz-SignedHeaders=host&X-Amz-Signature=7b8db765446f716ec2233fc6a725e29469ea2164b5aebbf9d8eb21bbd40bd65d"
    );
    // An IPv6 address goes escaped, as aws-cli's urlencode writes it.
    let v6 = Target { address: "2600:1f14::1".parse().unwrap(), port: 22, max_duration: Some(600) };
    let path = presigned_path(&endpoint, &v6, &credentials(false), 1_793_448_000);
    assert!(path.contains("&privateIpAddress=2600%3A1f14%3A%3A1&maxTunnelDuration=600&"), "{}", path.as_str());
}

#[test]
fn eice_upgrade_is_awscrt_s_with_a_user_agent() {
    let got = request(DNS, "/openTunnel?x=1", "AAAAAAAAAAAAAAAAAAAAAA==", "podssh/0").unwrap();
    let want = format!(
        "GET /openTunnel?x=1 HTTP/1.1\r\nHost: {DNS}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\nUser-Agent: podssh/0\r\n\r\n"
    );
    assert_eq!(String::from_utf8_lossy(&got), want);
    assert!(request("a.example/x", "/", "k", "ua").is_err());
    assert!(request(DNS, "/a b", "k", "ua").is_err());
}

/// A refusal that quotes what it was sent shows neither the key nor the
/// token nor the query; `Debug` shows whether the key is temporary, alone;
/// a value with a space is refused by its name.
#[test]
fn eice_no_credential_is_shown() {
    let endpoint = Endpoint::parse(DNS).unwrap();
    let target = Target { address: "10.0.1.5".parse().unwrap(), port: 22, max_duration: None };
    let creds = credentials(true);
    let path = presigned_path(&endpoint, &target, &creds, 1_793_448_000);
    let body = format!("denied: GET {} by AKIDEXAMPLE", path.as_str());
    // As upgrade_with gives it, cut at 200 characters, and whole.
    let cut: String = body.chars().take(200).collect();
    let token = "IQoJb3JpZ2luX2VjEXAMPLE/Token+With=Signs";
    for text in [cut, body.clone(), format!("{body}; X-Amz-Credential=AKIDEXAMPLE/x; token {token}")] {
        let hidden = creds.hide(&text);
        let secrets = ["AKIDEXAMPLE", "X-Amz-Signature", "X-Amz-Credential", "IQoJb3JpZ2luX2VjEXAMPLE", "Token%2BWith"];
        for secret in secrets {
            assert!(!hidden.contains(secret), "{secret}: {hidden}");
        }
        assert!(hidden.starts_with("denied: GET /openTunnel?<not shown>"), "{hidden}");
    }
    let shown = format!("{creds:?}");
    assert!(!shown.contains("AKID") && !shown.contains("wJal") && shown.contains("temporary: true"), "{shown}");
    let spaced = Credentials { secret_access_key: Zeroizing::new("a secret with spaces".into()), ..credentials(false) };
    let why = spaced.check().unwrap_err();
    assert!(why.contains("secret access key") && !why.contains("with spaces"), "{why}");
    assert!(credentials(true).check().is_ok());
}
