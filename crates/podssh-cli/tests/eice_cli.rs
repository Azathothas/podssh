//! `eice://`, the road of AWS's EC2 Instance Connect Endpoint (T-351), as a
//! process. Each destination, flag and duration that cannot go is refused
//! before anything connects. Then, through a stand-in proxy that
//! re-terminates TLS (`cloud_support`), `podssh proxy eice://...` carries a
//! session to a stand-in of the endpoint, which checks the presigned URL as
//! AWS's documents give the check, by a SigV4 of the test's own over
//! aws-lc-rs: a credential's JSON and a profile of a shared credentials
//! file each sign it; the duration asked goes in the URL; and a refusal
//! gives this host's clock and shows no part of the credential or the URL.

mod cloud_support;

use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cloud_support::*;
use podssh_ws::frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const TOKEN: &str = "IQoJb3JpZ2luX2VjEXAMPLE/session+token=";
const DNS: &str = "eice-0123456789example.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";
const WAIT: Duration = Duration::from_secs(30);

fn dest() -> String {
    format!("eice://{DNS}/10.0.1.5:22")
}

/// The stand-in of the endpoint: what it saw, and the secret that signs.
struct Eice {
    heads: Mutex<Vec<String>>,
    secret: &'static str,
    refuse: bool,
}

fn handler(eice: Arc<Eice>) -> Handler {
    Arc::new(move |host: String, stream: Stream| {
        let eice = eice.clone();
        Box::pin(async move {
            if host == DNS {
                endpoint(stream, eice).await;
            }
        })
    })
}

async fn endpoint(mut tls: Stream, eice: Arc<Eice>) {
    let Ok(head) = read_head(&mut tls).await else { return };
    eice.heads.lock().unwrap().push(head.clone());
    let path = head.split_whitespace().nth(1).unwrap_or_default();
    let checked = signed_right(path, eice.secret);
    if eice.refuse || checked.is_err() {
        // As an answer may quote its request.
        let body = format!("{}: {}", checked.err().unwrap_or_else(|| "denied".into()), head.lines().next().unwrap());
        let answer = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let _ = tls.write_all(answer.as_bytes()).await;
        return;
    }
    accept_upgrade(&mut tls, &head, None).await;
    let mut frames = Frames::default();
    while let Some(f) = frames.next(&mut tls).await {
        let echo = match f.opcode {
            frame::OPCODE_CLOSE => {
                let _ = send(&mut tls, frame::OPCODE_CLOSE, &f.payload[..f.payload.len().min(2)]).await;
                return;
            }
            frame::OPCODE_PING => frame::OPCODE_PONG,
            frame::OPCODE_BINARY => frame::OPCODE_BINARY,
            _ => continue,
        };
        let _ = send(&mut tls, echo, &f.payload).await;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    aws_lc_rs::hmac::sign(&key, data.as_bytes()).as_ref().to_vec()
}

/// Seconds since the Unix epoch of `YYYYMMDDTHHMMSSZ`.
fn epoch_of(text: &str) -> i64 {
    let n = |r: std::ops::Range<usize>| text[r].parse::<i64>().unwrap();
    let (y, m, d) = (n(0..4), n(4..6), n(6..8));
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    days * 86_400 + n(9..11) * 3600 + n(11..13) * 60 + n(13..15)
}

/// The endpoint's check of a presigned URL: the canonical request rebuilt
/// from the URL as it came, the key derived from `secret`, the signature
/// compared; the scope, the expiry, the one signed header, the target and
/// the time each checked.
fn signed_right(path: &str, secret: &str) -> Result<(), String> {
    let (route, query) = path.split_once('?').ok_or("no query")?;
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .map(|pair| pair.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).unwrap_or_default())
        .collect();
    let at = pairs.iter().position(|(k, _)| k == "X-Amz-Signature").ok_or("no signature")?;
    let (_, signature) = pairs.remove(at);
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()).unwrap_or_default();
    let credential = get("X-Amz-Credential").replace("%2F", "/");
    let parts: Vec<&str> = credential.split('/').collect();
    let [key, date, region, service, "aws4_request"] = parts[..] else { return Err("a bad credential".into()) };
    let when = get("X-Amz-Date");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let fresh = (epoch_of(&when) - now).abs() < 300;
    let (expires, signed, algorithm) = (get("X-Amz-Expires"), get("X-Amz-SignedHeaders"), get("X-Amz-Algorithm"));
    let (id, address, port) = (get("instanceConnectEndpointId"), get("privateIpAddress"), get("remotePort"));
    let expected: [(&str, &str); 11] = [
        (key, KEY),
        (region, "us-west-2"),
        (service, "ec2-instance-connect"),
        (&when[..8], date),
        (&expires, "60"),
        (&signed, "host"),
        (&algorithm, "AWS4-HMAC-SHA256"),
        (&id, "eice-0123456789example"),
        (&address, "10.0.1.5"),
        (&port, "22"),
        (route, "/openTunnel"),
    ];
    if let Some((got, want)) = expected.iter().find(|(got, want)| got != want) {
        return Err(format!("{got} where {want} was due"));
    }
    if !fresh {
        return Err("RequestExpired".into());
    }
    let mut sorted = pairs.clone();
    sorted.sort();
    let canonical_query: Vec<String> = sorted.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let empty = hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"").as_ref());
    let request = format!("GET\n{route}\n{}\nhost:{DNS}\n\nhost\n{empty}", canonical_query.join("&"));
    let hashed = hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, request.as_bytes()).as_ref());
    let to_sign = format!("AWS4-HMAC-SHA256\n{when}\n{date}/{region}/{service}/aws4_request\n{hashed}");
    let mut k = hmac(format!("AWS4{secret}").as_bytes(), date);
    for part in [region, service, "aws4_request"] {
        k = hmac(&k, part);
    }
    (hex(&hmac(&k, &to_sign)) == signature).then_some(()).ok_or_else(|| "SignatureDoesNotMatch".to_string())
}

fn spawn(dir: &std::path::Path, args: &[&str], proxy: &Proxy, set: &[(&str, &str)]) -> tokio::process::Child {
    let mut cmd = tokio::process::Command::from(command(dir, args, Some(proxy), set));
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    cmd.spawn().expect("podssh runs")
}

async fn finish(mut child: tokio::process::Child) -> (i32, String) {
    drop(child.stdin.take());
    let output = tokio::time::timeout(WAIT, child.wait_with_output()).await.expect("podssh ends").unwrap();
    (output.status.code().unwrap_or(-1), String::from_utf8_lossy(&output.stderr).into_owned())
}

fn shows_no_credential(err: &str) {
    for secret in [KEY, SECRET, "IQoJb3JpZ2luX2VjEXAMPLE", "X-Amz-Signature", "X-Amz-Credential"] {
        assert!(!err.contains(secret), "{secret} was shown: {err}");
    }
}

/// `podssh proxy eice://...` with the JSON of export-credentials: the
/// stand-in takes the signature, and 64 KiB come back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eice_carries_a_session_through_a_proxy_that_reterminates_tls() {
    let dir = scratch("eice-echo");
    let eice = Arc::new(Eice { heads: Mutex::default(), secret: SECRET, refuse: false });
    let proxy = Proxy::start(&dir, handler(eice.clone())).await;
    let json = format!(
        r#"{{"Version": 1, "AccessKeyId": "{KEY}", "SecretAccessKey": "{SECRET}", "SessionToken": "{TOKEN}"}}"#
    );
    let file = private_file(&dir, "credentials.json", &json).display().to_string();
    let (ca, dest) = (proxy.ca_file.display().to_string(), dest());
    let set = [("PODSSH_EICE_CREDENTIALS_FILE", file.as_str())];
    let mut child = spawn(&dir, &["proxy", "--ca-file", &ca, &dest], &proxy, &set);
    let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 249) as u8).collect();
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        stdin.write_all(&sent).await.unwrap();
        stdin
    });
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(WAIT, stdout.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    assert_eq!(back, data);
    child.stdin = Some(writer.await.unwrap());
    let (code, err) = finish(child).await;
    assert_eq!(code, 0, "{err}");
    shows_no_credential(&err);
    let heads = eice.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    let line = heads[0].lines().next().unwrap();
    assert!(line.contains("&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEXAMPLE%2Fsession%2Btoken%3D&"), "{line}");
    assert!(!line.contains("maxTunnelDuration"), "no duration asked: {line}");
    assert_eq!(header(&heads[0], "Host"), Some(DNS));
    assert!(header(&heads[0], "Sec-WebSocket-Protocol").is_none(), "awscrt offers no subprotocol");
    assert_eq!(proxy.connects.lock().unwrap().as_slice(), [format!("{DNS}:443")]);
}

/// A profile of a shared credentials file, by AWS_PROFILE, signs; a
/// duration asked goes in the URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eice_a_profile_signs_and_a_duration_goes_in_the_url() {
    let dir = scratch("eice-profile");
    let eice = Arc::new(Eice { heads: Mutex::default(), secret: "lab-secret-of-this-test", refuse: false });
    let proxy = Proxy::start(&dir, handler(eice.clone())).await;
    let ini = format!(
        "[default]\naws_access_key_id = AKIDOTHER\naws_secret_access_key = other\n\n[lab]\n\
                       aws_access_key_id = {KEY}\naws_secret_access_key = lab-secret-of-this-test\n"
    );
    let file = private_file(&dir, "credentials", &ini).display().to_string();
    let (ca, dest) = (proxy.ca_file.display().to_string(), dest());
    let set = [
        ("AWS_SHARED_CREDENTIALS_FILE", file.as_str()),
        ("AWS_PROFILE", "lab"),
        ("PODSSH_EICE_MAX_TUNNEL_DURATION", "600"),
    ];
    let mut child = spawn(&dir, &["proxy", "--ca-file", &ca, &dest], &proxy, &set);
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    stdin.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(WAIT, stdout.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    child.stdin = Some(stdin);
    let (code, err) = finish(child).await;
    assert_eq!((code, &back), (0, b"hello"), "{err}");
    let line = eice.heads.lock().unwrap()[0].lines().next().unwrap().to_string();
    assert!(line.contains("&maxTunnelDuration=600&"), "{line}");
    shows_no_credential(&err);
}

/// A refusal: 77, the permission and this host's clock named, and no part
/// of the credential or of the URL, which the answer quoted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eice_a_refusal_gives_the_clock_and_no_credential() {
    let dir = scratch("eice-refused");
    let eice = Arc::new(Eice { heads: Mutex::default(), secret: SECRET, refuse: true });
    let proxy = Proxy::start(&dir, handler(eice)).await;
    let json = format!(
        r#"{{"Version": 1, "AccessKeyId": "{KEY}", "SecretAccessKey": "{SECRET}", "SessionToken": "{TOKEN}"}}"#
    );
    let file = private_file(&dir, "credentials.json", &json).display().to_string();
    let (ca, dest) = (proxy.ca_file.display().to_string(), dest());
    let child = spawn(&dir, &["proxy", "--ca-file", &ca, &dest], &proxy, &[("PODSSH_EICE_CREDENTIALS_FILE", &file)]);
    let (code, err) = finish(child).await;
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("ec2-instance-connect:OpenTunnel") && err.contains("this host's clock reads"), "{err}");
    assert!(err.contains("eice://eice-0123456789example/10.0.1.5"), "{err}");
    shows_no_credential(&err);
}

fn offline(args: &[&str], set: &[(&str, &str)]) -> (i32, String) {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let dir = scratch(&format!("eice-offline-{}", RUNS.fetch_add(1, Ordering::SeqCst)));
    let mut cmd = command(&dir, args, None, set);
    cmd.env("https_proxy", "http://127.0.0.1:9");
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn an_eice_destination_is_checked_before_anything_connects() {
    let off = [("PODSSH_OFFLINE", "1")];
    let dest = dest();
    let v6 = format!("eice://{DNS}/[2600:1f14::1]");
    let no_address = format!("eice://{DNS}");
    let by_name = format!("eice://{DNS}/host.example");
    for (args, says) in [
        (vec!["ssh", no_address.as_str(), "true"], "ENDPOINT/ADDRESS"),
        (vec!["ssh", by_name.as_str(), "true"], "not an IP address"),
        (vec!["ssh", "eice://vpce-1.example.com/10.0.1.5", "true"], "not the DNS name of an EC2 Instance Connect"),
        (vec!["ssh", "--direct", dest.as_str(), "true"], "--direct cannot reach it"),
        (vec!["ssh", "-6", v6.as_str(), "true"], "-4 and -6 do not apply"),
        (vec!["proxy", dest.as_str(), "22"], "the port goes in the destination"),
    ] {
        let (rc, err) = offline(&args, &off);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    let (rc, err) = offline(&["ssh", "-o", "BatchMode=yes", &v6, "true"], &off);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    // A duration that cannot be one is the variable's fault, before anything.
    let long = [("PODSSH_OFFLINE", "1"), ("PODSSH_EICE_MAX_TUNNEL_DURATION", "7200")];
    for args in [&["proxy", dest.as_str()][..], &["ssh", "-o", "BatchMode=yes", dest.as_str(), "true"][..]] {
        let (rc, err) = offline(args, &long);
        assert_eq!(rc, 78, "{args:?}: {err}");
        assert!(err.contains("PODSSH_EICE_MAX_TUNNEL_DURATION"), "{args:?}: {err}");
    }
}

/// No credential named and no ~/.aws/credentials: refused before anything
/// connects, naming the variables.
#[test]
fn an_eice_credential_is_named() {
    let (rc, err) = offline(&["proxy", &dest()], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("PODSSH_EICE_CREDENTIALS_FILE") && err.contains("AWS_SHARED_CREDENTIALS_FILE"), "{err}");
}
