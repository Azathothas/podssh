//! `iap://`, the road of GCP's Identity-Aware Proxy for TCP (T-351), as a
//! process. Each destination and flag that cannot go is refused before
//! anything connects. Then, through a stand-in proxy that re-terminates TLS
//! (`cloud_support`), `podssh proxy iap://...` carries a session to a
//! stand-in of IAP that answers as gcloud's and IAP Desktop's sources say,
//! with gcloud's upgrade and the token in its header alone; it takes the
//! session up on a new link after a lost one; a key of a service account
//! gets its token from a stand-in of Google's endpoint by a JWT that the
//! key's public half takes; and a refusal names its step. No token is on
//! the process's command line or in its output.

mod cloud_support;

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cloud_support::*;
use podssh_ws::frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOKEN: &str = "ya29.TEST-token-not-a-credential";
const MINTED: &str = "ya29.stand-in-token-of-a-key";
const DEST: &str = "iap://a-project/us-central1-a/a-vm:22";
const WAIT: Duration = Duration::from_secs(30);

/// How the stand-in of IAP answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Echo,
    /// The first link goes, with no Close, once 1000 bytes came.
    CutOnce,
    /// The upgrade is refused with 403, its body quoting the header.
    Refuse,
    /// A Close of this code comes in place of the session.
    Close(u16),
}

/// The stand-in of IAP and of Google's token endpoint: what it saw.
struct Iap {
    mode: Mode,
    heads: Mutex<Vec<String>>,
    token_requests: Mutex<Vec<String>>,
    /// The public half of a service account's key, for its JWT.
    public: Option<Vec<u8>>,
    cut: AtomicBool,
    /// The client's bytes that the stand-in took, on each link.
    took: AtomicU64,
}

impl Iap {
    fn new(mode: Mode, public: Option<Vec<u8>>) -> Arc<Iap> {
        Arc::new(Iap {
            mode,
            heads: Mutex::default(),
            token_requests: Mutex::default(),
            public,
            cut: AtomicBool::new(false),
            took: AtomicU64::new(0),
        })
    }
}

fn handler(iap: Arc<Iap>) -> Handler {
    Arc::new(move |host: String, stream: Stream| {
        let iap = iap.clone();
        Box::pin(async move {
            match host.as_str() {
                "tunnel.cloudproxy.app" => tunnel(stream, iap).await,
                "oauth2.googleapis.com" => token_endpoint(stream, iap).await,
                _ => {}
            }
        })
    })
}

/// IAP's messages, as gcloud's sources lay them out: a tag, then fields.
fn array(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let mut m = tag.to_be_bytes().to_vec();
    m.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    m.extend_from_slice(bytes);
    m
}

fn number(tag: u16, n: u64) -> Vec<u8> {
    let mut m = tag.to_be_bytes().to_vec();
    m.extend_from_slice(&n.to_be_bytes());
    m
}

async fn tunnel(mut tls: Stream, iap: Arc<Iap>) {
    let Ok(head) = read_head(&mut tls).await else { return };
    iap.heads.lock().unwrap().push(head.clone());
    if iap.mode == Mode::Refuse {
        let body = format!("forbidden: {}", header(&head, "Authorization").unwrap_or_default());
        let answer = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let _ = tls.write_all(answer.as_bytes()).await;
        return;
    }
    accept_upgrade(&mut tls, &head, Some("relay.tunnel.cloudproxy.app")).await;
    let path = head.split_whitespace().nth(1).unwrap_or_default().to_string();
    if path.starts_with("/v4/reconnect?") {
        let _ = send(&mut tls, frame::OPCODE_BINARY, &number(2, iap.took.load(Ordering::SeqCst))).await;
    } else if let Mode::Close(code) = iap.mode {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(b"refused by the stand-in");
        let _ = send(&mut tls, frame::OPCODE_CLOSE, &payload).await;
        return;
    } else {
        let _ = send(&mut tls, frame::OPCODE_BINARY, &array(1, b"a-sid")).await;
    }
    let mut frames = Frames::default();
    while let Some(f) = frames.next(&mut tls).await {
        if f.opcode == frame::OPCODE_CLOSE {
            let _ = send(&mut tls, frame::OPCODE_CLOSE, &f.payload[..f.payload.len().min(2)]).await;
            return;
        }
        // The client's data comes back, with an acknowledgement; its own
        // acknowledgements are kept for no one.
        if f.opcode != frame::OPCODE_BINARY || f.payload.len() < 6 || f.payload[..2] != [0, 4] {
            continue;
        }
        let data = f.payload[6..].to_vec();
        let took = iap.took.fetch_add(data.len() as u64, Ordering::SeqCst) + data.len() as u64;
        let _ = send(&mut tls, frame::OPCODE_BINARY, &array(4, &data)).await;
        let _ = send(&mut tls, frame::OPCODE_BINARY, &number(7, took)).await;
        if iap.mode == Mode::CutOnce && took >= 1000 && !iap.cut.swap(true, Ordering::SeqCst) {
            return;
        }
    }
}

/// Google's token endpoint: a JWT bearer grant whose signature the key's
/// public half takes, and whose claims are those of Google's documents,
/// gets a token.
async fn token_endpoint(mut tls: Stream, iap: Arc<Iap>) {
    let Ok(head) = read_head(&mut tls).await else { return };
    let len: usize = header(&head, "Content-Length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    if tls.read_exact(&mut body).await.is_err() {
        return;
    }
    let body = String::from_utf8(body).unwrap();
    iap.token_requests.lock().unwrap().push(format!("{head}{body}"));
    let grant = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
    let ok = body.strip_prefix(grant).is_some_and(|jwt| jwt_holds(jwt, iap.public.as_deref().unwrap_or_default()));
    let (status, answer) = if ok {
        (200, format!(r#"{{"access_token": "{MINTED}", "expires_in": 3599, "token_type": "Bearer"}}"#))
    } else {
        (400, r#"{"error": "invalid_grant", "error_description": "Invalid JWT Signature."}"#.to_string())
    };
    let reply = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{answer}",
        answer.len()
    );
    let _ = tls.write_all(reply.as_bytes()).await;
}

fn jwt_holds(jwt: &str, public: &[u8]) -> bool {
    use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = jwt.split('.').collect();
    let [head, body, sig] = parts[..] else { return false };
    let (Ok(signature), Ok(claims)) = (b64.decode(sig), b64.decode(body)) else { return false };
    let signed = format!("{head}.{body}");
    if UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public).verify(signed.as_bytes(), &signature).is_err() {
        return false;
    }
    let claims: serde_json::Value = serde_json::from_slice(&claims).unwrap_or_default();
    let life = claims["exp"].as_u64().unwrap_or(0).saturating_sub(claims["iat"].as_u64().unwrap_or(u64::MAX));
    claims["iss"] == "tunnel@a-project.iam.gserviceaccount.com"
        && claims["aud"] == "https://oauth2.googleapis.com/token"
        && claims["scope"] == "https://www.googleapis.com/auth/cloud-platform"
        && life == 3600
}

/// `podssh ARGS` as a process with each pipe, the stand-in its proxy.
fn spawn(dir: &std::path::Path, args: &[&str], proxy: &Proxy, set: &[(&str, &str)]) -> tokio::process::Child {
    let mut cmd = tokio::process::Command::from(command(dir, args, Some(proxy), set));
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    cmd.spawn().expect("podssh runs")
}

/// Close stdin, then the exit code and stderr, within the wait.
async fn finish(mut child: tokio::process::Child) -> (i32, String) {
    drop(child.stdin.take());
    let output = tokio::time::timeout(WAIT, child.wait_with_output()).await.expect("podssh ends").unwrap();
    (output.status.code().unwrap_or(-1), String::from_utf8_lossy(&output.stderr).into_owned())
}

/// The heads of gcloud's upgrade, line by line, but for the key and the
/// `User-Agent` of each run (iap's own tests hold the bytes of gcloud's).
fn gcloud_s(head: &str, token: &str) {
    let lines: Vec<&str> = head.trim_end().split("\r\n").collect();
    let query = "project=a-project&port=22&newWebsocket=True&zone=us-central1-a&instance=a-vm&interface=nic0";
    assert_eq!(lines[0], format!("GET /v4/connect?{query} HTTP/1.1"));
    let upgrade =
        ["Upgrade: websocket", "Connection: Upgrade", "Host: tunnel.cloudproxy.app", "Origin: bot:iap-tunneler"];
    assert_eq!(&lines[1..5], upgrade);
    assert!(lines[5].starts_with("Sec-WebSocket-Key: "), "{head}");
    assert_eq!(&lines[6..8], ["Sec-WebSocket-Version: 13", "Sec-WebSocket-Protocol: relay.tunnel.cloudproxy.app"]);
    assert!(lines[8].starts_with("User-Agent: podssh/"), "{head}");
    assert_eq!(lines[9], format!("Authorization: Bearer {token}"));
    assert_eq!(lines.len(), 10, "{head}");
}

/// 64 KiB both ways through the proxy that re-terminates TLS, to the
/// stand-in of IAP: the upgrade is gcloud's, the token is in its header
/// alone, and neither the command line nor the output holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iap_carries_a_session_through_a_proxy_that_reterminates_tls() {
    let dir = scratch("iap-echo");
    let iap = Iap::new(Mode::Echo, None);
    let proxy = Proxy::start(&dir, handler(iap.clone())).await;
    let file = private_file(&dir, "token", &format!("{TOKEN}\n"));
    let (file, ca) = (file.display().to_string(), proxy.ca_file.display().to_string());
    let mut child = spawn(&dir, &["proxy", "--ca-file", &ca, DEST], &proxy, &[("PODSSH_IAP_TOKEN_FILE", &file)]);
    let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        stdin.write_all(&sent).await.unwrap();
        stdin
    });
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(WAIT, stdout.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    assert_eq!(back, data);
    #[cfg(target_os = "linux")]
    {
        let argv = std::fs::read(format!("/proc/{}/cmdline", child.id().unwrap())).unwrap();
        assert!(!String::from_utf8_lossy(&argv).contains(TOKEN), "the token is on the command line");
    }
    child.stdin = Some(writer.await.unwrap());
    let (code, err) = finish(child).await;
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains(TOKEN), "the token was shown: {err}");
    let heads = iap.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    gcloud_s(&heads[0], TOKEN);
    assert_eq!(proxy.connects.lock().unwrap().as_slice(), ["tunnel.cloudproxy.app:443"]);
}

/// The link goes with no Close after 1000 bytes: the next is a reconnect
/// with the session's id and the 1000 bytes that came back, with the token
/// again in its header; the stream goes on, each byte once; and a line on
/// stderr tells of each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iap_takes_the_session_up_after_a_lost_link() {
    let dir = scratch("iap-cut");
    let iap = Iap::new(Mode::CutOnce, None);
    let proxy = Proxy::start(&dir, handler(iap.clone())).await;
    let file = private_file(&dir, "token", TOKEN).display().to_string();
    let ca = proxy.ca_file.display().to_string();
    let mut child = spawn(&dir, &["proxy", "--ca-file", &ca, DEST], &proxy, &[("PODSSH_IAP_TOKEN_FILE", &file)]);
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let mut back = vec![0u8; 1000];
    for byte in [b'A', b'B'] {
        stdin.write_all(&[byte; 1000]).await.unwrap();
        tokio::time::timeout(WAIT, stdout.read_exact(&mut back)).await.expect("the echo in time").unwrap();
        assert_eq!(back, vec![byte; 1000]);
    }
    child.stdin = Some(stdin);
    let (code, err) = finish(child).await;
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("the link to IAP was lost") && err.contains("took the session up"), "{err}");
    let heads = iap.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 2, "{heads:?}");
    let reconnect = heads[1].split_whitespace().nth(1).unwrap();
    assert_eq!(reconnect, "/v4/reconnect?sid=a-sid&ack=1000&newWebsocket=True&zone=us-central1-a");
    assert_eq!(header(&heads[1], "Authorization"), Some(format!("Bearer {TOKEN}").as_str()));
    assert!(!err.contains(TOKEN), "{err}");
}

/// A key of a service account: podssh asks the stand-in of Google's token
/// endpoint, through the same proxy, with a JWT that the key's public half
/// takes, and the token that it gets goes in the upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iap_a_service_account_s_key_gets_its_token_from_google() {
    use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine as _;
    let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der: Pkcs8V1Der<'static> = pair.as_der().unwrap();
    let text = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", lines.join("\n"));
    let key = serde_json::json!({
        "type": "service_account", "project_id": "a-project", "private_key_id": "k1", "private_key": pem,
        "client_email": "tunnel@a-project.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
    });
    let dir = scratch("iap-key");
    let iap = Iap::new(Mode::Echo, Some(pair.public_key().as_ref().to_vec()));
    let proxy = Proxy::start(&dir, handler(iap.clone())).await;
    let file = private_file(&dir, "key.json", &key.to_string()).display().to_string();
    let ca = proxy.ca_file.display().to_string();
    let mut child =
        spawn(&dir, &["proxy", "--ca-file", &ca, DEST], &proxy, &[("GOOGLE_APPLICATION_CREDENTIALS", &file)]);
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    stdin.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(WAIT, stdout.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    child.stdin = Some(stdin);
    let (code, err) = finish(child).await;
    assert_eq!((code, &back), (0, b"hello"), "{err}");
    let requests = iap.token_requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "one token for the session");
    assert!(requests[0].starts_with("POST /token HTTP/1.1\r\n"), "{}", requests[0]);
    assert_eq!(header(&requests[0], "Content-Type"), Some("application/x-www-form-urlencoded"));
    gcloud_s(&iap.heads.lock().unwrap()[0], MINTED);
    assert!(!err.contains(MINTED) && !err.contains("PRIVATE KEY"), "{err}");
    let connects = proxy.connects.lock().unwrap().clone();
    assert_eq!(connects, ["oauth2.googleapis.com:443", "tunnel.cloudproxy.app:443"]);
}

/// Each refusal names its step, with its code: the upgrade (77, its body
/// showing no token), the account (77), the VM's port (69).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iap_a_refusal_names_its_step() {
    for (mode, want, says) in [
        (Mode::Refuse, 77, "roles/iap.tunnelResourceAccessor"),
        (Mode::Close(4033), 77, "IAP refused the account"),
        (Mode::Close(4003), 69, "35.235.240.0/20"),
        (Mode::Close(4047), 69, "IAP found no VM a-vm in zone us-central1-a of project a-project"),
    ] {
        let dir = scratch("iap-refused");
        let proxy = Proxy::start(&dir, handler(Iap::new(mode, None))).await;
        let file = private_file(&dir, "token", TOKEN).display().to_string();
        let ca = proxy.ca_file.display().to_string();
        let child = spawn(&dir, &["proxy", "--ca-file", &ca, DEST], &proxy, &[("PODSSH_IAP_TOKEN_FILE", &file)]);
        let (code, err) = finish(child).await;
        assert_eq!(code, want, "{err}");
        assert!(err.contains(says) && err.contains("iap://a-project/us-central1-a/a-vm"), "{err}");
        assert!(!err.contains(TOKEN), "the token was shown: {err}");
    }
}

/// `podssh ARGS` offline, with no proxy that could carry anything: its code
/// and stderr.
fn offline(args: &[&str], set: &[(&str, &str)]) -> (i32, String) {
    static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = scratch(&format!("iap-offline-{}", RUNS.fetch_add(1, Ordering::SeqCst)));
    let mut cmd = command(&dir, args, None, set);
    cmd.env("https_proxy", "http://127.0.0.1:9");
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn an_iap_destination_is_checked_before_anything_connects() {
    let off = [("PODSSH_OFFLINE", "1")];
    for (args, says) in [
        (&["ssh", "iap://a-project/us-central1-a", "true"][..], "PROJECT/ZONE/INSTANCE"),
        (&["ssh", "iap://a-project/us-central1-a/A-VM", "true"][..], "not the name of a VM"),
        (&["ssh", "--direct", DEST, "true"][..], "--direct cannot reach it"),
        (&["ssh", "-4", DEST, "true"][..], "-4 and -6 do not apply"),
        (&["ssh", "-o", "HostName=other.example", DEST, "true"][..], "HostName cannot apply"),
        (&["ssh", "-J", "jump.example", DEST, "true"][..], "make it the first hop of -J"),
        (&["ssh", "-J", "jump.example,iap://a-project/us-central1-a/a-vm", "d.example", "true"][..], "first hop"),
        (&["proxy", DEST, "22"][..], "the port goes in the destination"),
        (&["proxy", "iap://me@a-project/us-central1-a/a-vm"][..], "takes no user here"),
        (&["proxy", "--relay-host", "r.example", DEST][..], "the relay's flags do not apply"),
    ] {
        let (rc, err) = offline(args, &off);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
    let (rc, err) = offline(&["ssh", "-o", "BatchMode=yes", DEST, "true"], &off);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE"), "{err}");
    let (rc, err) = offline(&["proxy", DEST], &off);
    assert_eq!(rc, 69, "{err}");
    // As the first hop of -J, the tunnel is the run's road, not the relay.
    let hop = "iap://me@a-project/us-central1-a/a-vm";
    let (rc, err) = offline(&["ssh", "-v", "-o", "BatchMode=yes", "-J", hop, "dest.example", "true"], &off);
    assert_eq!(rc, 255, "{err}");
    assert!(err.contains("PODSSH_OFFLINE") && !err.contains("through the relay"), "{err}");
}

/// No token named, or one that others can read: refused before anything
/// connects (78 for proxy; ssh exits 255), naming the variables and never
/// the value.
#[test]
fn an_iap_token_is_named_and_private() {
    let (rc, err) = offline(&["proxy", DEST], &[]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("PODSSH_IAP_TOKEN_FILE") && err.contains("GOOGLE_APPLICATION_CREDENTIALS"), "{err}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("iap-open-token");
        let file = private_file(&dir, "token", TOKEN);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = file.display().to_string();
        for args in [&["proxy", DEST][..], &["ssh", "-o", "BatchMode=yes", DEST, "true"][..]] {
            let (rc, err) = offline(args, &[("PODSSH_IAP_TOKEN_FILE", &file)]);
            assert!(rc == 78 || rc == 255, "{args:?}: {rc}: {err}");
            assert!(err.contains("chmod 600") && !err.contains(TOKEN), "{args:?}: {err}");
        }
    }
}
