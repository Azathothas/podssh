//! The token of IAP (T-351): a token's file read again for each link, by
//! its path alone and only when private; the JWT of a service account's
//! key, RS256 with the claims of Google's documents, whose signature the
//! key's public half takes; a key of another kind, or of another token
//! endpoint, refused; and the endpoint's answer read, its refusal in
//! Google's words and no secret.

use super::*;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

const TOKEN: &str = "ya29.a-token-of-this-test";

fn private_file(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("podssh-iap-{name}-{}", std::process::id()));
    std::fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn vars(pairs: Vec<(&'static str, String)>) -> impl Fn(&str) -> Option<String> {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
}

/// A key of a service account, as gcloud writes one, with a key made here.
fn service_account_json(pair: &KeyPair, token_uri: &str) -> String {
    let der: Pkcs8V1Der<'static> = pair.as_der().unwrap();
    let text = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", lines.join("\n"));
    serde_json::json!({
        "type": "service_account", "project_id": "a-project", "private_key_id": "a-key-id",
        "private_key": pem, "client_email": "tunnel@a-project.iam.gserviceaccount.com",
        "client_id": "1234", "token_uri": token_uri,
    })
    .to_string()
}

#[tokio::test]
async fn google_a_token_file_is_read_again_for_each_link() {
    let file = private_file("token", &format!("{TOKEN}\n"));
    let read = vars(vec![(TOKEN_FILE_ENV, file.display().to_string())]);
    let tokens = Tokens::from_vars(&read, Trust::Default).unwrap();
    assert!(matches!(tokens.source, Source::File(_)));
    assert_eq!(tokens.token().await.unwrap().as_str(), TOKEN);
    std::fs::write(&file, "ya29.a-later-token\n").unwrap();
    assert_eq!(tokens.token().await.unwrap().as_str(), "ya29.a-later-token");
    // Google's own variable names a file too, and the first one wins.
    let both = vars(vec![(GOOGLE_ENV, "no-such-file".into()), (TOKEN_FILE_ENV, file.display().to_string())]);
    assert!(Tokens::from_vars(&both, Trust::Default).is_ok());
    let _ = std::fs::remove_file(&file);
}

#[test]
fn google_no_file_or_a_bad_one_is_refused_by_its_name() {
    let Err(TokenFault::Config(why)) = Tokens::from_vars(&vars(vec![]), Trust::Default) else { panic!("refused") };
    assert!(why.contains(TOKEN_FILE_ENV) && why.contains(GOOGLE_ENV), "{why}");
    let spaced = private_file("spaced", "two words of a token\n");
    let read = vars(vec![(TOKEN_FILE_ENV, spaced.display().to_string())]);
    let Err(TokenFault::Config(why)) = Tokens::from_vars(&read, Trust::Default) else { panic!("refused") };
    assert!(why.contains(TOKEN_FILE_ENV) && !why.contains("two words"), "{why}");
    let _ = std::fs::remove_file(&spaced);
}

/// A token's file that others can read is refused, as a key is.
#[cfg(unix)]
#[test]
fn google_a_token_file_that_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let file = private_file("open", TOKEN);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let read = vars(vec![(TOKEN_FILE_ENV, file.display().to_string())]);
    let Err(TokenFault::Config(why)) = Tokens::from_vars(&read, Trust::Default) else { panic!("refused") };
    assert!(why.contains("chmod 600") && !why.contains(TOKEN), "{why}");
    let _ = std::fs::remove_file(&file);
}

/// The JWT's header and claims are those of Google's documents, and the
/// public half of the key takes its RS256 signature.
#[test]
fn google_a_service_account_s_jwt_is_signed_rs256() {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let mut json: Value = serde_json::from_str(&service_account_json(&pair, TOKEN_URI)).unwrap();
    let Source::ServiceAccount { email, key_id, key } = service_account(&mut json).unwrap() else { panic!("a key") };
    assert_eq!((email.as_str(), key_id.as_deref()), ("tunnel@a-project.iam.gserviceaccount.com", Some("a-key-id")));
    let jwt = assertion(&email, key_id.as_deref(), &key, 1_793_448_000).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let part = |i: usize| -> Value { serde_json::from_slice(&b64.decode(parts[i]).unwrap()).unwrap() };
    assert_eq!(part(0), serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "a-key-id"}));
    assert_eq!(
        part(1),
        serde_json::json!({
            "iss": "tunnel@a-project.iam.gserviceaccount.com", "scope": SCOPE, "aud": TOKEN_URI,
            "iat": 1_793_448_000u64, "exp": 1_793_451_600u64,
        })
    );
    let signed = format!("{}.{}", parts[0], parts[1]);
    let signature = b64.decode(parts[2]).unwrap();
    let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public_key().as_ref());
    public.verify(signed.as_bytes(), &signature).expect("the key's public half takes the signature");
    assert!(public.verify(b"another message", &signature).is_err());
}

#[test]
fn google_a_key_of_another_kind_or_endpoint_is_refused() {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let elsewhere = service_account_json(&pair, "https://tokens.example/token");
    let why = parse(&elsewhere, PathBuf::from("k.json")).err().unwrap();
    assert!(why.contains("token_uri") && why.contains(TOKEN_URI), "{why}");
    let why = parse(r#"{"type": "external_account"}"#, PathBuf::from("k.json")).err().unwrap();
    assert!(why.contains("external_account"), "{why}");
    let why = parse(r#"{"client_email": "x"}"#, PathBuf::from("k.json")).err().unwrap();
    assert!(why.contains("no type"), "{why}");
    let bad_pem = r#"{"type": "service_account", "client_email": "x@y", "private_key": "not a key"}"#;
    assert!(parse(bad_pem, PathBuf::from("k.json")).err().unwrap().contains("PEM"));
    let user = r#"{"type": "authorized_user", "client_id": "id", "client_secret": "s3", "refresh_token": "1//r"}"#;
    assert!(matches!(parse(user, PathBuf::from("adc.json")), Ok(Source::User { .. })));
}

fn answer(status: u16, body: &str) -> podssh_ws::http::Response {
    podssh_ws::http::Response { status, reason: String::new(), headers: Vec::new(), body: body.as_bytes().to_vec() }
}

#[test]
fn google_the_answer_gives_the_token_and_its_life() {
    let ok = answer(200, &format!(r#"{{"access_token": "{TOKEN}", "expires_in": 3599, "token_type": "Bearer"}}"#));
    let (token, life) = read_answer(ok, true).unwrap();
    assert_eq!((token.as_str(), life), (TOKEN, Duration::from_secs(3599)));
    let refused = answer(400, r#"{"error": "invalid_grant", "error_description": "Invalid JWT Signature."}"#);
    let Err(TokenFault::Refused(why)) = read_answer(refused, true) else { panic!("refused") };
    assert!(why.contains("HTTP 400") && why.contains("invalid_grant Invalid JWT Signature."), "{why}");
    assert!(why.contains("this host's clock"), "a JWT is checked against Google's clock: {why}");
    let empty = answer(200, r#"{"token_type": "Bearer"}"#);
    assert!(matches!(read_answer(empty, false), Err(TokenFault::Unreachable(_))));
    let down = answer(503, "<html>busy</html>");
    let Err(TokenFault::Unreachable(why)) = read_answer(down, false) else { panic!("unreachable") };
    assert!(why.contains("HTTP 503") && !why.contains("clock"), "{why}");
    assert_eq!(form("1//0g-r+t=").as_str(), "1%2F%2F0g-r%2Bt%3D");
}
