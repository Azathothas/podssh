//! The credential of AWS that signs EICE's URL (T-351), from a file,
//! private as a pair file is: the one of `PODSSH_EICE_CREDENTIALS_FILE`,
//! else of AWS's own `AWS_SHARED_CREDENTIALS_FILE`, else
//! `~/.aws/credentials` when it is there, as AWS's tools read it. The file
//! is either AWS's shared credentials file, an INI file whose profile is
//! `AWS_PROFILE`'s, else `default`, or the JSON that `aws configure
//! export-credentials --format process` writes, for a temporary key.

use std::path::{Path, PathBuf};

use podssh_ws::eice::Credentials;
use serde_json::Value;
use zeroize::Zeroizing;

/// The file of the credential, which the user names.
pub const CREDENTIALS_FILE_ENV: &str = "PODSSH_EICE_CREDENTIALS_FILE";
/// AWS's own variables: the shared credentials file, and its profile.
pub const SHARED_ENV: &str = "AWS_SHARED_CREDENTIALS_FILE";
pub const PROFILE_ENV: &str = "AWS_PROFILE";
/// The longest life asked of a tunnel, in seconds.
pub const DURATION_ENV: &str = "PODSSH_EICE_MAX_TUNNEL_DURATION";

/// The credential that the environment names.
pub fn credentials() -> Result<Credentials, String> {
    let home = std::env::var_os("HOME")
        .or_else(|| if cfg!(windows) { std::env::var_os("USERPROFILE") } else { None })
        .map(PathBuf::from);
    credentials_from(&|name| std::env::var(name).ok(), home.as_deref())
}

/// The credential that `read` gives the variables of, with `home` for AWS's
/// own file.
pub fn credentials_from(read: &dyn Fn(&str) -> Option<String>, home: Option<&Path>) -> Result<Credentials, String> {
    let named = [CREDENTIALS_FILE_ENV, SHARED_ENV]
        .into_iter()
        .find_map(|var| read(var).map(|p| (var, p.trim().to_string())).filter(|(_, p)| !p.is_empty()));
    let (what, path) = match named {
        Some((var, path)) => (var.to_string(), PathBuf::from(path)),
        None => match home.map(|h| h.join(".aws").join("credentials")).filter(|p| p.is_file()) {
            Some(path) => ("~/.aws/credentials".to_string(), path),
            None => {
                return Err(format!(
                    "EICE needs a credential of AWS: name its file in {CREDENTIALS_FILE_ENV} (the JSON of aws \
                     configure export-credentials --format process, or a shared credentials file), or in \
                     {SHARED_ENV}; ~/.aws/credentials is read too"
                ))
            }
        },
    };
    let text = Zeroizing::new(podssh_relay::cache::read_private(&path).map_err(|why| format!("{what}: {why}"))?);
    let profile = read(PROFILE_ENV).map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
    let profile = profile.as_deref().unwrap_or("default");
    let found = if text.trim_start().starts_with('{') { from_json(&text) } else { from_ini(&text, profile) };
    let credentials = found.map_err(|why| format!("{what}: {}: {why}", path.display()))?;
    credentials.check().map_err(|why| format!("{what}: {}: {why}", path.display()))?;
    Ok(credentials)
}

/// The JSON of `aws configure export-credentials --format process`, which
/// a `credential_process` writes too.
fn from_json(text: &str) -> Result<Credentials, String> {
    // serde_json's message gives a line and a column, never the text.
    let mut json: Value = serde_json::from_str(text).map_err(|e| format!("it is not JSON: {e}"))?;
    let mut take = |name: &str| match json.get_mut(name).map(Value::take) {
        Some(Value::String(value)) if !value.is_empty() => Some(Zeroizing::new(value)),
        _ => None,
    };
    let access_key_id = take("AccessKeyId").ok_or("its JSON has no AccessKeyId")?;
    let secret_access_key = take("SecretAccessKey").ok_or("its JSON has no SecretAccessKey")?;
    Ok(Credentials { access_key_id, secret_access_key, session_token: take("SessionToken") })
}

/// The profile `profile` of a shared credentials file: `[NAME]`, then
/// `key = value` lines; `#` and `;` begin a comment line.
fn from_ini(text: &str, profile: &str) -> Result<Credentials, String> {
    let (mut access_key_id, mut secret_access_key, mut session_token) = (None, None, None);
    let mut inside = false;
    let mut seen = false;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.trim();
            inside = name == profile || name.strip_prefix("profile ").map(str::trim) == Some(profile);
            seen |= inside;
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| inside) else { continue };
        let value = Some(Zeroizing::new(value.trim().to_string()));
        match key.trim().to_ascii_lowercase().as_str() {
            "aws_access_key_id" => access_key_id = value,
            "aws_secret_access_key" => secret_access_key = value,
            "aws_session_token" => session_token = value,
            _ => {}
        }
    }
    if !seen {
        return Err(format!("it has no profile [{profile}]"));
    }
    let lacks = |name: &str| format!("its profile [{profile}] has no {name}");
    let access_key_id = access_key_id.ok_or_else(|| lacks("aws_access_key_id"))?;
    let secret_access_key = secret_access_key.ok_or_else(|| lacks("aws_secret_access_key"))?;
    Ok(Credentials { access_key_id, secret_access_key, session_token })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn private_file(name: &str, body: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("podssh-eice-{name}-{}", std::process::id()));
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn with(pairs: Vec<(&'static str, String)>) -> impl Fn(&str) -> Option<String> {
        move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn aws_the_json_of_export_credentials_is_read() {
        let json = format!(
            r#"{{"Version": 1, "AccessKeyId": "{KEY}", "SecretAccessKey": "{SECRET}", "SessionToken": "tok/en+=",
                "Expiration": "2026-10-31T13:00:00+00:00"}}"#
        );
        let file = private_file("json", &json);
        let got = credentials_from(&with(vec![(CREDENTIALS_FILE_ENV, file.display().to_string())]), None).unwrap();
        assert_eq!((got.access_key_id.as_str(), got.secret_access_key.as_str()), (KEY, SECRET));
        assert_eq!(got.session_token.as_deref().map(String::as_str), Some("tok/en+="));
        let _ = std::fs::remove_file(&file);
    }

    /// A shared credentials file: the profile of AWS_PROFILE, else default,
    /// with `[profile NAME]` read as `[NAME]`.
    #[test]
    fn aws_a_shared_credentials_file_gives_its_profile() {
        let ini = format!(
            "# a comment\n[default]\naws_access_key_id = {KEY}\naws_secret_access_key = {SECRET}\n\n\
             [profile lab]\nAWS_ACCESS_KEY_ID=AKIDLAB\naws_secret_access_key=lab-secret\naws_session_token = tok\n"
        );
        let file = private_file("ini", &ini);
        let path = file.display().to_string();
        let default = credentials_from(&with(vec![(SHARED_ENV, path.clone())]), None).unwrap();
        assert_eq!((default.access_key_id.as_str(), default.session_token.is_none()), (KEY, true));
        let lab = credentials_from(&with(vec![(SHARED_ENV, path.clone()), (PROFILE_ENV, "lab".into())]), None).unwrap();
        assert_eq!(lab.access_key_id.as_str(), "AKIDLAB");
        assert_eq!(lab.session_token.as_deref().map(String::as_str), Some("tok"));
        let none = credentials_from(&with(vec![(SHARED_ENV, path), (PROFILE_ENV, "other".into())]), None);
        assert!(none.unwrap_err().contains("no profile [other]"));
        let _ = std::fs::remove_file(&file);
    }

    /// No file named and no ~/.aws/credentials: the refusal names each
    /// variable; one there is read; no value is ever quoted.
    #[test]
    fn aws_the_file_is_named_or_found_and_no_value_shown() {
        let home = std::env::temp_dir().join(format!("podssh-eice-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        let why = credentials_from(&with(vec![]), Some(&home)).unwrap_err();
        assert!(why.contains(CREDENTIALS_FILE_ENV) && why.contains(SHARED_ENV), "{why}");
        let file = home.join(".aws").join("credentials");
        let body = format!("[default]\naws_access_key_id={KEY}\naws_secret_access_key=has a space\n");
        std::fs::write(&file, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let why = credentials_from(&with(vec![]), Some(&home)).unwrap_err();
        assert!(why.contains("secret access key") && !why.contains("has a space"), "{why}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
