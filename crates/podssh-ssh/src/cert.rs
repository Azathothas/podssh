//! OpenSSH certificates (PROTOCOL.certkeys) for `podssh keygen -s` and `-L`
//! (T-021): a user or a host key signed by a CA, with the validity, the
//! options and the lines of the `ssh-keygen` of OpenSSH for Windows 10.0p2
//! (measured on 2026-10-11). An RSA CA signs through aws-lc-rs, never the
//! `rsa` crate (T-257); a CA in an agent signs through the agent.

use std::collections::BTreeMap;

use russh::keys::ssh_key::certificate::{Builder, CertType, Certificate};
use russh::keys::ssh_key::{Algorithm, HashAlg, Signature};
use russh::keys::{PrivateKey, PublicKey};

use crate::options::Agent;
use crate::rsa_key::Detached;

/// The end of a certificate that is valid forever.
pub const FOREVER: u64 = u64::MAX;

/// The flags of a user certificate (`-O`): its default extensions, and the
/// flags of `-O` that come and go.
const PERMITS: [&str; 5] =
    ["permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc"];

/// What a certificate says, as `-s` takes it.
#[derive(Debug, Clone)]
pub struct Request {
    pub key_id: String,
    /// Empty: valid for each principal, as OpenSSH writes a certificate
    /// with no `-n`.
    pub principals: Vec<String>,
    pub host: bool,
    pub serial: u64,
    pub valid_after: u64,
    pub valid_before: u64,
    /// The flags of `-O`: the `permit-` extensions, `no-touch-required` and
    /// `verify-required`.
    pub flags: Vec<&'static str>,
    pub force_command: Option<String>,
    pub source_address: Option<String>,
    /// `-O critical:NAME[=VALUE]` and `-O extension:NAME[=VALUE]`.
    pub critical: BTreeMap<String, String>,
    pub extensions: BTreeMap<String, String>,
}

impl Request {
    /// OpenSSH's defaults: valid forever, serial 0, and the five `permit-`
    /// extensions (a host certificate carries none).
    pub fn new(key_id: &str, host: bool) -> Request {
        Request {
            key_id: key_id.to_string(),
            principals: Vec::new(),
            host,
            serial: 0,
            valid_after: 0,
            valid_before: FOREVER,
            flags: PERMITS.to_vec(),
            force_command: None,
            source_address: None,
            critical: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// `-O OPTION`, as ssh-keygen takes it: `clear` drops the flags; the
    /// names compare in any case.
    pub fn option(&mut self, option: &str) -> Result<(), String> {
        let lower = option.to_ascii_lowercase();
        // A `permit-` extension by the name that `-O` gives it, in any case.
        let permit = |name: &str| PERMITS.iter().find(|p| p.eq_ignore_ascii_case(name)).copied();
        let denied = lower.strip_prefix("no-").and_then(|rest| permit(&format!("permit-{rest}")));
        if lower == "clear" {
            self.flags.clear();
        } else if let Some(name) = permit(&lower) {
            self.set(name);
        } else if let Some(name) = denied {
            self.unset(name);
        } else if lower == "no-touch-required" {
            self.set("no-touch-required");
        } else if lower == "touch-required" {
            self.unset("no-touch-required");
        } else if lower == "verify-required" {
            self.set("verify-required");
        } else if lower == "no-verify-required" {
            self.unset("verify-required");
        } else if lower.starts_with("force-command=") {
            let value = &option["force-command=".len()..];
            if value.is_empty() {
                return Err("Empty force-command option".into());
            }
            if self.force_command.is_some() {
                return Err("force-command already specified".into());
            }
            self.force_command = Some(value.to_string());
        } else if lower.starts_with("source-address=") {
            let value = &option["source-address=".len()..];
            if value.is_empty() {
                return Err("Empty source-address option".into());
            }
            if self.source_address.is_some() {
                return Err("source-address already specified".into());
            }
            if !address_list(value) {
                return Err("Invalid source-address list".into());
            }
            self.source_address = Some(value.to_string());
        } else if lower.starts_with("extension:") || lower.starts_with("critical:") {
            let (kind, rest) = option.split_once(':').unwrap_or_default();
            let (name, value) = rest.split_once('=').unwrap_or((rest, ""));
            let map = if kind.eq_ignore_ascii_case("critical") { &mut self.critical } else { &mut self.extensions };
            map.insert(name.to_string(), value.to_string());
        } else {
            return Err(unsupported(option));
        }
        Ok(())
    }

    fn set(&mut self, flag: &'static str) {
        if !self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    fn unset(&mut self, flag: &str) {
        self.flags.retain(|f| *f != flag);
    }

    /// The critical options and the extensions that the certificate holds:
    /// none for a host certificate, as OpenSSH writes them.
    fn options(&self) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        if self.host {
            return (BTreeMap::new(), BTreeMap::new());
        }
        let mut critical = self.critical.clone();
        let mut extensions = self.extensions.clone();
        if let Some(command) = &self.force_command {
            critical.insert("force-command".into(), command.clone());
        }
        if let Some(addresses) = &self.source_address {
            critical.insert("source-address".into(), addresses.clone());
        }
        for flag in &self.flags {
            if *flag == "verify-required" {
                critical.insert((*flag).into(), String::new());
            } else {
                extensions.insert((*flag).into(), String::new());
            }
        }
        (critical, extensions)
    }

    fn builder(&self, public: &PublicKey, nonce: &[u8]) -> Result<Builder, String> {
        let failed = |e: russh::keys::ssh_key::Error| e.to_string();
        let mut builder = Builder::new(nonce.to_vec(), public.key_data().clone(), self.valid_after, self.valid_before)
            .map_err(failed)?;
        builder.serial(self.serial).map_err(failed)?;
        builder.key_id(self.key_id.as_str()).map_err(failed)?;
        builder.cert_type(if self.host { CertType::Host } else { CertType::User }).map_err(failed)?;
        if self.principals.is_empty() {
            builder.all_principals_valid().map_err(failed)?;
        }
        for principal in &self.principals {
            builder.valid_principal(principal.as_str()).map_err(failed)?;
        }
        let (critical, extensions) = self.options();
        for (name, value) in critical {
            builder.critical_option(name, value).map_err(failed)?;
        }
        for (name, value) in extensions {
            builder.extension(name, value).map_err(failed)?;
        }
        builder.comment(public.comment().as_str_lossy()).map_err(failed)?;
        Ok(builder)
    }
}

fn unsupported(option: &str) -> String {
    format!("Unsupported certificate option \"{option}\"")
}

/// Whether `list` is a list of addresses and CIDR blocks, as OpenSSH's
/// `addr_match_cidr_list` takes one.
fn address_list(list: &str) -> bool {
    list.split(',').all(|entry| {
        let (address, bits) = match entry.split_once('/') {
            Some((address, bits)) => (address, Some(bits)),
            None => (entry, None),
        };
        let Ok(ip) = address.parse::<std::net::IpAddr>() else { return false };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        bits.is_none_or(|b| b.parse::<u32>().is_ok_and(|b| b <= max))
    })
}

/// A random nonce of 32 bytes, as OpenSSH's.
fn nonce() -> [u8; 32] {
    rand::random()
}

/// `public` certified by the CA `ca`: an RSA CA signs with `rsa_hash`
/// (SHA-512 unless `-t rsa-sha2-256`) through aws-lc-rs; each other CA
/// through ssh-key.
pub fn certify(
    ca: &PrivateKey,
    public: &PublicKey,
    request: &Request,
    rsa_hash: HashAlg,
) -> Result<Certificate, String> {
    let builder = request.builder(public, &nonce())?;
    if !ca.algorithm().is_rsa() {
        return builder.sign(ca).map_err(|e| format!("could not sign the certificate: {e}"));
    }
    let signer = crate::rsa_key::RsaSigner::of(ca)?;
    let detached = Detached::new(ca.public_key().key_data().clone(), move |data| {
        let bytes = match rsa_hash {
            HashAlg::Sha256 => signer.sign_sha256(data),
            _ => signer.sign_sha512(data),
        }
        .map_err(|e| e.to_string())?;
        Signature::new(Algorithm::Rsa { hash: Some(rsa_hash) }, bytes).map_err(|e| e.to_string())
    });
    builder.sign(&detached).map_err(|e| format!("could not sign the certificate: {e}"))
}

/// `public` certified by the CA key `ca` that the agent of `choice` holds
/// (`-U`): the certificate is built once to learn what is signed, the agent
/// signs that, and the same certificate is built again with its signature.
pub async fn certify_with_agent(
    choice: &Agent,
    ca: &PublicKey,
    public: &PublicKey,
    request: &Request,
    rsa_hash: HashAlg,
) -> Result<Certificate, String> {
    let nonce = nonce();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
    let capture = {
        let seen = seen.clone();
        Detached::new(ca.key_data().clone(), move |data| {
            *seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(data.to_vec());
            Err("captured".into())
        })
    };
    let _ = request.builder(public, &nonce)?.sign(&capture);
    let data = seen.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or("the certificate had nothing to sign")?;
    let Some(mut agent) = crate::keys::connect_agent(choice).await? else {
        return Err("no agent runs: SSH_AUTH_SOCK names none".into());
    };
    let held = agent.request_identities().await.map_err(|e| format!("the agent: {e}"))?;
    if !held.iter().any(|id| id.public_key().key_data() == ca.key_data()) {
        return Err("the agent does not hold the CA key".into());
    }
    let hash = ca.algorithm().is_rsa().then_some(rsa_hash);
    let signature =
        agent.sign_request_signature(ca, hash, &data).await.map_err(|e| format!("the agent did not sign: {e}"))?;
    let replay = Detached::new(ca.key_data().clone(), move |again| {
        if again == data.as_slice() {
            Ok(signature.clone())
        } else {
            Err("the certificate changed between its two builds".into())
        }
    });
    request.builder(public, &nonce)?.sign(&replay).map_err(|e| format!("could not sign the certificate: {e}"))
}

/// `-V`, as ssh-keygen takes it: `+TIME` from now (the start a minute
/// back, as OpenSSH's), or `FROM:TO` of `+TIME`, `-TIME`, a time of
/// `YYYYMMDD[HHMM[SS]][Z]`, `always` (FROM) and `forever` (TO).
pub fn validity(spec: &str, now: i64) -> Result<(u64, u64), String> {
    let invalid = || format!("Invalid certificate life specification {spec}");
    if let Some(relative) = spec.strip_prefix('+').filter(|_| !spec.contains(':')) {
        let seconds = duration(relative).ok_or_else(invalid)?;
        let to = now.checked_add(seconds).ok_or_else(invalid)?;
        let from = (now - 59).div_euclid(60) * 60;
        return Ok((from.max(0) as u64, to.max(0) as u64));
    }
    let (from, to) = spec.split_once(':').filter(|(f, t)| !f.is_empty() && !t.is_empty()).ok_or_else(invalid)?;
    let from = match from {
        "always" => 0,
        f if f.starts_with(['+', '-']) => {
            relative(f, now).ok_or_else(|| format!("Invalid relative certificate time {f}"))?
        }
        f => crate::sshsig::parse_time(f).ok_or_else(|| format!("Invalid from time \"{f}\""))?.max(0) as u64,
    };
    let to = match to {
        "forever" => FOREVER,
        t if t.starts_with(['+', '-']) => {
            relative(t, now).ok_or_else(|| format!("Invalid relative certificate time {t}"))?
        }
        t => crate::sshsig::parse_time(t).ok_or_else(|| format!("Invalid to time \"{t}\""))?.max(0) as u64,
    };
    if to <= from {
        return Err("Empty certificate validity interval".into());
    }
    Ok((from, to))
}

/// `+TIME` or `-TIME` from `now`.
fn relative(text: &str, now: i64) -> Option<u64> {
    let (sign, rest) = text.split_at(1);
    let seconds = duration(rest)?;
    let at = if sign == "+" { now.checked_add(seconds)? } else { now.checked_sub(seconds)? };
    Some(at.max(0) as u64)
}

/// A time of OpenSSH's `convtime`: numbers each with a unit of `s`, `m`,
/// `h`, `d` or `w` (seconds when none), as `52w`, `1d12h` or `90`.
fn duration(text: &str) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let (mut total, mut number) = (0i64, None::<i64>);
    for c in text.chars() {
        if let Some(digit) = c.to_digit(10) {
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(digit as i64)?);
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    if let Some(seconds) = number {
        total = total.checked_add(seconds)?;
    }
    Some(total)
}

/// `-z`: a serial of 0 to 2^64-1, in decimal.
pub fn serial(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Invalid serial number \"{text}\""));
    }
    text.parse::<u64>().map_err(|_| format!("Invalid serial number \"{text}\""))
}

/// The validity as `ssh-keygen` says it: `forever`, `before T`, `after T`
/// or `from T to T`, in local time.
pub fn format_validity(after: u64, before: u64) -> String {
    let time = |t: u64| crate::sshsig::format_time(i64::try_from(t).unwrap_or(i64::MAX));
    match (after, before) {
        (0, FOREVER) => "forever".into(),
        (0, before) => format!("before {}", time(before)),
        (after, FOREVER) => format!("after {}", time(after)),
        (after, before) => format!("from {} to {}", time(after), time(before)),
    }
}

/// The name of a certificate's type, as `ssh-ed25519-cert-v01@openssh.com`.
pub fn cert_type_name(certificate: &Certificate) -> String {
    let key = PublicKey::new(certificate.public_key().clone(), "");
    let base = match key.algorithm() {
        Algorithm::Rsa { .. } => "ssh-rsa".to_string(),
        other => other.as_str().to_string(),
    };
    format!("{base}-cert-v01@openssh.com")
}

/// The lines of `ssh-keygen -L` for a certificate, after the line of its
/// file.
pub fn describe(certificate: &Certificate) -> Vec<String> {
    let key = PublicKey::new(certificate.public_key().clone(), "");
    let ca = PublicKey::new(certificate.signature_key().clone(), "");
    let kind = if certificate.cert_type().is_host() { "host" } else { "user" };
    let mut lines = vec![
        format!("        Type: {} {kind} certificate", cert_type_name(certificate)),
        format!(
            "        Public key: {}-CERT {}",
            crate::known_hosts::key_type(&key),
            crate::known_hosts::fingerprint(&key)
        ),
        format!(
            "        Signing CA: {} {} (using {})",
            crate::known_hosts::key_type(&ca),
            crate::known_hosts::fingerprint(&ca),
            certificate.signature().algorithm().as_str()
        ),
        format!("        Key ID: \"{}\"", certificate.key_id()),
        format!("        Serial: {}", certificate.serial()),
        format!("        Valid: {}", format_validity(certificate.valid_after(), certificate.valid_before())),
    ];
    list(&mut lines, "Principals", certificate.valid_principals().iter().map(|p| p.to_string()));
    let options = |map: &BTreeMap<String, String>, critical: bool| -> Vec<String> {
        map.iter().map(|(name, value)| option_line(name, value, critical)).collect()
    };
    list(&mut lines, "Critical Options", options(certificate.critical_options(), true).into_iter());
    list(&mut lines, "Extensions", options(certificate.extensions(), false).into_iter());
    lines
}

fn list(lines: &mut Vec<String>, name: &str, items: impl Iterator<Item = String>) {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        lines.push(format!("        {name}: (none)"));
        return;
    }
    lines.push(format!("        {name}: "));
    lines.extend(items.into_iter().map(|item| format!("                {item}")));
}

/// One option as `ssh-keygen -L` prints it: a known flag by its name, a
/// command or an address list with its value, another option with its data
/// in hex, as OpenSSH shows what it does not know.
fn option_line(name: &str, value: &str, critical: bool) -> String {
    let known_flag =
        if critical { name == "verify-required" } else { PERMITS.contains(&name) || name == "no-touch-required" };
    if known_flag {
        return name.to_string();
    }
    if critical && matches!(name, "force-command" | "source-address") {
        return format!("{name} {value}");
    }
    if value.is_empty() {
        return format!("{name} UNKNOWN FLAG OPTION");
    }
    let mut data = (value.len() as u32).to_be_bytes().to_vec();
    data.extend_from_slice(value.as_bytes());
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("{name} UNKNOWN OPTION: {hex} (len {})", data.len())
}

#[cfg(test)]
#[path = "cert_tests.rs"]
mod tests;
