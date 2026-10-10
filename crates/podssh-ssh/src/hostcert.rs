//! Host certificates against the `@cert-authority` lines of `known_hosts`
//! (T-027), as OpenSSH checks them: a certificate from a CA that a line
//! names for the host is accepted when it is valid for this host, and refused
//! with the check that failed; one from a CA that no line names is checked
//! as its plain key, as OpenSSH falls back. A CA line never makes a plain key
//! known.

use std::path::PathBuf;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::{Certificate, HashAlg};

use crate::known_hosts::{self, Marker};

/// What the check of a certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertCheck {
    /// No `@cert-authority` line for the host names the certificate's CA:
    /// its plain key is checked; the words say why.
    NoAuthority(String),
    /// Valid for this host, from a CA that a line names: accepted, and
    /// nothing is recorded.
    Valid,
    /// From a CA that a line names, but not valid for this host: the check
    /// that failed, with the host key's and the CA's fingerprints.
    Invalid(String),
}

/// Whether `files` hold a `@cert-authority` line for `name` (`host` or
/// `[host]:port`): podssh then asks the server for a certificate.
pub fn trusted_for(files: &[PathBuf], name: &str) -> bool {
    known_hosts::entries_for(files, name).iter().any(|e| e.marker == Some(Marker::CertAuthority))
}

/// Check `cert` for `name` against `files`, at `now` (seconds since the Unix
/// epoch).
pub fn check(cert: &Certificate, files: &[PathBuf], name: &str, now: u64) -> CertCheck {
    let entries = known_hosts::entries_for(files, name);
    let host_fp = cert.public_key().fingerprint(HashAlg::Sha256);
    let ca = cert.signature_key();
    let ca_fp = ca.fingerprint(HashAlg::Sha256);
    let refused = |what: String| {
        CertCheck::Invalid(format!(
            "the host certificate of '{name}' (key {host_fp}, signed by the CA {ca_fp}) {what}. Refusing to connect."
        ))
    };
    let revoked = |key: &KeyData| entries.iter().any(|e| e.marker == Some(Marker::Revoked) && e.key.key_data() == key);
    if revoked(cert.public_key()) {
        return refused("holds a key that is marked @revoked".into());
    }
    if revoked(ca) {
        return refused("comes from a CA that is marked @revoked".into());
    }
    if !entries.iter().any(|e| e.marker == Some(Marker::CertAuthority) && e.key.key_data() == ca) {
        return CertCheck::NoAuthority(format!(
            "the CA {ca_fp} of the host certificate of '{name}' is in no @cert-authority line for it, so its key \
             {host_fp} is checked as a plain key"
        ));
    }
    let (after, before) = (cert.valid_after(), cert.valid_before());
    if now < after || now >= before {
        let state = if now < after { "is not valid yet" } else { "has expired" };
        return refused(format!(
            "{state}: it is valid from {} to {}, and this host's clock says {}; a sandbox's clock can be wrong, and \
             podssh doctor checks it",
            stamp(after),
            stamp(before),
            stamp(now)
        ));
    }
    if cert.validate_at(now, [&ca_fp]).is_err() {
        return refused("has a signature that does not verify".into());
    }
    if cert.cert_type() != CertType::Host {
        return refused("is a user certificate, not a host certificate".into());
    }
    // The principal is the host as typed, or HostKeyAlias, with no port.
    let host = bare_host(name);
    if !cert.valid_principals().iter().any(|p| p == host) {
        let named = if cert.valid_principals().is_empty() {
            "no principal".to_string()
        } else {
            cert.valid_principals().join(", ")
        };
        return refused(format!("names {named}, not {host}"));
    }
    // OpenSSH defines no critical option for a host certificate.
    if let Some(option) = cert.critical_options().keys().next() {
        return refused(format!("has the critical option {option}, which podssh does not know"));
    }
    CertCheck::Valid
}

/// `host` of a `known_hosts` name: `host`, or `[host]:port`.
fn bare_host(name: &str) -> &str {
    match name.strip_prefix('[').and_then(|rest| rest.rsplit_once("]:")) {
        Some((host, _port)) => host,
        None => name,
    }
}

/// A time in seconds since the epoch, as `YYYY-MM-DD HH:MM:SS UTC`; the
/// greatest value of a certificate is "forever".
fn stamp(secs: u64) -> String {
    if secs == u64::MAX {
        return "forever".into();
    }
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rest = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rest / 3600, rest / 60 % 60, rest % 60)
}

/// The date of `z` days since 1970-01-01 (Howard Hinnant's algorithm), as
/// `podssh doctor`'s clock check computes it.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_gives_its_host_and_a_time_its_date() {
        assert_eq!(bare_host("example.org"), "example.org");
        assert_eq!(bare_host("[example.org]:2222"), "example.org");
        assert_eq!(bare_host("[2001:db8::1]:22"), "2001:db8::1");
        assert_eq!(stamp(0), "1970-01-01 00:00:00 UTC");
        // date(2026, 10, 11) is 20737 days after the epoch.
        assert_eq!(stamp(20_737 * 86_400 + 3_661), "2026-10-11 01:01:01 UTC");
        assert_eq!(stamp(u64::MAX), "forever");
    }
}
