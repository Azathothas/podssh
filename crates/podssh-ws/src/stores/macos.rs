//! macOS's trust settings, through the Security framework
//! (`security-framework`): those of the user, then those of the
//! administrator, where `security add-trusted-cert` and an MDM profile put a
//! root. The system's own roots are Apple's, which `/etc/ssl/cert.pem` holds.

use std::collections::HashSet;

use rustls_pki_types::CertificateDer;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use super::Store;

/// The domains, the user's first: its settings override the administrator's.
const DOMAINS: [(&str, Domain); 2] =
    [("the user's trust settings", Domain::User), ("the administrator's trust settings", Domain::Admin)];

pub(super) fn read() -> Vec<Store> {
    // Each certificate is decided once, by the first domain that names it.
    let mut decided: HashSet<Vec<u8>> = HashSet::new();
    DOMAINS
        .iter()
        .map(|&(name, domain)| {
            let settings = TrustSettings::new(domain);
            let certificates = match settings.iter() {
                Ok(certificates) => certificates,
                Err(why) => return Store { name, note: Some(format!("not read: {why}")), ..Store::default() },
            };
            let mut store = Store { name, ..Store::default() };
            for certificate in certificates {
                let der = certificate.to_der();
                if decided.contains(&der) {
                    continue;
                }
                // Settings that cannot be read decide nothing: a later
                // domain may.
                let Ok(setting) = settings.tls_trust_settings_for_certificate(&certificate) else {
                    store.passed_over += 1;
                    continue;
                };
                decided.insert(der.clone());
                // No setting for TLS means a root, as the framework documents
                // an empty array of settings; what is left is a denial.
                match setting {
                    None | Some(TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot) => {
                        store.roots.push(CertificateDer::from(der));
                    }
                    Some(_) => store.passed_over += 1,
                }
            }
            store
        })
        .collect()
}
