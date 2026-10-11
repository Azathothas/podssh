//! A bundle of PEM certificates (`podssh_ws::bundle::pem_certificates`), as
//! `--ca-file` or `SSL_CERT_FILE` names it: any bytes, no panic, and no
//! certificate made of nothing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ws::bundle::pem_certificates;

fuzz_target!(|data: &[u8]| {
    if let Ok(certificates) = pem_certificates(data) {
        assert!(certificates.iter().all(|c| !c.is_empty()));
    }
});
