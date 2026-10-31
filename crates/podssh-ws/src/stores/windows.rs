//! Windows' stores, through crypt32's own calls (`windows-sys`): `ROOT` of the
//! current user, whose view holds the machine's too, then `ROOT` of the
//! machine, which group policy and the enterprise's store fill.

use std::collections::HashSet;
use std::ffi::CStr;

use windows_sys::Win32::Foundation::{SetLastError, CRYPT_E_NOT_FOUND};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertGetEnhancedKeyUsage, CertOpenStore, CertVerifyTimeValidity,
    CERT_CONTEXT, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CTL_USAGE, X509_ASN_ENCODING,
};

use super::{sort, Held, Store};

/// Server authentication, the usage that a root for TLS needs (RFC 5280,
/// 4.2.1.12).
const SERVER_AUTH: &[u8] = b"1.3.6.1.5.5.7.3.1";

/// The places of the stores, the user's first.
const PLACES: [(&str, u32); 2] = [
    ("the current user's ROOT store", CERT_SYSTEM_STORE_CURRENT_USER),
    ("the machine's ROOT store", CERT_SYSTEM_STORE_LOCAL_MACHINE),
];

pub(super) fn read() -> Vec<Store> {
    // A certificate of a Disallowed store is no root, as for Windows.
    let mut refused: HashSet<Vec<u8>> = HashSet::new();
    for (_, place) in PLACES {
        if let Ok(held) = certificates(place, "Disallowed") {
            refused.extend(held.into_iter().map(|cert| cert.der));
        }
    }
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    PLACES
        .iter()
        .map(|&(name, place)| match certificates(place, "ROOT") {
            Ok(held) => sort(name, held, &refused, &mut seen),
            Err(note) => Store { name, note: Some(note), ..Store::default() },
        })
        .collect()
}

/// Each certificate of the system store `name` at `place`, opened read-only
/// and only if it exists.
fn certificates(place: u32, name: &str) -> Result<Vec<Held>, String> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 name that outlives the call.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            place | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
            wide.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return Err(format!("did not open: {}", std::io::Error::last_os_error()));
    }
    let mut held = Vec::new();
    let mut context: *const CERT_CONTEXT = std::ptr::null();
    loop {
        // SAFETY: the call frees the context that it is given and returns the
        // next one, or null after the last, which frees nothing more.
        context = unsafe { CertEnumCertificatesInStore(store, context) };
        if context.is_null() {
            break;
        }
        // SAFETY: a context of the store stays valid until the next call.
        let cert = unsafe { &*context };
        if cert.dwCertEncodingType & X509_ASN_ENCODING == 0 || cert.pbCertEncoded.is_null() {
            continue;
        }
        // SAFETY: the context holds `cbCertEncoded` bytes at `pbCertEncoded`.
        let der = unsafe { std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) }.to_vec();
        // SAFETY: the context's CERT_INFO is valid with it; a null time is now.
        let in_time = unsafe { CertVerifyTimeValidity(std::ptr::null(), cert.pCertInfo) } == 0;
        held.push(Held { der, for_servers: in_time && signs_for_servers(context) });
    }
    // SAFETY: the store came from CertOpenStore, and is closed once.
    unsafe { CertCloseStore(store, 0) };
    Ok(held)
}

/// Whether the certificate's usage, from its extension and the store's
/// property of it, is all usages or holds server authentication.
fn signs_for_servers(context: *const CERT_CONTEXT) -> bool {
    let mut len: u32 = 0;
    // SAFETY: with no buffer, the call writes only the length that it needs.
    if unsafe { CertGetEnhancedKeyUsage(context, 0, std::ptr::null_mut(), &mut len) } == 0 {
        return false;
    }
    // In u64s, so that the start is aligned for the struct.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8).max(1)];
    let usage = buffer.as_mut_ptr().cast::<CTL_USAGE>();
    // The reason of an empty answer is read after the call, so none may stay
    // from before it.
    // SAFETY: the buffer holds at least `len` bytes, aligned for CTL_USAGE.
    if unsafe {
        SetLastError(0);
        CertGetEnhancedKeyUsage(context, 0, usage, &mut len)
    } == 0
    {
        return false;
    }
    // SAFETY: the call filled the struct, and its array points into the buffer.
    let usage = unsafe { &*usage };
    if usage.cUsageIdentifier == 0 {
        // No usage named: all of them when the reason is "not found", else
        // none (crypt32's documentation of the call).
        return std::io::Error::last_os_error().raw_os_error() == Some(CRYPT_E_NOT_FOUND);
    }
    (0..usage.cUsageIdentifier as usize).any(|i| {
        // SAFETY: the array holds cUsageIdentifier NUL-terminated strings.
        let oid = unsafe { CStr::from_ptr((*usage.rgpszUsageIdentifier.add(i)).cast()) };
        oid.to_bytes() == SERVER_AUTH
    })
}
