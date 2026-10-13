//! Security keys on Windows, through the WebAuthn API of the system
//! (webauthn.dll, of Windows 10 1903 and later): Windows talks to the
//! device, and shows its own dialog for the touch and the PIN. A process
//! needs no right of an administrator, which the raw HID of a FIDO device
//! needs on Windows. podssh loads the library at run time, which is the
//! probe, so that a Windows without it still runs podssh; windows-sys gives
//! the types, and no C is compiled.
//!
//! The client data that Windows hashes is podssh's data itself, as
//! libfido2 gives it to Windows for OpenSSH: the device then signs SHA-256
//! of the data, as PROTOCOL.u2f wants.

use std::path::Path;

use windows_sys::core::{HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, HWND};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIALS,
    WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

use super::format::{self, SkKey};
use super::{Ask, Enroll, Enrolled, Signed, TOUCH_LIMIT};

/// The functions of webauthn.dll that podssh calls, as the Windows SDK's
/// webauthn.h declares them (and windows-sys after it).
type Symbol = unsafe extern "system" fn() -> isize;
type ApiVersion = unsafe extern "system" fn() -> u32;
type MakeCredential = unsafe extern "system" fn(
    HWND,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type FreeAttestation = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type ErrorName = unsafe extern "system" fn(HRESULT) -> PCWSTR;

/// NTE_USER_CANCELLED: the dialog was closed, or its time ran out.
const USER_CANCELLED: u32 = 0x8009_0036;

/// webauthn.dll, loaded, with its functions; freed when dropped.
struct Library {
    module: HMODULE,
    version: u32,
    make: MakeCredential,
    get: GetAssertion,
    free_attestation: FreeAttestation,
    free_assertion: FreeAssertion,
    error_name: ErrorName,
}

impl Library {
    fn load() -> Result<Library, String> {
        let name = wide("webauthn.dll");
        // SAFETY: a name that ends in NUL. Only System32 is searched, so no
        // file of the working directory or of PATH is loaded.
        let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err("no security key: this Windows has no WebAuthn API (webauthn.dll, which Windows 10 1903 \
                        and later have)"
                .into());
        }
        match functions(module) {
            Some(library) => Ok(library),
            None => {
                // SAFETY: the module that LoadLibraryExW gave, freed once.
                unsafe { FreeLibrary(module) };
                Err("no security key: webauthn.dll lacks a function of the WebAuthn API".into())
            }
        }
    }

    /// Why an operation failed, in Windows' words.
    fn failure(&self, hr: HRESULT) -> String {
        // SAFETY: the API's name of an error is a static text of the library.
        let name = unsafe { from_wide((self.error_name)(hr)) };
        match hr as u32 {
            USER_CANCELLED => format!(
                "the dialog of the security key was closed, or nobody touched the key within {} s ({name})",
                TOUCH_LIMIT.as_secs()
            ),
            code => format!("Windows' WebAuthn API refused: {name} ({code:#010x})"),
        }
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: the module that LoadLibraryExW gave, freed once.
        unsafe { FreeLibrary(self.module) };
    }
}

/// The functions of `module`, or `None` when one is missing.
fn functions(module: HMODULE) -> Option<Library> {
    let symbol = |name: &[u8]| -> Option<Symbol> {
        // SAFETY: a loaded module, and a name that ends in NUL.
        unsafe { GetProcAddress(module, name.as_ptr()) }
    };
    // SAFETY: each pointer is the function of that name in webauthn.dll, of
    // the type that the Windows SDK declares for it.
    unsafe {
        let version = std::mem::transmute::<Symbol, ApiVersion>(symbol(b"WebAuthNGetApiVersionNumber\0")?);
        Some(Library {
            module,
            version: version(),
            make: std::mem::transmute::<Symbol, MakeCredential>(symbol(b"WebAuthNAuthenticatorMakeCredential\0")?),
            get: std::mem::transmute::<Symbol, GetAssertion>(symbol(b"WebAuthNAuthenticatorGetAssertion\0")?),
            free_attestation: std::mem::transmute::<Symbol, FreeAttestation>(symbol(
                b"WebAuthNFreeCredentialAttestation\0",
            )?),
            free_assertion: std::mem::transmute::<Symbol, FreeAssertion>(symbol(b"WebAuthNFreeAssertion\0")?),
            error_name: std::mem::transmute::<Symbol, ErrorName>(symbol(b"WebAuthNGetErrorName\0")?),
        })
    }
}

/// The window that owns Windows' dialog: the one in front, else the
/// console's. A session with no desktop has neither.
fn window() -> Result<HWND, String> {
    // SAFETY: neither call has a precondition.
    let front = unsafe { GetForegroundWindow() };
    let window = if front.is_null() { unsafe { GetConsoleWindow() } } else { front };
    if window.is_null() {
        return Err("no security key: Windows shows the dialog of a security key in a window, and this session \
                    has none (a session with no desktop)"
            .into());
    }
    Ok(window)
}

/// The version of Windows' WebAuthn API.
pub(super) struct Found {
    version: u32,
}

impl Found {
    pub fn describe(&self) -> String {
        format!("the WebAuthn API of Windows, version {}", self.version)
    }
}

/// webauthn.dll and a window for its dialog. A device named by path is for
/// Linux: on Windows the system chooses the device in its dialog.
pub(super) fn probe(named: Option<&Path>) -> Result<Found, String> {
    if let Some(path) = named {
        return Err(format!(
            "no security key: {} names a device of Linux; on Windows the system chooses the device in its dialog \
             (unset {}, and leave out -O device=)",
            path.display(),
            super::DEVICE_VARIABLE
        ));
    }
    let library = Library::load()?;
    window()?;
    Ok(Found { version: library.version })
}

/// Make a key in a device that the person chooses in Windows' dialog.
pub(super) fn enroll(_found: &Found, request: &Enroll, ask: &Ask) -> Result<Enrolled, String> {
    let library = Library::load()?;
    let owner = window()?;
    let rp_id = wide(&request.application);
    let openssh = wide("openssh");
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: rp_id.as_ptr(),
        pwszName: rp_id.as_ptr(),
        pwszIcon: std::ptr::null(),
    };
    let mut user_id = request.user.clone();
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: openssh.as_ptr(),
        pwszIcon: std::ptr::null(),
        pwszDisplayName: openssh.as_ptr(),
    };
    let mut parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: request.alg.cose() as i32,
    };
    let parameters =
        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS { cCredentialParameters: 1, pCredentialParameters: &mut parameter };
    let mut challenge: [u8; 32] = rand::random();
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: challenge.len() as u32,
        pbClientDataJSON: challenge.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    // SAFETY: zeros are a valid value of the options: null pointers, empty
    // lists and no flags. Version 1 reads only the fields set below.
    let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = unsafe { std::mem::zeroed() };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1;
    options.dwTimeoutMilliseconds = TOUCH_LIMIT.as_millis() as u32;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.bRequireResidentKey = i32::from(request.resident);
    options.dwUserVerificationRequirement = verification(request.verify);
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    (ask.say)("You may need to touch your security key to authorize key generation.");
    let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
    // SAFETY: each pointer is to a value of this frame, which lives through
    // the call; the API writes the pointer of its answer.
    let hr = unsafe { (library.make)(owner, &rp, &user, &parameters, &client_data, &options, &mut attestation) };
    if hr != 0 || attestation.is_null() {
        return Err(library.failure(hr));
    }
    // SAFETY: the API's answer, which lives until it is freed.
    let (data, id) = unsafe {
        let answer = &*attestation;
        let read = (
            bytes(answer.pbAuthenticatorData, answer.cbAuthenticatorData),
            bytes(answer.pbCredentialId, answer.cbCredentialId),
        );
        (library.free_attestation)(attestation);
        read
    };
    format::enrolled(request.alg, &request.application, &data, Some(&id))
}

/// Sign `data` with `key`, in the device that the person touches.
pub(super) fn sign(_found: &Found, key: &SkKey, data: &[u8], _ask: &Ask) -> Result<Signed, String> {
    let library = Library::load()?;
    let owner = window()?;
    let rp_id = wide(&key.application);
    let mut data = data.to_vec();
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: data.len() as u32,
        pbClientDataJSON: data.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let mut handle = key.key_handle.clone();
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
        cbId: handle.len() as u32,
        pbId: handle.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };
    // SAFETY: as for the options of `enroll`.
    let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1;
    options.dwTimeoutMilliseconds = TOUCH_LIMIT.as_millis() as u32;
    options.CredentialList = WEBAUTHN_CREDENTIALS { cCredentials: 1, pCredentials: &mut credential };
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.dwUserVerificationRequirement = verification(key.verify());
    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: as for the call of `enroll`.
    let hr = unsafe { (library.get)(owner, rp_id.as_ptr(), &client_data, &options, &mut assertion) };
    if hr != 0 || assertion.is_null() {
        return Err(library.failure(hr));
    }
    // SAFETY: the API's answer, which lives until it is freed.
    let (auth, signature) = unsafe {
        let answer = &*assertion;
        let read = (
            bytes(answer.pbAuthenticatorData, answer.cbAuthenticatorData),
            bytes(answer.pbSignature, answer.cbSignature),
        );
        (library.free_assertion)(assertion);
        read
    };
    format::signed(&key.application, &auth, signature)
}

fn verification(required: bool) -> u32 {
    if required {
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
    } else {
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
    }
}

/// `text` in UTF-16, with its NUL.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// A copy of `length` bytes at `pointer`.
///
/// # Safety
/// `pointer`, when it is not null, points to `length` bytes.
unsafe fn bytes(pointer: *const u8, length: u32) -> Vec<u8> {
    if pointer.is_null() || length == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(pointer, length as usize).to_vec()
}

/// The text at `text`, UTF-16 that ends in NUL, read up to 256 units.
///
/// # Safety
/// `text`, when it is not null, points to such a text.
unsafe fn from_wide(text: PCWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    while length < 256 && *text.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
}
