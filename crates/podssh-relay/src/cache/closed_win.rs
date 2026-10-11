//! The Windows side of [`super::closed`] (T-274): the owner and the access
//! list of an opened file, read from its security descriptor; and the files
//! and directories that podssh makes, with an access list of their own that
//! lets in the user, SYSTEM and the Administrators alone, whatever the
//! directory above them lets in, as OpenSSH for Windows makes its files.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::closed::{judge, Acl, Entry};
use super::Others;

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE`: the entries of a
/// file's list; another type (an object's, a callback's) is not a file's.
const ALLOWED: u8 = 0;
const DENIED: u8 = 1;
/// The right to read a descriptor, and the flag that opens a directory.
const READ_CONTROL: u32 = 0x2_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Whether `file` is this user's and closed to others beyond `others`.
pub(crate) fn closed(file: &File, others: Others) -> Result<(), String> {
    let user = user_sid().map_err(|e| format!("this user's SID cannot be read: {e}"))?;
    let acl = acl_of(file).map_err(|e| format!("its owner and access list cannot be read: {e}"))?;
    judge(&acl, user, others)
}

/// This user's SID, read once.
fn user_sid() -> Result<&'static str, String> {
    static USER: OnceLock<Result<String, String>> = OnceLock::new();
    USER.get_or_init(|| read_user_sid().map_err(|e| e.to_string())).as_deref().map_err(Clone::clone)
}

fn read_user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of this process; `token` receives a handle,
    // closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len: u32 = 0;
    // SAFETY: a call with no buffer asks for the length.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    let size = (buf.len() * 8) as u32;
    // SAFETY: `buf` holds `size` bytes, aligned for a TOKEN_USER.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size, &mut len) };
    let e = io::Error::last_os_error();
    // SAFETY: opened above.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(e);
    }
    // SAFETY: the buffer holds the TOKEN_USER that was written; its SID
    // points inside the buffer, which lives to the end of this call.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    sid_string(sid)
}

/// A SID as its string, `S-1-5-...`.
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `text` receives a string to free.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` is a string that ends with a NUL; it is freed once.
    let string = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let string = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        string
    };
    Ok(string)
}

/// The owner and the access list of `file`, opened with the right to read
/// its descriptor (each read open has it).
fn acl_of(file: &File) -> io::Result<Acl> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is the open file's; `owner` and `dacl` point into
    // `descriptor`, which is freed below, after its last use.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let acl = read_acl(owner, dacl);
    // SAFETY: allocated by GetSecurityInfo, and no longer used.
    unsafe { LocalFree(descriptor) };
    acl
}

fn read_acl(owner: PSID, dacl: *mut ACL) -> io::Result<Acl> {
    let owner = sid_string(owner)?;
    if dacl.is_null() {
        return Ok(Acl { owner, entries: None });
    }
    // SAFETY: a valid list of the descriptor.
    let count = unsafe { (*dacl).AceCount };
    let mut entries = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the count of entries.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: each entry begins with its header.
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        if header.AceType != ALLOWED && header.AceType != DENIED {
            continue;
        }
        // SAFETY: an allowed or a denied entry is a header, a mask, then the
        // SID, which begins at `SidStart`.
        let (mask, sid) = unsafe {
            let entry = &*(ace as *const ACCESS_ALLOWED_ACE);
            (entry.Mask, std::ptr::addr_of!(entry.SidStart) as PSID)
        };
        entries.push(Entry {
            allow: header.AceType == ALLOWED,
            inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
            sid: sid_string(sid)?,
            mask,
        });
    }
    Ok(Acl { owner, entries: Some(entries) })
}

/// A security descriptor that LocalFree frees.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurity
        // DescriptorW, and freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// The access list of what podssh makes: full control for SYSTEM, the
/// Administrators and the user, and none for anyone else, protected from
/// the entries of the directory above; `inherit` for a directory, whose new
/// files and directories get the same.
fn private_descriptor(inherit: bool) -> io::Result<Descriptor> {
    let user = user_sid().map_err(io::Error::other)?;
    let flags = if inherit { "OICI" } else { "" };
    descriptor(&format!("D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)(A;{flags};FA;;;{user})"))
}

/// The access list of a file that each may read and only those of the
/// private list may change, as OpenSSH for Windows makes a `.pub` file
/// (T-288): the private list, and reading for Everyone.
fn public_descriptor() -> io::Result<Descriptor> {
    let user = user_sid().map_err(io::Error::other)?;
    descriptor(&format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})(A;;FR;;;WD)"))
}

fn descriptor(sddl: &str) -> io::Result<Descriptor> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide` ends with a NUL; `descriptor` receives an allocation
    // that `Descriptor` frees.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Descriptor(descriptor))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// A new file of this user that nobody else may open, never one that
/// exists, and so never through a link.
pub(crate) fn create_new_private(path: &Path) -> io::Result<File> {
    create_new(path, &private_descriptor(false)?)
}

/// A new file of this user that each may read and nobody else may change,
/// never one that exists (T-288).
pub(crate) fn create_new_public(path: &Path) -> io::Result<File> {
    create_new(path, &public_descriptor()?)
}

fn create_new(path: &Path, descriptor: &Descriptor) -> io::Result<File> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = wide(path);
    // SAFETY: `name` ends with a NUL, and `attributes` and its descriptor
    // live through the call; the handle that comes back is the file's.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle that this call opened, owned by the File from now on.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

/// `dir` made, a real directory, and closed to others: when its list lets
/// anyone else in, it gets an access list of its own, which its files
/// inherit.
pub(crate) fn make_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the directory is a symbolic link"));
    }
    let open =
        std::fs::OpenOptions::new().access_mode(READ_CONTROL).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir)?;
    let user = user_sid().map_err(io::Error::other)?;
    if judge(&acl_of(&open)?, user, Others::NoAccess).is_ok() {
        return Ok(());
    }
    drop(open);
    let descriptor = private_descriptor(true)?;
    let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut::<ACL>());
    // SAFETY: the descriptor is valid; `dacl` points into it, which lives
    // through the next call.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let name = wide(dir);
    // SAFETY: `name` ends with a NUL; `dacl` is the descriptor's list.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}
