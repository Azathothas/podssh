//! The probes that need libc: the user database, a pty, binding a socket,
//! and the noexec mount flag. Each closes or removes what it opened. A
//! refusal here is a fact about the host, never a failure of podssh: podssh
//! needs none of these.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use podssh_ws::Verdict;

fn ok(detail: impl Into<String>) -> Verdict {
    Verdict::Ok { detail: detail.into() }
}

/// The current uid's entry in the user database, which OpenSSH's own tools
/// need and podssh does not.
pub(super) fn user() -> Verdict {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let named = ["USER", "LOGNAME"]
        .iter()
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()).map(|v| format!("{n}={v}")));
    match passwd_entry(uid) {
        Ok(Some((name, home))) => ok(format!("uid {uid} is '{name}' in the user database (home {home})")),
        Ok(None) => {
            let missing = if Path::new("/etc/passwd").exists() {
                "is not in /etc/passwd"
            } else {
                "has no user database entry (there is no /etc/passwd)"
            };
            let podssh = match (named, uid) {
                (Some(var), _) => format!("podssh takes the user name from {var}"),
                (None, 0) => "podssh takes uid 0 to be root".to_string(),
                (None, _) => "podssh ssh needs user@host or -l USER here".to_string(),
            };
            ok(format!(
                "uid {uid} {missing}: OpenSSH's ssh, scp and ssh-keygen refuse to run without an entry; {podssh}"
            ))
        }
        Err(e) => Verdict::Unknown { why: format!("the user database could not be read: {e}") },
    }
}

/// `(name, home)` for `uid`, or `None` when the user database has no entry.
fn passwd_entry(uid: libc::uid_t) -> io::Result<Option<(String, String)>> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: an all-zero passwd is valid (null pointers); getpwuid_r
        // writes only within `buf`, whose length it is given.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        // "Not found" is 0 with no result; some C libraries say ENOENT or ESRCH.
        if result.is_null() && matches!(rc, 0 | libc::ENOENT | libc::ESRCH) {
            return Ok(None);
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        // SAFETY: on success both strings are NUL-terminated inside `buf`.
        let text = |p: *const libc::c_char| {
            if p.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            }
        };
        return Ok(Some((text(pwd.pw_name), text(pwd.pw_dir))));
    }
}

/// Whether a pty can be had: the master from `/dev/ptmx`, then its slave.
pub(super) fn pty() -> Verdict {
    let remote = "a remote pty (podssh ssh -t) needs nothing here";
    // SAFETY: posix_openpt takes flags only.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return ok(format!("none: /dev/ptmx: {}; {remote}", io::Error::last_os_error()));
    }
    let slave = open_slave(master);
    // SAFETY: `master` was opened above and is closed once.
    unsafe { libc::close(master) };
    match slave {
        Ok(name) => ok(format!("a pty can be allocated here ({name})")),
        Err(e) => ok(format!("/dev/ptmx opens, but no pty comes of it: {e}; {remote}")),
    }
}

fn open_slave(master: libc::c_int) -> Result<String, String> {
    // SAFETY: `master` is an open pty master for both calls.
    if unsafe { libc::grantpt(master) } != 0 {
        return Err(format!("grantpt: {}", io::Error::last_os_error()));
    }
    if unsafe { libc::unlockpt(master) } != 0 {
        return Err(format!("unlockpt: {}", io::Error::last_os_error()));
    }
    let name = pts_name(master).map_err(|e| format!("ptsname: {e}"))?;
    let path = CString::new(name.clone()).map_err(|_| "ptsname gave a name with a NUL in it".to_string())?;
    // SAFETY: `path` is NUL-terminated; the descriptor is closed at once.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        return Err(format!("{name}: {}", io::Error::last_os_error()));
    }
    unsafe { libc::close(fd) };
    Ok(name)
}

#[cfg(target_os = "linux")]
fn pts_name(master: libc::c_int) -> io::Result<String> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: the buffer's length is passed with it.
    let rc = unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // SAFETY: ptsname_r NUL-terminates within the buffer on success.
    Ok(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "linux"))]
fn pts_name(master: libc::c_int) -> io::Result<String> {
    // SAFETY: the host checks run on one thread, so ptsname's static buffer
    // is not shared; it is copied out at once.
    let p = unsafe { libc::ptsname(master) };
    if p.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// Bind a TCP socket to 127.0.0.1 port 0 and close it, never listening.
pub(super) fn bind_inet() -> Verdict {
    // SAFETY: plain socket creation; the descriptor is closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return ok(format!("no TCP socket can be made: {}", io::Error::last_os_error()));
    }
    // SAFETY: an all-zero sockaddr_in is valid. The kernel sets the length
    // field where there is one (BSD) from the length passed to bind.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `addr` is a sockaddr_in of `len` bytes.
    let bound = if unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_in).cast(), len) } == 0 {
        let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut name_len = len;
        // SAFETY: `name` has room for `name_len` bytes.
        unsafe { libc::getsockname(fd, (&mut name as *mut libc::sockaddr_in).cast(), &mut name_len) };
        Ok(u16::from_be(name.sin_port))
    } else {
        Err(io::Error::last_os_error())
    };
    // SAFETY: `fd` was opened above and is closed once.
    unsafe { libc::close(fd) };
    match bound {
        Ok(port) => ok(format!("bound 127.0.0.1:{port} and closed it without listening")),
        Err(e) => ok(format!("refused: {e}; podssh never listens, so nothing depends on it")),
    }
}

/// Bind a Unix socket to a file (removed at once) and, on Linux, to a name
/// in the abstract namespace: a host can refuse one and allow the other.
pub(super) fn bind_unix() -> Verdict {
    let file = socket_path();
    let at_file = bind_unix_at(Some(&file));
    let _ = std::fs::remove_file(&file);
    let file_text = match at_file {
        Ok(()) => format!("bound {} and removed it", file.display()),
        Err(e) => format!("{}: refused: {e}", file.display()),
    };
    let abstract_text = if cfg!(target_os = "linux") {
        match bind_unix_at(None) {
            Ok(()) => "; the abstract namespace: bound".to_string(),
            Err(e) => format!("; the abstract namespace: refused: {e}"),
        }
    } else {
        String::new()
    };
    ok(format!("{file_text}{abstract_text}; podssh never listens"))
}

fn socket_path() -> PathBuf {
    let name = format!("{}.sock", super::host::unique("podssh-doctor"));
    let tmp = std::env::temp_dir().join(&name);
    // sun_path holds 104 to 108 bytes; a long TMPDIR would not fit.
    if tmp.as_os_str().len() < 100 {
        tmp
    } else {
        PathBuf::from("/tmp").join(name)
    }
}

/// Bind a Unix stream socket to `path`, or with `None` to an abstract name,
/// and close it.
fn bind_unix_at(path: Option<&Path>) -> io::Result<()> {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name: Vec<u8> = match path {
        Some(p) => p.as_os_str().as_bytes().to_vec(),
        None => [b"\0".as_slice(), super::host::unique("podssh-doctor").as_bytes()].concat(),
    };
    if name.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the name is too long for a Unix socket"));
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(&name) {
        *slot = *byte as libc::c_char;
    }
    let len = (match path {
        Some(_) => std::mem::size_of::<libc::sockaddr_un>(),
        None => std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len(),
    }) as libc::socklen_t;
    // SAFETY: plain socket creation; the descriptor is closed below.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `addr` is a sockaddr_un and `len` does not exceed its size.
    let rc = unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
    let result = if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
    // SAFETY: `fd` was opened above and is closed once.
    unsafe { libc::close(fd) };
    result
}

/// Whether `dir` is on a mount that forbids running programs (`None` when
/// that cannot be read).
#[cfg(target_os = "linux")]
pub(super) fn noexec(dir: &Path) -> Option<bool> {
    let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero statvfs is valid; `path` is NUL-terminated.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return None;
    }
    Some(stats.f_flag & libc::ST_NOEXEC != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(v: &Verdict) -> &str {
        match v {
            Verdict::Ok { detail } | Verdict::Failed { detail } => detail,
            Verdict::Unknown { why } => why,
        }
    }

    #[test]
    fn the_probes_report_facts_and_never_fail() {
        for (name, v) in [("user", user()), ("pty", pty()), ("inet", bind_inet()), ("unix", bind_unix())] {
            assert!(!matches!(v, Verdict::Failed { .. }), "{name}: {v:?}");
            assert!(!detail(&v).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_unix_socket_probe_leaves_no_file_behind() {
        let file = socket_path();
        let _ = bind_unix_at(Some(&file));
        let _ = std::fs::remove_file(&file);
        assert!(!file.exists());
        let too_long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
        assert_eq!(bind_unix_at(Some(&too_long)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noexec_reads_a_mount_and_says_nothing_for_a_missing_path() {
        assert!(noexec(Path::new("/")).is_some());
        assert_eq!(noexec(Path::new("/nonexistent/podssh")), None);
    }
}
