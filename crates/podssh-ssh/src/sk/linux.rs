//! Security keys on Linux: CTAP2 over the kernel's raw HID devices,
//! `/dev/hidraw*`. The probe lists them, keeps those whose report
//! descriptor is a FIDO device's (the usage page 0xF1D0, read in sysfs, else
//! by `HIDIOCGRDESC`), and opens each, as a user needs a udev rule for that
//! on most systems. Nothing is assumed: a sandbox or a container has no
//! such device, and the probe says so.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::flow;
use super::format::SkKey;
use super::hid::{Channel, Reports, REPORT};
use super::{Ask, Enroll, Enrolled, Signed, TOUCH_LIMIT};

/// `_IOR('H', 0x01, int)` and `_IOR('H', 0x02, struct
/// hidraw_report_descriptor)` of linux/hidraw.h: the size of a report
/// descriptor, and the descriptor, of 4096 bytes at most.
const HIDIOCGRDESCSIZE: u32 = 0x8004_4801;
const HIDIOCGRDESC: u32 = 0x9004_4802;
const MAX_DESCRIPTOR: usize = 4096;

/// The FIDO devices that this user may open.
pub(super) struct Found {
    paths: Vec<PathBuf>,
}

impl Found {
    pub fn describe(&self) -> String {
        let paths: Vec<String> = self.paths.iter().map(|p| p.display().to_string()).collect();
        paths.join(", ")
    }
}

/// The FIDO devices of `/dev`, or only `named`.
pub(super) fn probe(named: Option<&Path>) -> Result<Found, String> {
    probe_in(Path::new("/dev"), Path::new("/sys/class/hidraw"), named)
}

/// [`probe`] with the directories of the devices and of sysfs, for the tests.
fn probe_in(dev: &Path, sys: &Path, named: Option<&Path>) -> Result<Found, String> {
    let candidates = match named {
        Some(path) => vec![path.to_path_buf()],
        None => hidraw_nodes(dev)?,
    };
    if candidates.is_empty() {
        return Err(format!(
            "no security key: this host shows no {}/hidraw* device (a container or a sandbox shows none)",
            dev.display()
        ));
    }
    let mut paths = Vec::new();
    let mut refused = Vec::new();
    for path in &candidates {
        match fido(path, sys) {
            Ok(true) => match open(path) {
                Ok(_) => paths.push(path.clone()),
                Err(why) => refused.push(why),
            },
            Ok(false) => {}
            Err(why) => refused.push(why),
        }
    }
    if !paths.is_empty() {
        return Ok(Found { paths });
    }
    Err(match (refused.is_empty(), named) {
        (false, _) => format!("no security key: {}", refused.join("; ")),
        (true, Some(path)) => format!("no security key: {} is not a FIDO device", path.display()),
        (true, None) => format!(
            "no security key: none of the {} HID devices of {} is a FIDO device",
            candidates.len(),
            dev.display()
        ),
    })
}

/// The `hidraw` devices of `dev`, in the order of their numbers.
fn hidraw_nodes(dev: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        std::fs::read_dir(dev).map_err(|e| format!("no security key: {} cannot be read: {e}", dev.display()))?;
    let mut nodes: Vec<(u32, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_char_device()))
        .filter_map(|entry| {
            let number = entry.file_name().to_str()?.strip_prefix("hidraw")?.parse().ok()?;
            Some((number, entry.path()))
        })
        .collect();
    nodes.sort();
    Ok(nodes.into_iter().map(|(_, path)| path).collect())
}

/// Whether `path` is a FIDO device, by its report descriptor.
fn fido(path: &Path, sys: &Path) -> Result<bool, String> {
    let name = path.file_name().map(|n| sys.join(n).join("device").join("report_descriptor"));
    if let Some(bytes) = name.and_then(|file| std::fs::read(file).ok()) {
        return Ok(is_fido(&bytes));
    }
    // No sysfs (a sandbox may hide it): the device's own answer.
    let file = open(path)?;
    let bytes = descriptor(&file).map_err(|e| format!("{} is no HID device here: {e}", path.display()))?;
    Ok(is_fido(&bytes))
}

/// The report descriptor of an open hidraw device.
fn descriptor(file: &File) -> std::io::Result<Vec<u8>> {
    let mut size: libc::c_int = 0;
    // SAFETY: HIDIOCGRDESCSIZE writes one int into `size`.
    if unsafe { libc::ioctl(file.as_raw_fd(), HIDIOCGRDESCSIZE as libc::Ioctl, &mut size) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let size = usize::try_from(size).unwrap_or(0).min(MAX_DESCRIPTOR);
    // struct hidraw_report_descriptor: the size, then 4096 bytes.
    let mut buffer = vec![0u8; 4 + MAX_DESCRIPTOR];
    buffer[..4].copy_from_slice(&(size as u32).to_ne_bytes());
    // SAFETY: the buffer has the layout and the size of the struct, and the
    // kernel writes at most `size` bytes after the first four.
    if unsafe { libc::ioctl(file.as_raw_fd(), HIDIOCGRDESC as libc::Ioctl, buffer.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buffer[4..4 + size].to_vec())
}

/// Whether a report descriptor has a collection of FIDO's: the usage page
/// 0xF1D0 and the usage 0x01 before a collection, as libfido2 reads it.
fn is_fido(descriptor: &[u8]) -> bool {
    let (mut page, mut usage) = (0u32, 0u32);
    let mut rest = descriptor;
    while let Some((&prefix, after)) = rest.split_first() {
        // A long item: its size, its tag, its data.
        if prefix == 0xfe {
            let size = after.first().map_or(0, |s| usize::from(*s));
            rest = after.get(2 + size..).unwrap_or_default();
            continue;
        }
        let size = match prefix & 0x03 {
            3 => 4,
            n => usize::from(n),
        };
        let Some(data) = after.get(..size) else { break };
        let value = data.iter().rev().fold(0u32, |n, b| n << 8 | u32::from(*b));
        match prefix & 0xfc {
            0x04 => page = value,
            0x08 => usage = value,
            0xa0 if page == 0xf1d0 && usage == 0x01 => return true,
            _ => {}
        }
        rest = &after[size..];
    }
    false
}

/// A hidraw device, opened to read and write, and held for this process:
/// another program that uses the device at once would get its answers.
fn open(path: &Path) -> Result<File, String> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "{} is a FIDO device that this user may not open ({e}): a udev rule gives the user access \
             (TAG+=\"uaccess\", as libfido2's 70-u2f.rules does)",
            path.display()
        ),
        _ => format!("{} cannot be opened: {e}", path.display()),
    })?;
    // SAFETY: flock on a descriptor that `file` holds open.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!("{} is in use by another program", path.display()));
    }
    Ok(file)
}

/// The reports of a hidraw device.
struct Hidraw(File);

impl Reports for Hidraw {
    fn send(&mut self, report: &[u8; REPORT]) -> std::io::Result<()> {
        // The first byte is the report's number: 0, as a FIDO device has none.
        let mut out = [0u8; REPORT + 1];
        out[1..].copy_from_slice(report);
        self.0.write_all(&out)
    }

    fn receive(&mut self, wait: Duration) -> std::io::Result<Option<[u8; REPORT]>> {
        let until = Instant::now() + wait;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let mut poll = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            // SAFETY: one pollfd of this function, for a descriptor held open.
            match unsafe { libc::poll(&mut poll, 1, ms) } {
                0 => continue,
                n if n > 0 => {
                    let mut report = [0u8; REPORT];
                    let read = self.0.read(&mut report)?;
                    if read == 0 {
                        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the device went"));
                    }
                    return Ok(Some(report));
                }
                _ => {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// A channel of the device at `path`.
fn channel(path: &Path) -> Result<Channel<Hidraw>, String> {
    let file = open(path)?;
    Channel::open(Hidraw(file), rand::random()).map_err(|e| format!("{}: {e}", path.display()))
}

/// Make a key in the one FIDO device. With several, podssh does not choose
/// one: the user names it.
pub(super) fn enroll(found: &Found, request: &Enroll, ask: &Ask) -> Result<Enrolled, String> {
    let [path] = found.paths.as_slice() else {
        return Err(format!(
            "{} FIDO devices are attached ({}): keep one, or name one with -O device=PATH or {}",
            found.paths.len(),
            found.describe(),
            super::DEVICE_VARIABLE
        ));
    };
    flow::enroll(&mut channel(path)?, request, ask, TOUCH_LIMIT)
}

/// Sign with the device that holds `key`: each device is asked silently
/// first, when there are several.
pub(super) fn sign(found: &Found, key: &SkKey, data: &[u8], ask: &Ask) -> Result<Signed, String> {
    let mut chosen = None;
    for path in &found.paths {
        let mut candidate = channel(path)?;
        if found.paths.len() == 1 {
            chosen = Some(candidate);
            break;
        }
        match flow::holds(&mut candidate, key) {
            Some(true) => {
                chosen = Some(candidate);
                break;
            }
            // A device that cannot say may hold it.
            None if chosen.is_none() => chosen = Some(candidate),
            _ => {}
        }
    }
    let mut channel = chosen.ok_or("no attached security key holds this key")?;
    flow::sign(&mut channel, key, data, ask, TOUCH_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report descriptor of a FIDO device that the FIDO U2F HID
    /// specification gives, encoded here item by item; and the start of a
    /// keyboard's.
    const FIDO: [u8; 34] = [
        0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
    ];
    const KEYBOARD: [u8; 8] = [0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07];

    #[test]
    fn a_fido_device_is_known_by_its_descriptor() {
        assert!(is_fido(&FIDO));
        assert!(!is_fido(&KEYBOARD));
        assert!(!is_fido(&FIDO[..3]), "a descriptor cut short");
        assert!(!is_fido(&[]));
    }

    /// A directory with no device, and one whose hidraw is a plain file,
    /// show no security key, and say why.
    #[test]
    fn no_device_is_said_by_name() {
        let dir = std::env::temp_dir().join(format!("podssh-sk-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let none = probe_in(&dir, &dir, None).err().unwrap();
        assert!(none.starts_with("no security key: this host shows no"), "{none}");
        std::fs::write(dir.join("hidraw0"), b"not a device").unwrap();
        let plain = probe_in(&dir, &dir, None).err().unwrap();
        assert!(plain.contains("shows no"), "a plain file is no device: {plain}");
        let null = probe_in(&dir, &dir, Some(Path::new("/dev/null"))).err().unwrap();
        assert!(null.starts_with("no security key: /dev/null"), "{null}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
