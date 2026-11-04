//! The file of the TLS groups that servers took (T-664): podssh-ws keeps the
//! groups (`podssh_ws::tls::groups`), and this crate knows where the cache
//! is. A private file of the cache, as [`crate::addresses::FILE`] is: mode
//! 0600 in a directory of this user's, and one that others can read is not
//! read. It holds names and group numbers, and no secret.

use std::path::PathBuf;
use std::sync::Once;

use podssh_ws::tls::groups::{self, GroupFile};

/// The file, in the cache.
pub const FILE: &str = "tls-groups.txt";

/// The file in the first of these directories that takes it.
pub struct In(pub Vec<PathBuf>);

impl GroupFile for In {
    fn load(&self) -> Option<String> {
        crate::cache::load_file_from(&self.0, FILE)
    }

    fn store(&self, text: &[u8]) {
        // A file that cannot be kept costs a later run its hint alone.
        let _ = crate::cache::store_file_in_first(&self.0, FILE, text);
    }
}

static INSTALLED: Once = Once::new();

/// Give the process's TLS configurations the file of the cache, once a run:
/// with the addresses of the cache, before any dial ([`crate::addresses::install`]).
pub fn install() {
    INSTALLED.call_once(|| {
        groups::keep_in(Box::new(In(crate::cache::candidate_dirs())));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ws::tls::groups::Kept;

    /// A test's directory of its own, gone when the test ends.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-tls-groups-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Scratch(dir)
    }

    /// A run keeps the group in a private file of the cache, and a later run
    /// reads it there.
    #[test]
    fn the_group_goes_to_a_private_file_and_back() {
        let dir = scratch("round");
        let first = Kept::new();
        first.keep_in(Box::new(In(vec![dir.0.clone()])));
        first.took("relay.example", 23);
        let path = dir.0.join(FILE);
        let text = std::fs::read_to_string(&path).expect("the file");
        assert!(text.contains("relay.example 23 "), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the file is the user's alone");
        }
        let later = Kept::new();
        later.keep_in(Box::new(In(vec![dir.0.clone()])));
        assert_eq!(later.group("relay.example"), Some(23));
    }

    /// A file of the cache that does not read gives no group, and a note.
    #[test]
    fn a_file_that_does_not_read_is_set_aside_with_a_note() {
        let dir = scratch("garbage");
        crate::cache::store_file_in_first(&[dir.0.clone()], FILE, b"garbage").expect("a private file");
        let kept = Kept::new();
        kept.keep_in(Box::new(In(vec![dir.0.clone()])));
        assert_eq!(kept.group("relay.example"), None);
        assert!(kept.take_note().is_some_and(|note| note.contains("set aside")));
    }

    /// A file that others can read is not read, as no file of the cache is.
    #[cfg(unix)]
    #[test]
    fn a_file_that_others_can_read_is_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("open");
        // A group of now, which would be read from a private file.
        let text = format!("podssh tls groups 1\nrelay.example 23 {}\n", crate::pool::now_ms());
        let path = crate::cache::store_file_in_first(&[dir.0.clone()], FILE, text.as_bytes()).expect("a private file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let kept = Kept::new();
        kept.keep_in(Box::new(In(vec![dir.0.clone()])));
        assert_eq!(kept.group("relay.example"), None);
        assert_eq!(kept.take_note(), None, "no file read, nothing set aside");
    }
}
