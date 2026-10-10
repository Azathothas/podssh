//! The scratch directories of a test, removed when the test ends, so that
//! runs of the tests do not fill the temporary directory (T-272).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// The directories that this thread made. libtest runs each test on a
/// thread of its own and joins it, and a thread's locals are dropped as it
/// ends: each directory goes then, also when the test fails, and no place
/// that uses the path has to hold anything.
struct Made(RefCell<Vec<PathBuf>>);

impl Drop for Made {
    fn drop(&mut self) {
        for dir in self.0.borrow().iter() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

thread_local!(static MADE: Made = const { Made(RefCell::new(Vec::new())) });

/// Remove `dir`, and all that is in it, when this test ends.
pub fn at_test_end(dir: &Path) {
    MADE.with(|made| made.0.borrow_mut().push(dir.to_path_buf()));
}
