//! The files that an `Include` names: `*` and `?` in any part of the path,
//! as glob(3) expands them for OpenSSH, the names sorted by their bytes. A
//! name that starts with `.` matches only a pattern that starts with `.`,
//! as in glob(3).

use std::path::{Component, Path, PathBuf};

/// Each path that `pattern` names, sorted; a path with no wildcard is itself,
/// whether it exists or not.
pub fn expand(pattern: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = vec![PathBuf::new()];
    for part in pattern.components() {
        let Component::Normal(name) = part else {
            found.iter_mut().for_each(|p| p.push(part.as_os_str()));
            continue;
        };
        let name = name.to_string_lossy();
        if !name.contains(['*', '?']) {
            found.iter_mut().for_each(|p| p.push(name.as_ref()));
            continue;
        }
        let mut next = Vec::new();
        for dir in &found {
            let listed = match std::fs::read_dir(if dir.as_os_str().is_empty() { Path::new(".") } else { dir }) {
                Ok(listed) => listed,
                Err(_) => continue,
            };
            for entry in listed.flatten() {
                let file = entry.file_name().to_string_lossy().into_owned();
                if file.starts_with('.') && !name.starts_with('.') {
                    continue;
                }
                if podssh_ssh::known_hosts::wildcard(name.as_bytes(), file.as_bytes()) {
                    next.push(dir.join(&file));
                }
            }
        }
        found = next;
    }
    found.sort_by(|a, b| a.to_string_lossy().as_bytes().cmp(b.to_string_lossy().as_bytes()));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_in_each_part_is_expanded_and_sorted() {
        let root = std::env::temp_dir().join(format!("podssh-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dir, file) in
            [("d2", "a.conf"), ("d1", "b.conf"), ("d1", "a.conf"), ("d1", ".hidden.conf"), ("e1", "a.txt")]
        {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join(file), "").unwrap();
        }
        let names = |pattern: &str| -> Vec<String> {
            expand(&root.join(pattern))
                .iter()
                .map(|p| p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
                .collect()
        };
        assert_eq!(names("d*/a.conf"), ["d1/a.conf", "d2/a.conf"]);
        assert_eq!(names("d1/*.conf"), ["d1/a.conf", "d1/b.conf"], "no hidden name, in order");
        assert_eq!(names("d1/.*.conf"), ["d1/.hidden.conf"]);
        assert_eq!(names("?1/a.*"), ["d1/a.conf", "e1/a.txt"]);
        assert!(names("x*/a.conf").is_empty());
        assert_eq!(names("no/such.conf"), ["no/such.conf"], "a plain path is itself");
        let _ = std::fs::remove_dir_all(&root);
    }
}
