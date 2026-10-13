//! `podssh job fetch HOST ID [DIR]` (T-197): the output of a job that
//! ended, and the files that `--files` names in the home directory of the
//! host, each copied as `podssh cp` copies a file (over SFTP, or by exec; a
//! temporary name, the digests, a rename; a new connection after a break),
//! into DIR, `./podssh-job-ID` by default. The output is `DIR/out`, and each
//! file goes under `DIR/files` by its path from the home directory, so that
//! no name of the host takes the place of the output.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::{Log, EXIT_FAILURE};

use super::{far, first_line, unexpected};
use crate::cp::link;
use crate::cp::operand::{Operand, Remote};
use crate::cp::pipe::Shape;
use crate::cp::session;
use crate::exitmap::sysexits;
use crate::ssh::resolve::Resolved;

/// What the far script said of a job to fetch: the name of its directory,
/// its state, and each file that the pattern names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub dir: String,
    pub state: String,
    pub files: Vec<String>,
}

/// The answer of the far script's `files`: `dir NAME STATE`, a line
/// `file PATH` for each file, then `end`; `None` for another answer, or one
/// that did not end.
pub fn parse_found(lines: &[String]) -> Option<Found> {
    let (head, rest) = lines.split_first()?;
    let mut words = head.split(' ');
    if words.next()? != "dir" {
        return None;
    }
    let (dir, state) = (words.next()?.to_string(), words.next()?.to_string());
    if rest.last().map(String::as_str) != Some("end") {
        return None;
    }
    let files = rest.iter().filter_map(|l| l.strip_prefix("file ")).map(str::to_string).collect();
    Some(Found { dir, state, files })
}

/// The place here of a far file of `--files`: under `dir/files`, by its
/// path from the home directory, each part a name that may be written
/// here; `None` for a path that has no such place.
pub fn local_place(dir: &Path, far: &str) -> Option<PathBuf> {
    let root = dir.join("files");
    let mut place = root.clone();
    for part in far.split('/').filter(|p| !p.is_empty() && *p != ".") {
        crate::cp::tree::check_name(part, cfg!(windows)).ok()?;
        place.push(part);
    }
    (place != root).then_some(place)
}

/// Fetch the job `id` into `dir`: 0, or 255 when a copy failed; 75 when the
/// job has not ended, so that its output is not whole yet.
pub(crate) async fn fetch(
    resolved: &Resolved,
    host: &str,
    id: &str,
    dir: &Path,
    files: Option<&str>,
    log: &Arc<Log>,
) -> i32 {
    let first = match link::connect(resolved, log).await {
        Ok(first) => first,
        Err(failed) => {
            log.error(&failed.message);
            return EXIT_FAILURE;
        }
    };
    let found = match far::lines(first.handle(), host, &["files", id, files.unwrap_or("-")]).await {
        Ok(lines) => first_line(host, &lines)
            .and_then(|head| parse_found(&lines).ok_or_else(|| unexpected(host, head))),
        Err(why) => Err(why),
    };
    let found = match found {
        Ok(found) => found,
        Err(why) => {
            first.close().await;
            log.error(&why);
            return EXIT_FAILURE;
        }
    };
    if found.state == "queued" || found.state == "running" {
        first.close().await;
        log.error(&format!(
            "job {id} on {host} is {}, so its output is not whole yet; podssh job wait {host} {id} waits for its end",
            found.state
        ));
        return sysexits::EX_TEMPFAIL;
    }
    let mut copies = vec![(format!(".podssh/jobs/{}/out", found.dir), dir.join("out"))];
    let mut failed = false;
    for far in &found.files {
        match local_place(dir, far) {
            Some(place) => copies.push((far.clone(), place)),
            None => {
                failed = true;
                log.error(&format!("{far}: not copied: its path has no place under {}", dir.join("files").display()));
            }
        }
    }
    let mut link = Some(first);
    for (far, place) in copies {
        if let Some(parent) = place.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                failed = true;
                log.error(&format!("{}: {e}", parent.display()));
                continue;
            }
        }
        let source = Operand::Remote(Remote { user: None, host: host.to_string(), port: None, path: far.clone() });
        let dest = Operand::Local(place.display().to_string());
        match session::attempts(&mut link, resolved, &source, &dest, false, log, Shape::default()).await {
            Ok((done, _)) => log.verbose(&format!("{far}: {} bytes to {}", done.bytes, done.destination)),
            Err(f) => {
                failed = true;
                log.error(&f.message);
                // No connection is left for the next file.
                if link.is_none() {
                    break;
                }
            }
        }
    }
    if let Some(link) = link {
        link.close().await;
    }
    if failed {
        EXIT_FAILURE
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_names_the_directory_the_state_and_each_file() {
        let lines: Vec<String> =
            ["dir 0001-abcd1234 done", "file build/a.log", "file b c.txt", "end"].iter().map(|s| s.to_string()).collect();
        let found = parse_found(&lines).unwrap();
        assert_eq!((found.dir.as_str(), found.state.as_str()), ("0001-abcd1234", "done"));
        assert_eq!(found.files, ["build/a.log", "b c.txt"]);
        assert_eq!(parse_found(&lines[..3]), None, "no end: the answer was cut");
        assert_eq!(parse_found(&["no-job abcd1234".to_string()]), None);
    }

    #[test]
    fn a_far_file_goes_under_files_and_never_out_of_it() {
        let dir = Path::new("podssh-job-abcd1234");
        assert_eq!(local_place(dir, "build/a.log"), Some(dir.join("files").join("build").join("a.log")));
        assert_eq!(local_place(dir, "./out"), Some(dir.join("files").join("out")), "never the output");
        for bad in ["../x", "a/../../x", "", "."] {
            assert_eq!(local_place(dir, bad), None, "{bad}");
        }
    }
}
