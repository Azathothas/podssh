//! What a copy by exec keeps besides the bytes (T-146). Up: the owner with
//! `chown`, the mode with `chmod`, and the times with `touch -t` read in UTC,
//! on the temporary file before `mv`. Down: what `stat` says of the far file
//! (GNU's and BusyBox's `-c`, else BSD's `-f`), set here as the SFTP road
//! sets it. A far side with no such tool keeps what it can, and a note says
//! what it did not. The rename takes `--no-clobber` and `--backup` (T-473).

use podssh_ssh::exec;
use podssh_ssh::{Connection, Log};

use super::{after_marker, command, failed, step_failed, Far, Kind, STEP_WAIT};
use crate::cp::clobber::{there, Clobber, Mode, Placed, Seen, Skip};
use crate::cp::meta::{note, Keep, Stamp};
use crate::cp::transfer::Failed;
use crate::exitmap::Fault;

/// What the script of a rename prints when `chown` refused the owner.
const OWNER_REFUSED: &str = "podssh-owner-refused";

/// A time as `touch -t` takes it, read in UTC (`TZ=UTC0`): `CCYYMMDDhhmm.SS`.
pub fn touch_time(seconds: u32) -> String {
    // 2026-10-12T08:10:00Z
    let t = crate::doctor::clock::format_utc(i64::from(seconds));
    format!("{}{}{}{}{}.{}", &t[0..4], &t[5..7], &t[8..10], &t[11..13], &t[14..16], &t[17..19])
}

/// What `stat` printed: the mode in octal, the access and the modification
/// times, the owner and the group. A field that does not read, as a time
/// out of SFTP's range, is none.
pub fn parse_stamp(text: &str) -> Option<Stamp> {
    let mut words = text.split_whitespace();
    let mode = u32::from_str_radix(words.next()?, 8).ok()?;
    let mut number = || words.next().and_then(|w| w.parse::<u32>().ok());
    let (atime, mtime, uid, gid) = (number(), number(), number(), number());
    Some(Stamp { mode: Some(mode & 0o777), atime, mtime, uid, gid })
}

/// `value` as the next positional word of a script: its name there.
fn word(args: &mut Vec<String>, value: String) -> String {
    args.push(value);
    format!("\"${}\"", args.len())
}

impl Far {
    /// Whether the far `path` is a symbolic link (`test -L`).
    pub(super) async fn is_link(&self, handle: &Connection, path: &str) -> Result<bool, Failed> {
        let script = self.marked("if [ -L \"$1\" ]; then echo link; else echo other; fi");
        let cmd = command(&script, &[path]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| step_failed(path, e))?;
        let at = after_marker(&got.stdout, &self.marker);
        Ok(at.is_some_and(|at| String::from_utf8_lossy(&got.stdout[at..]).trim() == "link"))
    }

    /// The mode, the times and the owner of the far file `path`, from
    /// `stat`; `None` when no `stat` there prints them.
    pub(super) async fn stamp(&self, handle: &Connection, path: &str) -> Result<Option<Stamp>, Failed> {
        if !self.tools.contains("stat") {
            return Ok(None);
        }
        let script = self.marked(
            "stat -c \"%a %X %Y %u %g\" -- \"$1\" 2>/dev/null || stat -f \"%Lp %a %m %u %g\" -- \"$1\" 2>/dev/null; \
             exit 0",
        );
        let cmd = command(&script, &[path]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| step_failed(path, e))?;
        let text =
            after_marker(&got.stdout, &self.marker).map(|at| String::from_utf8_lossy(&got.stdout[at..]).to_string());
        Ok(text.as_deref().and_then(parse_stamp))
    }

    /// The far `path` as the look of `--no-clobber` and `--update` sees it
    /// (T-473): `None` when it is missing; its time only with `times`, from
    /// `stat`, where the server has one.
    pub(in crate::cp) async fn seen(
        &self,
        handle: &Connection,
        path: &str,
        times: bool,
    ) -> Result<Option<Seen>, Failed> {
        let size = match self.kind(handle, path).await? {
            Kind::Missing => return Ok(None),
            Kind::File(n) => n,
            _ => 0,
        };
        let mtime = if times { self.stamp(handle, path).await?.and_then(|s| s.mtime) } else { None };
        Ok(Some(Seen { mtime, size }))
    }

    /// Give `temp` what `keep` asks of `stamp`, and its mode, as far as the
    /// server has the tools; then rename it onto `target`, unless it is the
    /// target itself (`--inplace`, T-147). A directory of that name is
    /// refused: `mv` would put the file inside it, where the SFTP road's
    /// rename fails. `clobber` places it as on the SFTP road (T-473):
    /// `--no-clobber` by `ln`, which refuses a name that is there, else `mv`
    /// after the look; `--backup` keeps the old file first, by `ln -f`, else
    /// by `mv`. `copy`: `temp` is a copy's, which goes when the name stays;
    /// else the source of a move, which stays.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) async fn rename(
        &self,
        handle: &Connection,
        temp: &str,
        target: &str,
        stamp: &Stamp,
        keep: Keep,
        clobber: Clobber,
        copy: bool,
        log: &Log,
    ) -> Result<Placed, Failed> {
        let mut script = String::from("if [ -d \"$2\" ]; then echo \"a directory has that name\" >&2; exit 1; fi; ");
        let mut args = vec![temp.to_string(), target.to_string()];
        if keep.owner {
            match (stamp.uid, stamp.gid) {
                (Some(uid), Some(gid)) if self.tools.contains("chown") => {
                    let owner = word(&mut args, format!("{uid}:{gid}"));
                    script.push_str(&format!("chown -- {owner} \"$1\" 2>/dev/null || echo {OWNER_REFUSED} >&2; "));
                }
                (Some(_), Some(_)) => note(log, "owner-chown", "the server has no chown: the owner was not kept"),
                _ => note(log, "owner-none", "the owner was not kept: this system has no owner by number"),
            }
        }
        // `--` before the mode: a strict POSIX chmod takes a later `--` as a
        // file.
        if let Some(mode) = stamp.mode.filter(|_| self.tools.contains("chmod")) {
            let mode = word(&mut args, format!("{mode:o}"));
            script.push_str(&format!("chmod -- {mode} \"$1\" || exit 1; "));
        }
        if keep.times {
            match (stamp.atime, stamp.mtime) {
                (Some(atime), Some(mtime)) if self.tools.contains("touch") => {
                    let (a, m) = (word(&mut args, touch_time(atime)), word(&mut args, touch_time(mtime)));
                    script.push_str(&format!(
                        "TZ=UTC0 touch -a -t {a} -- \"$1\" && TZ=UTC0 touch -m -t {m} -- \"$1\" || exit 1; "
                    ));
                }
                (Some(_), Some(_)) => note(log, "times-touch", "the server has no touch: the times were not kept"),
                _ => note(log, "times-range", "the times were not kept: SFTP carries 1970 to 2106 only"),
            }
        }
        let aside = clobber.backup.map(|suffix| format!("{target}{suffix}"));
        let end = match (temp == target, clobber.mode, &aside) {
            (true, ..) => "exit 0".to_string(),
            (false, Mode::Keep, _) => keep_name(copy),
            (false, _, Some(aside)) => backup_name(&word(&mut args, aside.clone())),
            (false, ..) => "exec mv -f -- \"$1\" \"$2\"".to_string(),
        };
        script.push_str(&end);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        let cmd = command(&script, &words).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| step_failed(target, e))?;
        let said = String::from_utf8_lossy(&got.stderr);
        if got.status != Some(0) {
            return Err(failed(Fault::CantCreate, format!("{target}: the rename failed: {}", said.trim())));
        }
        if said.contains(OWNER_REFUSED) {
            note(log, "owner-far", &format!("{target}: the owner was not kept: only root may give a file away"));
        }
        let mut placed = Placed::default();
        if said.contains(THERE) {
            log.info(&there(target));
            placed.skipped = Some(Skip::Exists);
        }
        if said.contains(NO_LINK) {
            log.verbose(&format!("{target}: ln made no hard link, so the look is the guard of --no-clobber"));
        }
        if said.contains(LINKED) || said.contains(RENAMED) {
            placed.backup = aside;
        }
        if said.contains(RENAMED) {
            log.verbose(&format!("{target}: ln made no hard link, so the old file was renamed first"));
        }
        Ok(placed)
    }
}

/// What the script of a rename prints when `--no-clobber` found the name
/// taken, when `ln` made no link, and how `--backup` kept the old file.
const THERE: &str = "podssh-name-there";
const NO_LINK: &str = "podssh-no-link";
const LINKED: &str = "podssh-backup-linked";
const RENAMED: &str = "podssh-backup-renamed";

/// The end of the script of `--no-clobber`: `ln` refuses a name that is
/// there (POSIX), and the name of `$1` then goes; a name there stays, and a
/// copy's temporary file goes; with no link made (no `ln`, a file system
/// with none), `mv` after the look.
fn keep_name(copy: bool) -> String {
    let drop = if copy { "rm -f -- \"$1\"; " } else { "" };
    format!(
        "if ln -- \"$1\" \"$2\" 2>/dev/null; then exec rm -f -- \"$1\"; fi; \
         if [ -e \"$2\" ] || [ -L \"$2\" ]; then {drop}echo {THERE} >&2; exit 0; fi; \
         echo {NO_LINK} >&2; exec mv -f -- \"$1\" \"$2\""
    )
}

/// The end of the script of `--backup`: the old file at `$2` takes the name
/// `aside`, a word of the script, by `ln -f`, which replaces an older backup
/// and leaves `$2` where it is; else by `mv`, and `$2` is missing a moment.
/// Then the rename.
fn backup_name(aside: &str) -> String {
    format!(
        "if [ -e \"$2\" ] || [ -L \"$2\" ]; then \
         if [ -d {aside} ]; then echo \"a directory has the name of the backup\" >&2; exit 1; fi; \
         if ln -f -- \"$2\" {aside} 2>/dev/null; then echo {LINKED} >&2; \
         else mv -f -- \"$2\" {aside} || exit 1; echo {RENAMED} >&2; fi; fi; \
         exec mv -f -- \"$1\" \"$2\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A script's end run by this host's `sh`, in `dir`, with `words` as its
    /// `$1`...: its stderr, after its status 0.
    #[cfg(unix)]
    fn sh(dir: &std::path::Path, script: &str, words: &[&str]) -> String {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("sh")
            .args(words)
            .current_dir(dir)
            .output()
            .expect("sh runs");
        assert!(out.status.success(), "{script}: {:?}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// The ends of the scripts of `--no-clobber` and `--backup` (T-473), with
    /// this host's `sh` and `ln`: a name that is there stays, a copy's
    /// temporary file goes and a moved source stays; a missing name takes
    /// the file; the old file takes the suffix, an older backup replaced.
    #[cfg(unix)]
    #[test]
    fn the_scripts_keep_a_name_that_is_there_and_the_old_file() {
        let dir = std::env::temp_dir().join(format!("podssh-keep-name-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let read = |name: &str| std::fs::read(dir.join(name)).ok();
        std::fs::write(dir.join("temp"), b"new").unwrap();
        std::fs::write(dir.join("there"), b"live").unwrap();
        assert!(sh(&dir, &keep_name(true), &["temp", "there"]).contains(THERE));
        assert_eq!((read("there").as_deref(), read("temp")), (Some(&b"live"[..]), None), "the copy's file went");
        std::fs::write(dir.join("source"), b"moved").unwrap();
        assert!(sh(&dir, &keep_name(false), &["source", "there"]).contains(THERE));
        assert_eq!(read("source").as_deref(), Some(&b"moved"[..]), "a moved source stays");
        sh(&dir, &keep_name(false), &["source", "missing"]);
        assert_eq!((read("missing").as_deref(), read("source")), (Some(&b"moved"[..]), None));
        // --backup: the old file at there~, then an older one replaced.
        std::fs::write(dir.join("temp"), b"one").unwrap();
        assert!(sh(&dir, &backup_name("\"$3\""), &["temp", "there", "there~"]).contains(LINKED));
        assert_eq!((read("there").as_deref(), read("there~").as_deref()), (Some(&b"one"[..]), Some(&b"live"[..])));
        std::fs::write(dir.join("temp"), b"two").unwrap();
        sh(&dir, &backup_name("\"$3\""), &["temp", "there", "there~"]);
        assert_eq!((read("there").as_deref(), read("there~").as_deref()), (Some(&b"two"[..]), Some(&b"one"[..])));
        // Nothing there: no backup.
        std::fs::write(dir.join("temp"), b"first").unwrap();
        let said = sh(&dir, &backup_name("\"$3\""), &["temp", "fresh", "fresh~"]);
        assert!(!said.contains(LINKED) && read("fresh~").is_none(), "{said}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_takes_the_time_in_utc() {
        assert_eq!(touch_time(0), "197001010000.00");
        // 2000-02-29T12:34:56Z, a leap day.
        assert_eq!(touch_time(951_827_696), "200002291234.56");
        assert_eq!(touch_time(u32::MAX), "210602070628.15");
    }

    #[test]
    fn a_stamp_reads_what_stat_prints() {
        let both = Stamp { mode: Some(0o644), atime: Some(1), mtime: Some(2), uid: Some(1000), gid: Some(100) };
        assert_eq!(parse_stamp("644 1 2 1000 100\n"), Some(both));
        // setuid is not kept; a time out of range is none.
        let odd = parse_stamp("4755 -5 3 0 0").expect("read");
        assert_eq!((odd.mode, odd.atime, odd.mtime, odd.uid), (Some(0o755), None, Some(3), Some(0)));
        assert_eq!(parse_stamp("stat: cannot stat"), None);
        assert_eq!(parse_stamp(""), None);
    }
}
