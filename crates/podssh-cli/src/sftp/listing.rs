//! `ls` of `podssh sftp`, as OpenSSH's sftp lists (T-471; `parse_ls_flags`,
//! `do_ls_dir` and `do_globbed_ls` of its `sftp.c`, 10.2p1 to 10.6p1).
//! Without `-l` or `-1`, the names go in columns of the terminal's width,
//! else 80. With `-l`, each entry of a directory is the long name that the
//! server wrote for it; a line made here instead (`podssh_ssh::sftp::long`,
//! OpenSSH's `ls_file`) when the server names owners by number
//! (`users-groups-by-id@openssh.com`), with `-n` or `-h`, for a file or a
//! pattern, and for an entry that came with no long name. `-n` shows the
//! numbers even where the server could name them, as OpenSSH does since
//! 10.4p1; 10.2p1 and 10.3p1 named them still.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::Write;

use podssh_ssh::sftp::{long, FileAttributes, Names, Sftp};

use super::commands;
use crate::cp::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// The order of a listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Sort {
    /// By name, the default.
    #[default]
    Name,
    /// `-t`: the newest first.
    Time,
    /// `-S`: the largest first.
    Size,
    /// `-f`: as the server listed them.
    Unsorted,
}

/// The switches of `ls`, read in their order as OpenSSH reads them: `-1`
/// drops `-l`, `-n` and `-h`; an `-l` or `-n` after it drops `-1`; the last of
/// `-f`, `-S` and `-t` gives the order, which `-r` turns round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub long: bool,
    pub one: bool,
    pub numeric: bool,
    pub si: bool,
    pub all: bool,
    pub reverse: bool,
    pub sort: Sort,
}

impl Flags {
    /// The switches of `letters`, each of `-1afhlnrSt`.
    pub fn parse(letters: &str) -> Flags {
        let mut f = Flags::default();
        for c in letters.chars() {
            match c {
                '1' => (f.one, f.long, f.numeric, f.si) = (true, false, false, false),
                'S' => f.sort = Sort::Size,
                'a' => f.all = true,
                'f' => f.sort = Sort::Unsorted,
                'h' => f.si = true,
                'l' => (f.one, f.long) = (false, true),
                'n' => (f.one, f.long, f.numeric) = (false, true, true),
                'r' => f.reverse = true,
                't' => f.sort = Sort::Time,
                _ => {}
            }
        }
        f
    }
}

/// One name of a listing: as it is shown, what it sorts by (the entry's name
/// in a directory, the whole path for a pattern), the server's long name, and
/// what the server told of it.
struct Row {
    shown: String,
    key: String,
    longname: String,
    attrs: FileAttributes,
}

/// A path that `ls` names, or that its pattern matches: whole, with a `/`
/// after a directory, as OpenSSH's glob marks one.
struct Found {
    path: String,
    dir: bool,
    attrs: FileAttributes,
}

/// The kind of `attrs` by its mode: russh-sftp's own test takes a socket for
/// a directory, as their bits overlap.
fn kind(attrs: &FileAttributes) -> u32 {
    attrs.permissions.unwrap_or(0) & 0o170_000
}

fn is_dir(attrs: &FileAttributes) -> bool {
    kind(attrs) == 0o040_000
}

/// `path` under `cwd`, the directory there.
fn joined(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd.ends_with('/') {
        format!("{cwd}{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

/// `path` as OpenSSH shows it (`path_strip`): `strip` and the `/` after it cut
/// from its head; with no `strip` (an absolute path was typed), whole.
pub fn stripped(path: &str, strip: Option<&str>) -> String {
    let Some(strip) = strip else { return path.to_string() };
    match path.strip_prefix(strip) {
        // The `/` after a strip that ends with none goes too.
        Some(rest) if !strip.ends_with('/') => rest.strip_prefix('/').unwrap_or(rest).to_string(),
        Some(rest) => rest.to_string(),
        None => path.to_string(),
    }
}

/// The width of the columns: the terminal's on stdin, as OpenSSH measures it
/// (`TIOCGWINSZ` of stdin alone, so a listing piped to a file still fits the
/// terminal that typed it), else 80.
fn width() -> usize {
    #[cfg(unix)]
    let size = podssh_ssh::terminal::size_of_fd(libc::STDIN_FILENO);
    #[cfg(not(unix))]
    let size = podssh_ssh::terminal::stdin_is_terminal().then(podssh_ssh::terminal::size).flatten();
    size.map_or(80, |s| s.cols as usize)
}

/// `ls` at `path` (`None`: the directory there, `cwd`), on `out`.
pub async fn ls(sftp: &Sftp, cwd: &str, path: Option<&str>, flags: Flags, out: &mut dyn Write) -> Result<(), Failed> {
    let width = width();
    let Some(path) = path else {
        return dir(sftp, cwd, "", flags, width, out).await;
    };
    // A relative path is shown from the directory there.
    let strip = (!path.starts_with('/')).then_some(cwd);
    let full = joined(cwd, path);
    let found = if commands::is_pattern(&full) { matched(sftp, &full).await? } else { vec![one(sftp, &full).await?] };
    // One directory: what it holds, each name after the path given.
    if let [only] = found.as_slice() {
        if only.dir {
            return dir(sftp, &only.path, &stripped(&only.path, strip), flags, width, out).await;
        }
    }
    let m = found.iter().map(|f| f.path.len()).max().unwrap_or(0);
    let mut rows: Vec<Row> = found
        .into_iter()
        .map(|f| Row { shown: stripped(&f.path, strip), key: f.path, longname: String::new(), attrs: f.attrs })
        .collect();
    sort(&mut rows, flags);
    let rows: Vec<&Row> = rows.iter().collect();
    match flags.long {
        true => long_rows(sftp, &rows, flags, false, out).await,
        false => columns(&rows, m, flags, width, out),
    }
    Ok(())
}

/// The path `full` itself: a directory, a link to one included, or else
/// itself, a link as a link.
async fn one(sftp: &Sftp, full: &str) -> Result<Found, Failed> {
    let source = |e| transfer::from_sftp(e, Side::Source);
    match sftp.stat(full).await {
        Ok(attrs) if is_dir(&attrs) => {
            // Marked with a `/`, as OpenSSH's glob marks a directory.
            let path = format!("{}/", full.trim_end_matches('/'));
            Ok(Found { path, dir: true, attrs })
        }
        Ok(_) => Ok(Found { path: full.to_string(), dir: false, attrs: sftp.lstat(full).await.map_err(source)? }),
        // A link that names nothing is still there.
        Err(e) => match sftp.lstat(full).await {
            Ok(attrs) => Ok(Found { path: full.to_string(), dir: false, attrs }),
            Err(_) => Err(source(e)),
        },
    }
}

/// The names of the directory of `full` that its last name matches, as a
/// shell's glob matches them: a name that starts with a dot only when the
/// pattern does, `.` and `..` too, as OpenSSH's glob gives them for `.*`;
/// each in the server's order.
async fn matched(sftp: &Sftp, full: &str) -> Result<Vec<Found>, Failed> {
    let (dir, pattern) = transfer::split_remote(full);
    let listed = sftp.read_dir(dir).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
    let mut found = Vec::new();
    for entry in listed {
        let name = entry.name.as_str();
        let dotted = name.starts_with('.') && !pattern.starts_with('.');
        if dotted || !commands::matches(pattern, name) {
            continue;
        }
        let path = format!("{dir}{name}");
        // A link to a directory counts as one, with what stat says of it.
        let attrs = match kind(&entry.attrs) == 0o120_000 {
            true => sftp.stat(&path).await.ok().filter(is_dir).unwrap_or(entry.attrs),
            false => entry.attrs,
        };
        found.push(match is_dir(&attrs) {
            true => Found { path: format!("{path}/"), dir: true, attrs },
            false => Found { path, dir: false, attrs },
        });
    }
    if found.is_empty() {
        return Err(Failed::new(Fault::NoInput, format!("{full}: no file matches")));
    }
    Ok(found)
}

/// The entries of the directory `path`, each shown after `prefix`; a name
/// that starts with a dot only with `-a`.
async fn dir(
    sftp: &Sftp,
    path: &str,
    prefix: &str,
    flags: Flags,
    width: usize,
    out: &mut dyn Write,
) -> Result<(), Failed> {
    let listed = sftp.read_dir(path).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
    let mut rows: Vec<Row> = listed
        .into_iter()
        .map(|e| Row { shown: format!("{prefix}{}", e.name), key: e.name, longname: e.longname, attrs: e.attrs })
        .collect();
    sort(&mut rows, flags);
    let rows: Vec<&Row> = rows.iter().filter(|r| flags.all || !r.key.starts_with('.')).collect();
    if !flags.long {
        let m = rows.iter().map(|r| r.key.len()).max().unwrap_or(0) + prefix.len();
        columns(&rows, m, flags, width, out);
        return Ok(());
    }
    // The server's own lines, unless a line of ls_file is asked for or the
    // server can name the owners.
    let own = !flags.numeric && !flags.si && !sftp.names_ids();
    long_rows(sftp, &rows, flags, own, out).await;
    Ok(())
}

/// The order of `flags`: by name, the newest or the largest first, or turned
/// round with `-r`; `-f` keeps the server's, and `-r` with it does nothing.
fn sort(rows: &mut [Row], flags: Flags) {
    let order = |a: &Row, b: &Row| match flags.sort {
        Sort::Name => a.key.cmp(&b.key),
        Sort::Time => b.attrs.mtime.unwrap_or(0).cmp(&a.attrs.mtime.unwrap_or(0)),
        Sort::Size => b.attrs.size.unwrap_or(0).cmp(&a.attrs.size.unwrap_or(0)),
        Sort::Unsorted => Ordering::Equal,
    };
    if flags.sort != Sort::Unsorted {
        rows.sort_by(|a, b| if flags.reverse { order(b, a) } else { order(a, b) });
    }
}

/// `text` and spaces after it, to `width` bytes, as printf's `%-*s` pads.
fn padded(text: &str, width: usize) -> String {
    format!("{text}{}", " ".repeat(width.saturating_sub(text.len())))
}

/// The short form: as many names a line as columns of `m + 2` fit in
/// `width`, each padded to its column; with `-1` one a line, unpadded.
fn columns(rows: &[&Row], m: usize, flags: Flags, width: usize, out: &mut dyn Write) {
    let (columns, space) = match flags.one {
        true => (1, 0),
        false => {
            let columns = (width / (m + 2)).max(1);
            (columns, (width / columns).min(width))
        }
    };
    let mut c = 1;
    for row in rows {
        let _ = write!(out, "{}", padded(&row.shown, space));
        if c >= columns {
            let _ = writeln!(out);
            c = 1;
        } else {
            c += 1;
        }
    }
    if c != 1 {
        let _ = writeln!(out);
    }
}

/// The long form: the server's line of each row when `own` says so and it
/// sent one, else OpenSSH's `ls_file` line, with the names of the owners and
/// the groups, asked once, or with `-n` their numbers.
async fn long_rows(sftp: &Sftp, rows: &[&Row], flags: Flags, own: bool, out: &mut dyn Write) {
    let names = if own || flags.numeric { None } else { names_of(sftp, rows).await };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    for row in rows {
        if own && !row.longname.is_empty() {
            let _ = writeln!(out, "{}", row.longname);
            continue;
        }
        let (uid, gid) = (row.attrs.uid.unwrap_or(0), row.attrs.gid.unwrap_or(0));
        let user = names.as_ref().and_then(|n| n.users.get(&uid)).map(String::as_str);
        let group = names.as_ref().and_then(|n| n.groups.get(&gid)).map(String::as_str);
        let _ = writeln!(out, "{}", long::long_line(&row.shown, &row.attrs, flags.si, user, group, now));
    }
}

/// The names of the owners and the groups of `rows`, in one request; `None`
/// when the server gives none, and the numbers show, as OpenSSH's do.
async fn names_of(sftp: &Sftp, rows: &[&Row]) -> Option<Names> {
    let uids: BTreeSet<u32> = rows.iter().map(|r| r.attrs.uid.unwrap_or(0)).collect();
    let gids: BTreeSet<u32> = rows.iter().map(|r| r.attrs.gid.unwrap_or(0)).collect();
    let (uids, gids): (Vec<u32>, Vec<u32>) = (uids.into_iter().collect(), gids.into_iter().collect());
    sftp.users_groups(&uids, &gids).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, size: u64, mtime: u32) -> Row {
        let attrs = FileAttributes { size: Some(size), mtime: Some(mtime), ..FileAttributes::default() };
        Row { shown: name.into(), key: name.into(), longname: String::new(), attrs }
    }

    fn order(flags: &str) -> Vec<String> {
        let mut rows = vec![row("b", 30, 100), row("a", 10, 300), row("c", 20, 200)];
        sort(&mut rows, Flags::parse(flags));
        rows.into_iter().map(|r| r.key).collect()
    }

    #[test]
    fn the_switches_are_read_in_their_order_as_openssh_reads_them() {
        let f = Flags::parse("la");
        assert!(f.long && f.all && !f.one && f.sort == Sort::Name);
        assert!(Flags::parse("n").long && Flags::parse("n").numeric, "-n is a long form");
        // -1 drops -l, -n and -h; -l after -1 drops -1.
        assert_eq!(Flags::parse("lnh1"), Flags { one: true, ..Flags::default() });
        let back = Flags::parse("1l");
        assert!(back.long && !back.one);
        // The last order wins.
        assert_eq!(Flags::parse("tS").sort, Sort::Size);
        assert_eq!(Flags::parse("St").sort, Sort::Time);
        assert_eq!(Flags::parse("tf").sort, Sort::Unsorted);
    }

    #[test]
    fn each_order_is_openssh_s() {
        assert_eq!(order(""), ["a", "b", "c"]);
        assert_eq!(order("r"), ["c", "b", "a"]);
        assert_eq!(order("t"), ["a", "c", "b"], "the newest first");
        assert_eq!(order("tr"), ["b", "c", "a"]);
        assert_eq!(order("S"), ["b", "c", "a"], "the largest first");
        assert_eq!(order("Sr"), ["a", "c", "b"]);
        assert_eq!(order("f"), ["b", "a", "c"], "the server's order");
        assert_eq!(order("fr"), ["b", "a", "c"], "-r sorts nothing with -f");
    }

    #[test]
    fn a_path_is_shown_from_the_directory_there() {
        assert_eq!(stripped("/home/u/dir/f", Some("/home/u")), "dir/f");
        assert_eq!(stripped("/home/u/dir/", Some("/home/u")), "dir/");
        assert_eq!(stripped("/name", Some("/")), "name");
        assert_eq!(stripped("/srv/x", None), "/srv/x");
        assert_eq!(stripped("/srv/x", Some("/home/u")), "/srv/x");
        assert_eq!(joined("/home/u", "d"), "/home/u/d");
        assert_eq!(joined("/", "d"), "/d");
        assert_eq!(joined("/home/u", "/abs"), "/abs");
    }

    #[test]
    fn the_names_go_in_columns_of_the_width_as_openssh_s_do() {
        let rows = [row("alpha", 0, 0), row("b", 0, 0), row("gamma", 0, 0)];
        let refs: Vec<&Row> = rows.iter().collect();
        let mut out = Vec::new();
        // m = 5: 80 / 7 = 11 columns of 80 / 11 = 7 bytes.
        columns(&refs, 5, Flags::default(), 80, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "alpha  b      gamma  \n");
        // Two a line in a width of 16: 16 / 7 = 2 columns of 8.
        let mut out = Vec::new();
        columns(&refs, 5, Flags::default(), 16, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "alpha   b       \ngamma   \n");
        // -1: one a line, unpadded.
        let mut out = Vec::new();
        columns(&refs, 5, Flags::parse("1"), 80, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "alpha\nb\ngamma\n");
        // A name wider than the line: one column, the whole width.
        let mut out = Vec::new();
        columns(&refs, 100, Flags::default(), 80, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), format!("{:<80}\n{:<80}\n{:<80}\n", "alpha", "b", "gamma"));
    }
}
