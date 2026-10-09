//! Each command of `podssh sftp` against one SFTP session. `get` and `put`
//! copy as `podssh cp` does (a temporary name, the digests, a rename); the
//! others are one SFTP request each, on paths that the session's directories
//! complete.

use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, Sftp};
use podssh_ssh::Log;

use super::commands::{self, Command};
use crate::cp::bysftp;
use crate::cp::link::{Link, Road};
use crate::cp::resume::Progress;
use crate::cp::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// What a command leaves the session to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    Bye,
}

/// The session's state: its directory there, and its directory here.
pub struct State<'a> {
    link: &'a Link,
    sftp: &'a Sftp,
    pub cwd: String,
    pub lcwd: PathBuf,
    home: String,
    log: &'a Log,
}

fn failed(fault: Fault, message: String) -> Failed {
    Failed::new(fault, message)
}

impl<'a> State<'a> {
    /// A session at the login directory, and at this host's directory.
    pub async fn new(link: &'a Link, log: &'a Log) -> Result<State<'a>, Failed> {
        let Road::Sftp(sftp) = &link.road else {
            return Err(failed(Fault::RelayUnreachable, "the server has no SFTP subsystem".into()));
        };
        let home = sftp.realpath(".").await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let lcwd = std::env::current_dir().map_err(|e| failed(Fault::CantCreate, format!("this directory: {e}")))?;
        Ok(State { link, sftp, cwd: home.clone(), lcwd, home, log })
    }

    /// `path` under the directory there.
    pub fn there(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_string()
        } else if self.cwd.ends_with('/') {
            format!("{}{path}", self.cwd)
        } else {
            format!("{}/{path}", self.cwd)
        }
    }

    /// `path` under the directory here.
    fn here(&self, path: &str) -> PathBuf {
        self.lcwd.join(path)
    }

    /// Whether `path` there is a directory.
    pub async fn is_dir(&self, path: &str) -> Result<bool, Failed> {
        let attrs = self.sftp.stat(path).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
        Ok(attrs.is_dir())
    }

    /// The paths there that `path` names: itself, or the names of its
    /// directory that its last name matches.
    async fn expand(&self, path: &str) -> Result<Vec<String>, Failed> {
        let full = self.there(path);
        if !commands::is_pattern(&full) {
            return Ok(vec![full]);
        }
        let (dir, pattern) = transfer::split_remote(&full);
        let listed = self.sftp.read_dir(dir).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let mut found: Vec<String> = listed
            .into_iter()
            .filter(|e| e.name != "." && e.name != ".." && commands::matches(pattern, &e.name))
            .map(|e| format!("{dir}{}", e.name))
            .collect();
        found.sort();
        if found.is_empty() {
            return Err(failed(Fault::NoInput, format!("{full}: no file matches")));
        }
        Ok(found)
    }

    /// Run one command.
    pub async fn run(&mut self, command: &Command, out: &mut dyn Write) -> Result<Flow, Failed> {
        let sftp = self.sftp;
        // An SFTP error names its step and its path already.
        let gone = |e| transfer::from_sftp(e, Side::Destination);
        match command {
            Command::Get { remote, local } => {
                let sources = self.expand(remote).await?;
                let many = sources.len() > 1;
                let dest = match local {
                    Some(l) => self.here(l),
                    None => self.lcwd.clone(),
                };
                for source in &sources {
                    let _ = writeln!(out, "Fetching {source} to {}", dest.display());
                    let shown = dest.display().to_string();
                    let handle = self.link.handle();
                    let mut progress = Progress::default();
                    bysftp::down(sftp, handle, source, &shown, many, self.log, &mut progress, &self.link.meter).await?;
                }
            }
            Command::Put { local, remote } => {
                let source = self.here(local);
                let dest = match remote {
                    Some(r) => self.there(r),
                    None => format!("{}/", self.cwd.trim_end_matches('/')),
                };
                let _ = writeln!(out, "Uploading {} to {dest}", source.display());
                let shown = source.display().to_string();
                let mut progress = Progress::default();
                bysftp::up(sftp, self.link.handle(), &shown, &dest, false, self.log, &mut progress, &self.link.meter)
                    .await?;
            }
            Command::Rename { from, to } => {
                let (from, to) = (self.there(from), self.there(to));
                sftp.rename(&from, &to).await.map_err(gone)?;
            }
            Command::Rm(path) => {
                for each in self.expand(path).await? {
                    let _ = writeln!(out, "Removing {each}");
                    sftp.remove(&each).await.map_err(gone)?;
                }
            }
            Command::Mkdir { path, parents } => self.mkdir(&self.there(path), *parents).await?,
            Command::Rmdir(path) => {
                let path = self.there(path);
                sftp.rmdir(&path).await.map_err(gone)?;
            }
            Command::Ls { path, long, all } => self.ls(path.as_deref(), *long, *all, out).await?,
            Command::Cd(path) => {
                let target = path.as_deref().map_or_else(|| self.home.clone(), |p| self.there(p));
                let real = sftp.realpath(&target).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
                if !self.is_dir(&real).await? {
                    return Err(failed(Fault::NoInput, format!("{real}: not a directory")));
                }
                self.cwd = real;
            }
            Command::Lcd(path) => {
                let target = match path {
                    Some(p) => self.here(p),
                    None => home_dir().ok_or_else(|| failed(Fault::Config, "lcd: this host has no home".into()))?,
                };
                if !target.is_dir() {
                    return Err(failed(Fault::NoInput, format!("{}: not a directory", target.display())));
                }
                self.lcwd = std::fs::canonicalize(&target).unwrap_or(target);
            }
            Command::Pwd => {
                let _ = writeln!(out, "Remote working directory: {}", self.cwd);
            }
            Command::Lpwd => {
                let _ = writeln!(out, "Local working directory: {}", self.lcwd.display());
            }
            Command::Chmod { mode, path } => {
                let path = self.there(path);
                let attrs = FileAttributes { permissions: Some(*mode), ..FileAttributes::default() };
                sftp.setstat(&path, attrs).await.map_err(gone)?;
            }
            Command::Df { path, human, inodes } => self.df(path.as_deref(), *human, *inodes, out).await?,
            Command::Help => {
                for (form, what) in commands::HELP {
                    let _ = writeln!(out, "{form:<26} {what}");
                }
            }
            Command::Version => {
                let _ = writeln!(out, "SFTP protocol version 3");
            }
            Command::Bye => return Ok(Flow::Bye),
        }
        Ok(Flow::Next)
    }

    async fn mkdir(&self, path: &str, parents: bool) -> Result<(), Failed> {
        let make = |p: String| async move {
            let attrs = FileAttributes { permissions: Some(0o777), ..FileAttributes::default() };
            self.sftp.mkdir(&p, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))
        };
        if !parents {
            return make(path.to_string()).await;
        }
        // Each directory on the way that is not there yet.
        let mut at = String::new();
        for part in path.split('/') {
            if part.is_empty() {
                at.push('/');
                continue;
            }
            at.push_str(part);
            if self.sftp.stat(&at).await.is_err() {
                make(at.clone()).await?;
            }
            at.push('/');
        }
        Ok(())
    }

    async fn ls(&self, path: Option<&str>, long: bool, all: bool, out: &mut dyn Write) -> Result<(), Failed> {
        let full = path.map_or_else(|| self.cwd.clone(), |p| self.there(p));
        let (dir, pattern) = if commands::is_pattern(&full) {
            let (d, p) = transfer::split_remote(&full);
            (d.to_string(), Some(p.to_string()))
        } else if self.is_dir(&full).await? {
            (full.clone(), None)
        } else {
            let attrs = self.sftp.stat(&full).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
            let _ = writeln!(out, "{}", entry_line(&full, &attrs, long));
            return Ok(());
        };
        let listed = self.sftp.read_dir(&dir).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let mut names: Vec<_> = listed
            .into_iter()
            .filter(|e| all || !e.name.starts_with('.'))
            .filter(|e| pattern.as_deref().is_none_or(|p| commands::matches(p, &e.name)))
            .collect();
        names.sort_by(|a, b| a.name.cmp(&b.name));
        for e in names {
            let _ = writeln!(out, "{}", entry_line(&e.name, &e.attrs, long));
        }
        Ok(())
    }

    async fn df(&self, path: Option<&str>, human: bool, inodes: bool, out: &mut dyn Write) -> Result<(), Failed> {
        let full = path.map_or_else(|| self.cwd.clone(), |p| self.there(p));
        let fs = self.sftp.statvfs(&full).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
        if inodes {
            let used = fs.files.saturating_sub(fs.files_free);
            let _ =
                writeln!(out, "{:>12} {:>12} {:>12} {:>12} {:>11}", "Inodes", "Used", "Avail", "(root)", "%Capacity");
            let _ = writeln!(
                out,
                "{:>12} {:>12} {:>12} {:>12} {:>10}%",
                fs.files,
                used,
                fs.files_available,
                fs.files_free,
                percent(used, fs.files)
            );
            return Ok(());
        }
        let size = |blocks: u64| blocks.saturating_mul(fs.unit);
        let (total, free, avail) = (size(fs.blocks), size(fs.free), size(fs.available));
        let used = total.saturating_sub(free);
        let show = |bytes: u64| if human { human_size(bytes) } else { (bytes / 1024).to_string() };
        let _ = writeln!(out, "{:>12} {:>12} {:>12} {:>12} {:>11}", "Size", "Used", "Avail", "(root)", "%Capacity");
        let _ = writeln!(
            out,
            "{:>12} {:>12} {:>12} {:>12} {:>10}%",
            show(total),
            show(used),
            show(avail),
            show(free),
            percent(used, total)
        );
        Ok(())
    }
}

/// One line of `ls`: the name, or with `-l` the type and mode, the size and
/// the name.
fn entry_line(name: &str, attrs: &FileAttributes, long: bool) -> String {
    if !long {
        return name.to_string();
    }
    let mode = attrs.permissions.unwrap_or(0);
    let kind = if attrs.is_dir() {
        'd'
    } else if attrs.is_regular() {
        '-'
    } else {
        '?'
    };
    let bits: String = (0..9).rev().map(|i| if mode & (1 << i) != 0 { ['x', 'w', 'r'][i % 3] } else { '-' }).collect();
    format!("{kind}{bits} {:>12} {name}", attrs.size.unwrap_or(0))
}

fn percent(part: u64, whole: u64) -> u64 {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

/// A size in the largest unit that keeps it at 1 or more.
fn human_size(bytes: u64) -> String {
    let units = ["B", "K", "M", "G", "T", "P"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}B")
    } else {
        format!("{value:.1}{}", units[unit])
    }
}

/// This user's home here.
fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(PathBuf::from).filter(|p| Path::new(p).is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_line_shows_the_type_the_bits_and_the_size() {
        let attrs = FileAttributes { size: Some(42), permissions: Some(0o100_644), ..FileAttributes::default() };
        assert_eq!(entry_line("f", &attrs, true), format!("-rw-r--r-- {:>12} f", 42));
        assert_eq!(entry_line("f", &attrs, false), "f");
        assert_eq!(human_size(512), "512B");
        assert_eq!(human_size(1536), "1.5K");
        assert_eq!(percent(1, 4), 25);
        assert_eq!(percent(1, 0), 0);
    }
}
