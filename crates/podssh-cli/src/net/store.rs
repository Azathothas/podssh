//! Where this host keeps the net's document (T-429), and the one rule by
//! which it takes a new one: the owner's signature, a serial higher than the
//! one held, and an end still to come. The file `net.doc` of the cache, or
//! the file of `PODSSH_NET`; `PODSSH_NET=no` turns the net off, so that no
//! name, admission or document of the channel comes from it. The file is
//! replaced whole, so that a node that reads it for each session never sees
//! half of one.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use podssh_relay::cache::{self, Others};

use super::sign::{self, Signed};

/// The variable that names the file, or turns the net off.
pub const ENV: &str = "PODSSH_NET";
/// The file's name in the cache's directories.
pub const FILE: &str = "net.doc";

/// Where the document is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// `PODSSH_NET=no`.
    Off,
    /// `net.doc` in the first of the cache's directories that has it.
    Cache,
    /// The file that `PODSSH_NET` names.
    File(PathBuf),
}

/// `PODSSH_NET`, read: unset, empty or `yes` is the cache; `no` is off; an
/// absolute path is that file; anything else is a fault of the setting.
pub fn place() -> Result<Place, String> {
    place_of(std::env::var_os(ENV).as_deref().map(|v| v.to_string_lossy().into_owned()).as_deref())
}

fn place_of(value: Option<&str>) -> Result<Place, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(Place::Cache),
        Some(word) if word.eq_ignore_ascii_case("yes") => Ok(Place::Cache),
        Some(word) if word.eq_ignore_ascii_case("no") => Ok(Place::Off),
        Some(path) if Path::new(path).is_absolute() => Ok(Place::File(PathBuf::from(path))),
        Some(_) => Err(format!("{ENV}: no, yes, or the absolute path of the net's document")),
    }
}

/// Whether the net is on: off with `PODSSH_NET=no`, or a setting that is
/// wrong, which the commands of the net say.
pub fn on() -> bool {
    !matches!(place(), Ok(Place::Off) | Err(_))
}

/// The document held, and its file; checked as each member checks one.
#[derive(Debug, Clone)]
pub struct Held {
    pub signed: Signed,
    pub path: PathBuf,
}

/// The document held: `Ok(None)` when there is none, or the net is off.
pub fn held() -> Result<Option<Held>, String> {
    let place = place()?;
    let Some((path, text)) = read(&place)? else { return Ok(None) };
    let signed = sign::verify_signed(text.as_bytes()).map_err(|why| format!("{}: {why}", path.display()))?;
    Ok(Some(Held { signed, path }))
}

/// The document held, or none: for an end that reads the net beside its
/// own work, where a fault of the net's file must not stop that work. The
/// fault is the caller's to say, when it says anything.
pub fn held_or_none() -> Option<Held> {
    held().ok().flatten()
}

/// The text of the document's file, and its path.
fn read(place: &Place) -> Result<Option<(PathBuf, String)>, String> {
    match place {
        Place::Off => Ok(None),
        // Others may read a named file, which holds public keys only; nobody
        // else may change it, as an allowlist is read.
        Place::File(path) => Ok(cache::read_own(path, Others::Read)?.map(|text| (path.clone(), text))),
        Place::Cache => {
            for dir in cache::candidate_dirs() {
                let path = dir.join(FILE);
                if let Some(text) = cache::read_own(&path, Others::Read)? {
                    return Ok(Some((path, text)));
                }
            }
            Ok(None)
        }
    }
}

/// One writer at a time in this process: the sessions of a node may each
/// bring a document.
static WRITING: Mutex<()> = Mutex::new(());

/// Keep `signed` in place of the document held.
fn write(place: &Place, signed: &Signed) -> Result<PathBuf, String> {
    let body = signed.to_bytes();
    match place {
        Place::Off => Err(format!("{ENV}=no: the net is off, and its document is kept nowhere")),
        Place::Cache => cache::store_file(FILE, &body),
        Place::File(path) => replace(path, &body),
    }
}

/// `path` replaced whole by `body`: a private file beside it, then a rename.
fn replace(path: &Path, body: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;
    let shown = path.display();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = cache::create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{shown}: {e}"));
    }
    Ok(path.to_path_buf())
}

/// What a document offered to this host came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// Kept, in this file, in place of the serial before (none: the first).
    Kept { path: PathBuf, before: Option<u64> },
    /// This host holds it already.
    Same,
}

/// Why a document is not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotTaken {
    /// A document of another owner than the one held: never taken.
    OtherOwner(String),
    /// A serial that is not higher than the one held.
    Older { offered: u64, held: u64 },
    /// It ended at this time.
    Expired(i64),
    /// The first document, of an owner that `--owner` does not name: its
    /// owner, and the key of `--owner`.
    NotNamed { owner: String, named: String },
    /// The signature, the form, or the place: why.
    Bad(String),
}

impl std::fmt::Display for NotTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotTaken::OtherOwner(owner) => {
                write!(f, "it is the net of the owner {owner}, not of the owner of the net held here")
            }
            NotTaken::Older { offered, held } => {
                write!(f, "its serial {offered} is not higher than {held}, the serial held here")
            }
            NotTaken::Expired(at) => write!(f, "it ended at {}", crate::pairs::utc(at * 1000)),
            NotTaken::NotNamed { owner, named } => write!(f, "its owner is {owner}, and --owner names {named}"),
            NotTaken::Bad(why) => f.write_str(why),
        }
    }
}

/// Take `signed` in place of the document held, by the rule: the owner of
/// the one held (or, for the first, of `--owner` when named), a higher
/// serial, an end still to come. `now` is in seconds since 1970.
pub fn take(signed: &Signed, owner: Option<&podssh_relay::identity::KeyName>, now: i64) -> Result<Taken, NotTaken> {
    let place = place().map_err(NotTaken::Bad)?;
    let _one = WRITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let offered = &signed.doc;
    if offered.expires <= now {
        return Err(NotTaken::Expired(offered.expires));
    }
    let shown = sign::owner_fingerprint(&offered.owner);
    let held = held().map_err(NotTaken::Bad)?;
    let before = match &held {
        Some(held) => {
            let mine = &held.signed;
            if mine.owner_id() != signed.owner_id() {
                return Err(NotTaken::OtherOwner(shown));
            }
            if mine.bytes == signed.bytes {
                return Ok(Taken::Same);
            }
            if offered.serial <= mine.doc.serial {
                return Err(NotTaken::Older { offered: offered.serial, held: mine.doc.serial });
            }
            Some(mine.doc.serial)
        }
        None => {
            if let Some(named) = owner.filter(|named| named.fingerprint() != shown) {
                return Err(NotTaken::NotNamed { owner: shown, named: named.fingerprint() });
            }
            None
        }
    };
    let path = write(&place, signed).map_err(NotTaken::Bad)?;
    Ok(Taken::Kept { path, before })
}

/// Keep a document that the owner signed here, in place of the one held:
/// its serial follows the held one's, as [`super::doc::Doc::next`] made it.
pub fn keep_own(signed: &Signed) -> Result<PathBuf, String> {
    let place = place()?;
    let _one = WRITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(held) = held()? {
        if held.signed.owner_id() != signed.owner_id() {
            return Err(format!("{} holds the net of another owner", held.path.display()));
        }
        if held.signed.doc.serial >= signed.doc.serial {
            return Err(format!(
                "{} holds the serial {} already: another change came first; run the command again",
                held.path.display(),
                held.signed.doc.serial
            ));
        }
    }
    write(&place, signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_names_the_place_or_turns_the_net_off() {
        assert_eq!(place_of(None), Ok(Place::Cache));
        assert_eq!(place_of(Some("")), Ok(Place::Cache));
        assert_eq!(place_of(Some("YES")), Ok(Place::Cache));
        assert_eq!(place_of(Some("no")), Ok(Place::Off));
        let absolute = if cfg!(windows) { "C:\\net\\doc" } else { "/net/doc" };
        assert_eq!(place_of(Some(absolute)), Ok(Place::File(PathBuf::from(absolute))));
        assert!(place_of(Some("relative/doc")).is_err(), "a relative path follows each run's directory");
    }
}
