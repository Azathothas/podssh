//! `-B`, `-R` and `-X` of `sftp`, and `-X` of `scp` (T-140): the bytes of
//! each read or write, and the requests in flight, as OpenSSH reads them.
//! podssh then keeps the bytes in flight within the window that it gives a
//! server, and the size within the server's limit.

use podssh_ssh::sftp::Pipeline;

use super::chunks::MOST_TASKS;
use super::meta::Keep;

/// How a copy goes: the requests in flight of each SFTP session (T-140), the
/// files at once of a run (T-297, T-474), the tasks of one file, each with a
/// session of its own (T-141), whether only the changed blocks go (T-142),
/// what it keeps besides the bytes (T-146), whether it writes into the
/// destination itself (T-147), and the mode that a copy up gives the far
/// file (T-149).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub pipe: Pipeline,
    /// The files of a run that go at once, each over an SFTP session of its
    /// own in the one connection. The default keeps one, for `edit`, `job`
    /// and `sftp`'s batch, whose files come one at a time.
    pub files: usize,
    /// The chunks of one file of more than one chunk that go at once: more
    /// than 1 only with `--parallel`.
    pub tasks: usize,
    /// Only the blocks that changed, over an older version (T-142).
    pub delta: bool,
    pub keep: Keep,
    /// `--inplace`: into the destination itself, with no temporary name.
    pub inplace: bool,
    /// The permission bits of the far file after a copy up, in place of the
    /// local source's: `podssh edit` keeps the far file's mode. Set on the
    /// temporary file before the rename, so the name never has another mode.
    pub mode: Option<u32>,
}

impl Default for Shape {
    fn default() -> Self {
        Shape {
            pipe: Pipeline::default(),
            files: 1,
            tasks: 1,
            delta: false,
            keep: Keep::default(),
            inplace: false,
            mode: None,
        }
    }
}

/// The files at once of a run over SFTP when the command line gives no
/// `--parallel` (T-474): through the relay each small file waits for its
/// own round trips, so one at a time takes their sum. Each file holds an
/// SFTP session and, for its far digest, an exec channel beside it, so 4
/// files hold 8 channels at most, within the 10 sessions that OpenSSH's
/// sshd opens on one connection by default (`MaxSessions`); with more, the
/// digests of some fall back to a second read.
pub const FILES_AT_ONCE: usize = 4;

// Several at once, and each file's two channels within OpenSSH's 10.
const _: () = assert!(FILES_AT_ONCE >= 2 && 2 * FILES_AT_ONCE <= 10);

/// The tasks of `--parallel K`: 1 to [`MOST_TASKS`].
pub fn tasks(text: Option<&str>) -> Result<usize, String> {
    let Some(text) = text else { return Ok(1) };
    match text.trim().parse::<usize>() {
        Ok(n) if (1..=MOST_TASKS).contains(&n) => Ok(n),
        _ => Err(format!("--parallel {text}: give 1 to {MOST_TASKS} tasks")),
    }
}

/// The files at once and the chunks of one file, from `--parallel K` (T-474):
/// K each when it is given, so `--parallel 1` copies one at a time; else
/// [`FILES_AT_ONCE`] files, and a large file in one stream, as no
/// measurement through the live relay shows that chunks gain by default.
pub fn at_once(text: Option<&str>) -> Result<(usize, usize), String> {
    match text {
        None => Ok((FILES_AT_ONCE, 1)),
        Some(_) => tasks(text).map(|k| (k, k)),
    }
}

/// The largest buffer that OpenSSH takes (`-X buffer=`).
const MOST: u64 = 256 * 1024;

/// A size: a number, with K, M or G for 1024, 1024² or 1024³, as OpenSSH's
/// `scan_scaled` reads it.
fn size(text: &str) -> Option<u64> {
    let text = text.trim();
    let last = text.chars().last()?;
    let (digits, scale) = match last.to_ascii_uppercase() {
        'K' => (&text[..text.len() - 1], 1u64 << 10),
        'M' => (&text[..text.len() - 1], 1 << 20),
        'G' => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(scale)
}

/// The size of `-B`, or of `-X buffer=`; `shown` is the flag as typed.
fn buffer(shown: &str, text: &str) -> Result<u32, String> {
    match size(text) {
        Some(n) if (1..=MOST).contains(&n) => Ok(n as u32),
        _ => Err(format!("{shown}: the buffer is 1 to {MOST} bytes")),
    }
}

/// The count of `-R`, or of `-X nrequests=`; `shown` is the flag as typed.
fn requests(shown: &str, text: &str) -> Result<usize, String> {
    match text.trim().parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(format!("{shown}: give one request or more")),
    }
}

/// The pipeline of `-B BYTES`, `-R COUNT` and each `-X NAME=VALUE`, which
/// come after them; the last of each wins.
pub fn pipeline(
    given_buffer: Option<&str>,
    given_requests: Option<&str>,
    options: &[String],
) -> Result<Pipeline, String> {
    let mut pipe = Pipeline::default();
    if let Some(text) = given_buffer {
        pipe.len = buffer(&format!("-B {text}"), text)?;
    }
    if let Some(text) = given_requests {
        pipe.requests = requests(&format!("-R {text}"), text)?;
    }
    for option in options {
        match option.split_once('=') {
            Some(("buffer", text)) => pipe.len = buffer(&format!("-X {option}"), text)?,
            Some(("nrequests", text)) => pipe.requests = requests(&format!("-X {option}"), text)?,
            _ => return Err(format!("-X {option}: the options are buffer=BYTES and nrequests=COUNT")),
        }
    }
    Ok(pipe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_counts_read_as_openssh_reads_them() {
        assert_eq!(pipeline(None, None, &[]), Ok(Pipeline::default()));
        let pipe = pipeline(Some("65536"), Some("8"), &[]).unwrap();
        assert_eq!((pipe.len, pipe.requests), (65536, 8));
        let pipe = pipeline(None, None, &["buffer=128k".into(), "nrequests=4".into()]).unwrap();
        assert_eq!((pipe.len, pipe.requests), (128 * 1024, 4));
        // -X comes after -B and -R, and the last wins.
        let options = ["buffer=32K".to_string(), "buffer=16k".to_string()];
        assert_eq!(pipeline(Some("1024"), None, &options).unwrap().len, 16 * 1024);
        assert_eq!(pipeline(Some("256K"), None, &[]).unwrap().len, 256 * 1024);
    }

    #[test]
    fn the_tasks_are_one_to_sixteen() {
        assert_eq!(tasks(None), Ok(1));
        assert_eq!(tasks(Some("4")), Ok(4));
        assert_eq!(tasks(Some("16")), Ok(16));
        assert_eq!(tasks(Some("0")), Err("--parallel 0: give 1 to 16 tasks".into()));
        assert!(tasks(Some("17")).is_err());
        assert!(tasks(Some("x")).is_err());
    }

    #[test]
    fn with_no_parallel_files_go_at_once_and_a_large_file_in_one_stream() {
        assert_eq!(at_once(None), Ok((FILES_AT_ONCE, 1)));
        assert_eq!(at_once(Some("1")), Ok((1, 1)), "the user chose one at a time");
        assert_eq!(at_once(Some("8")), Ok((8, 8)));
        assert!(at_once(Some("0")).is_err());
        // The row of --parallel names the default that the code takes.
        let row = crate::flags::CP_FLAGS.iter().find(|r| r.long == "parallel").expect("the row of --parallel");
        assert!(row.help.contains(&format!("with none, {FILES_AT_ONCE} files at once")), "{}", row.help);
        assert_eq!((Shape::default().files, Shape::default().tasks), (1, 1), "edit, job and sftp's batch");
    }

    #[test]
    fn a_size_or_a_count_out_of_range_is_refused_with_its_flag() {
        assert_eq!(pipeline(Some("0"), None, &[]), Err("-B 0: the buffer is 1 to 262144 bytes".into()));
        assert!(pipeline(Some("257K"), None, &[]).unwrap_err().starts_with("-B 257K:"));
        assert!(pipeline(Some("1x"), None, &[]).is_err());
        assert_eq!(pipeline(None, Some("0"), &[]), Err("-R 0: give one request or more".into()));
        assert!(pipeline(None, None, &["nrequests=-1".into()]).unwrap_err().starts_with("-X nrequests=-1:"));
        assert_eq!(
            pipeline(None, None, &["fast".into()]),
            Err("-X fast: the options are buffer=BYTES and nrequests=COUNT".into())
        );
    }
}
