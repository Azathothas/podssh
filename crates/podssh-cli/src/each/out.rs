//! Where the output of `podssh each` goes (T-183). Each host's session
//! hands its bytes to a sink ([`podssh_ssh::io::Sink`]) in place of this
//! process's streams; here they become lines with the host's label, which
//! one writer puts on stdout or stderr whole, so that no line is cut by
//! another host's; or, with `--output-dir`, they go unchanged into the
//! host's files.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// A whole line for the writer: its bytes, and whether it is stderr's.
pub(crate) type Line = (Vec<u8>, bool);

/// A line longer than this is written in pieces of this size, each with its
/// label: a far program with no newline cannot fill this process's memory.
pub const LONGEST_LINE: usize = 64 * 1024;

/// The files of one host in `--output-dir`, made before anything connects.
pub(crate) struct Files {
    pub out: std::fs::File,
    pub err: std::fs::File,
    pub status: PathBuf,
}

/// Where one host's output goes.
pub(crate) enum Place {
    /// Lines that start with `LABEL: `, through the one writer.
    Lines { label: String, to: mpsc::Sender<Line> },
    /// The bytes as they came, in the host's files.
    Files(Files),
}

/// The stem of a host's files: its label, with each byte but a letter, a
/// digit, `.`, `_`, `-` and `@` written as `%XX`, so that no label names a
/// path or another label's file, on any system.
pub fn file_stem(label: &str) -> String {
    let mut stem = String::with_capacity(label.len());
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@') {
            stem.push(char::from(byte));
        } else {
            stem.push_str(&format!("%{byte:02X}"));
        }
    }
    stem
}

/// The files of each host in `dir`, made now, or none with no `dir`: an
/// output and an error file, empty, and no status file, which a host writes
/// at its end. Two labels whose files would be one on a system that ignores
/// case are refused (64); a file that cannot be made is 73.
pub(crate) fn prepare(labels: &[String], dir: Option<&str>) -> Result<Vec<Option<Files>>, Refusal> {
    let Some(dir) = dir else { return Ok(labels.iter().map(|_| None).collect()) };
    let mut stems: Vec<(String, &String)> = Vec::new();
    for label in labels {
        let stem = file_stem(label);
        if let Some((_, other)) = stems.iter().find(|(s, _)| s.eq_ignore_ascii_case(&stem)) {
            return Err(Refusal::usage(format!("--output-dir: {other} and {label} would share their files")));
        }
        stems.push((stem, label));
    }
    let cant = |path: &Path, e: std::io::Error| Refusal {
        message: format!("--output-dir: {}: {e}", path.display()),
        code: sysexits::EX_CANTCREAT,
    };
    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).map_err(|e| cant(dir, e))?;
    let mut files = Vec::new();
    for (stem, _) in stems {
        let path = |ext: &str| dir.join(format!("{stem}.{ext}"));
        let make = |path: PathBuf| std::fs::File::create(&path).map_err(|e| cant(&path, e));
        let status = path("status");
        // A status of an earlier run would name an end that this run did not have.
        match std::fs::remove_file(&status) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(cant(&status, e)),
            _ => {}
        }
        files.push(Some(Files { out: make(path("out"))?, err: make(path("err"))?, status }));
    }
    Ok(files)
}

/// Write each line to stdout or stderr, in the order it came, until each
/// sender is gone. A Windows console gets valid UTF-8 (T-294); after a
/// write to stdout fails, as when its reader went, stdout gets no more.
pub(crate) async fn writer(mut lines: mpsc::Receiver<Line>) {
    let consoles = [podssh_ssh::terminal::is_console(false), podssh_ssh::terminal::is_console(true)];
    let (mut stdout, mut stderr) = (tokio::io::stdout(), tokio::io::stderr());
    let mut gone = false;
    while let Some((bytes, to_stderr)) = lines.recv().await {
        if gone && !to_stderr {
            continue;
        }
        let bytes = if consoles[usize::from(to_stderr)] {
            String::from_utf8_lossy(&bytes).into_owned().into_bytes()
        } else {
            bytes
        };
        let written = if to_stderr { write(&mut stderr, &bytes).await } else { write(&mut stdout, &bytes).await };
        gone |= written.is_err() && !to_stderr;
    }
}

async fn write(to: &mut (impl AsyncWriteExt + Unpin), bytes: &[u8]) -> std::io::Result<()> {
    to.write_all(bytes).await?;
    to.flush().await
}

/// Take the pieces of one host's session until each sender is gone, into
/// its place. A write that fails is said once, and the rest is dropped, so
/// that the session never waits for a place that takes nothing.
pub(crate) async fn drain(mut pieces: mpsc::Receiver<(Vec<u8>, bool)>, place: Place) -> Result<(), String> {
    match place {
        Place::Lines { label, to } => {
            let mut held = [Vec::new(), Vec::new()];
            while let Some((bytes, stderr)) = pieces.recv().await {
                let buffer = &mut held[usize::from(stderr)];
                buffer.extend_from_slice(&bytes);
                for line in whole_lines(buffer) {
                    let _ = to.send((labelled(&label, &line), stderr)).await;
                }
            }
            // A last line with no newline gets one, so that the next line
            // starts with its own label.
            for (stderr, rest) in [(false, &held[0]), (true, &held[1])] {
                if !rest.is_empty() {
                    let _ = to.send((labelled(&label, rest), stderr)).await;
                }
            }
            Ok(())
        }
        Place::Files(files) => {
            let mut out = [tokio::fs::File::from_std(files.out), tokio::fs::File::from_std(files.err)];
            let mut failed: Option<String> = None;
            while let Some((bytes, stderr)) = pieces.recv().await {
                if failed.is_none() {
                    if let Err(e) = write(&mut out[usize::from(stderr)], &bytes).await {
                        failed = Some(format!("its output could not be written: {e}; the rest is dropped"));
                    }
                }
            }
            failed.map_or(Ok(()), Err)
        }
    }
}

/// Each whole line at the start of `buffer`, its newline kept, taken out of
/// it; and a piece of [`LONGEST_LINE`] bytes of a line that has no end yet.
pub fn whole_lines(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    loop {
        match buffer.iter().position(|b| *b == b'\n') {
            Some(end) if end < LONGEST_LINE => lines.push(buffer.drain(..=end).collect()),
            _ if buffer.len() >= LONGEST_LINE => lines.push(buffer.drain(..LONGEST_LINE).collect()),
            _ => return lines,
        }
    }
}

/// `LABEL: ` and the line, which ends with a newline.
fn labelled(label: &str, line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 2 + line.len() + 1);
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(line);
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

/// Write `code` and a newline to a host's status file.
pub(crate) async fn status(path: &Path, code: i32) -> Result<(), String> {
    tokio::fs::write(path, format!("{code}\n"))
        .await
        .map_err(|e| format!("{}: its status could not be written: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_gives_one_file_name_on_any_system() {
        assert_eq!(file_stem("web1.example.org"), "web1.example.org");
        assert_eq!(file_stem("podtest@127.0.0.1:2201"), "podtest@127.0.0.1%3A2201");
        assert_eq!(file_stem("[2001:db8::1]:22"), "%5B2001%3Adb8%3A%3A1%5D%3A22");
        assert_eq!(file_stem("a/b\\c%"), "a%2Fb%5Cc%25");
    }

    #[test]
    fn lines_are_whole_and_a_long_one_comes_in_pieces() {
        let mut buffer = b"one\ntwo\nthr".to_vec();
        assert_eq!(whole_lines(&mut buffer), [b"one\n".to_vec(), b"two\n".to_vec()]);
        assert_eq!(buffer, b"thr");
        let mut long = vec![b'x'; LONGEST_LINE + 3];
        let pieces = whole_lines(&mut long);
        assert_eq!((pieces.len(), pieces[0].len(), long.len()), (1, LONGEST_LINE, 3));
        assert_eq!(labelled("web1", b"rest"), b"web1: rest\n");
        assert_eq!(labelled("web1", b"line\n"), b"web1: line\n");
    }
}
