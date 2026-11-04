//! `--cover DIR` of `ws-listen:` (T-639, GitHub #137): a request that asks
//! for no upgrade, as a browser's visit, gets a file of DIR in place of the
//! 426 that names the protocol. GET and HEAD alone (405 for another method,
//! with `Allow: GET, HEAD`); a file by the request's path, `index.html` for
//! `/` and for a directory, which is never listed, and 404 when there is
//! none. The path is walked under DIR part by part, each part decoded: `..`,
//! a name that starts with `.`, a separator or a NUL inside a part and a `%`
//! that is no escape give 404; then the file is resolved, links and all, and
//! served only while it is still under DIR, a regular file of 1 MiB at most.
//! A page reaches nothing past DIR: only an upgrade opens the other side.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use podssh_ws::http::request::{self, Request};

use crate::relay_settings::Refusal;

/// The flag, for its refusals.
pub const FLAG: &str = "--cover";
/// The largest file served: a page, not a download, read whole.
pub const MAX_PAGE: u64 = 1024 * 1024;
/// The page of `/` and of a directory.
const INDEX: &str = "index.html";
/// The type of the words of a 404.
const TEXT: &str = "text/plain; charset=utf-8";

/// The directory of `--cover`, resolved once, at the start.
#[derive(Debug, Clone)]
pub struct Cover {
    root: PathBuf,
}

impl Cover {
    /// DIR resolved, or 64 when it is no directory: a typo is said at the
    /// start, not to each visitor.
    pub fn open(dir: &str) -> Result<Cover, Refusal> {
        let root = std::fs::canonicalize(dir).map_err(|e| Refusal::usage(format!("{FLAG} {dir}: {e}")))?;
        if !root.is_dir() {
            return Err(Refusal::usage(format!("{FLAG} {dir}: not a directory")));
        }
        Ok(Cover { root })
    }

    /// The answer to a request that asks for no upgrade: its status, and its
    /// bytes, after which the connection closes.
    pub async fn visit(&self, head: &Request) -> (u16, Vec<u8>) {
        if head.method != "GET" && head.method != "HEAD" {
            let words = "this listener serves GET and HEAD of its pages, and a WebSocket's GET";
            return (405, request::refusal(405, words, &[("Allow", "GET, HEAD")]));
        }
        // A request of HTTP/1.1 names its Host (RFC 9112 section 3.2), as an
        // upgrade's must.
        if head.minor >= 1 && !head.has("host") {
            return (400, request::refusal(400, "a request of HTTP/1.1 names its Host", &[]));
        }
        let (root, target) = (self.root.clone(), head.target.clone());
        // Off the runtime's thread: a slow disk stalls no other client.
        let found = tokio::task::spawn_blocking(move || find(&root, &target)).await.ok().flatten();
        let head_only = head.method == "HEAD";
        match found {
            Some((kind, body)) => (200, request::answer(200, kind, &body, head_only)),
            None => (404, request::answer(404, TEXT, b"no such page here\n", head_only)),
        }
    }
}

/// A visit as its line shows it: the method and the path, cut short, with
/// no query, which may be the visitor's own.
pub fn shown(head: &Request) -> String {
    let path = head.target.split(['?', '#']).next().unwrap_or_default();
    let path: String = path.chars().take(100).collect();
    format!("{} {path}", head.method)
}

/// The type and the bytes of the file that `target` names under `root`,
/// which is resolved; none when there is none, or none that may be served.
fn find(root: &Path, target: &str) -> Option<(&'static str, Vec<u8>)> {
    let mut path = root.to_path_buf();
    path.extend(parts(target)?);
    let mut path = inside(root, &path)?;
    if path.is_dir() {
        // A directory is never listed: its index page, or nothing.
        path = inside(root, &path.join(INDEX))?;
    }
    let body = read_regular(&path)?;
    Some((kind_of(&path), body))
}

/// The parts of a request's path, each percent-decoded; none for a path that
/// could leave DIR or name what is no page: `..` and each name that starts
/// with `.` (`.git`, `.env`), a `/`, `\`, `:` or NUL that an escape put
/// inside a part, a `%` that is no escape, bytes that are not UTF-8, and a
/// target that is no path from `/` (`*`, `http://...`).
fn parts(target: &str) -> Option<Vec<String>> {
    let path = target.split(['?', '#']).next()?.strip_prefix('/')?;
    let mut out = Vec::new();
    for raw in path.split('/').filter(|raw| !raw.is_empty()) {
        let part = decode(raw)?;
        if part.is_empty() || part.starts_with('.') || part.contains(['/', '\\', ':', '\0']) {
            return None;
        }
        out.push(part);
    }
    Some(out)
}

/// `%XX` decoded; none for a `%` that is not two hex digits, or bytes that
/// are not UTF-8.
fn decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let hex = bytes.get(at + 1..at + 3)?;
        // from_str_radix takes a sign too; an escape has two digits alone.
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
        at += 3;
    }
    String::from_utf8(out).ok()
}

/// `path` resolved, its links followed, while it is still under `root`: a
/// link that leads out of DIR is refused, as a `..` is.
fn inside(root: &Path, path: &Path) -> Option<PathBuf> {
    let resolved = std::fs::canonicalize(path).ok()?;
    resolved.starts_with(root).then_some(resolved)
}

/// The bytes of a regular file of [`MAX_PAGE`] at most. Checked by its path
/// first, so that a FIFO or a device is not opened; then opened with no wait
/// and no link followed, and checked again on the handle, so that one put
/// there after the first check is never read.
fn read_regular(path: &Path) -> Option<Vec<u8>> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_PAGE {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_PAGE + 1).read_to_end(&mut body).ok()?;
    // A file that grew since its length was read.
    (body.len() <= MAX_PAGE as usize).then_some(body)
}

/// A file's type by its name; bytes of another name have no type that a
/// browser runs.
fn kind_of(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "txt" | "md" => TEXT,
        "json" => "application/json",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
#[path = "cover_tests.rs"]
mod tests;
