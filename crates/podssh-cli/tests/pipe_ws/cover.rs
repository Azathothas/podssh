//! `ws-listen:` with `--cover DIR` (T-639, GitHub #137), beside the tests
//! of its upgrade: a visit gets a file of DIR, `index.html` for `/`, a HEAD
//! its head alone, and 404 for a path that names none, also for one that
//! climbs out of DIR by `..`, by an escape or by a link; nothing outside DIR
//! is ever sent. Another method gets 405, an upgrade keeps each refusal,
//! and the first client whose upgrade is good still opens the other side.
//! The flag is for `ws-listen:` alone, and its DIR must be a directory (64).

use super::*;

const HOME: &str = "<!doctype html><title>covered</title><p>nothing to see here</p>\n";
const SECRET: &str = "a secret outside the cover\n";

/// A scratch site, removed at the end: DIR with its index page and a page,
/// a secret beside DIR, and on Unix a link in DIR to the secret.
struct Site {
    top: std::path::PathBuf,
    dir: String,
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.top);
    }
}

fn site(name: &str) -> Site {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let top = std::env::temp_dir().join(format!("podssh-pipe-cover-{name}-{}-{nanos}", std::process::id()));
    let dir = top.join("site");
    std::fs::create_dir_all(dir.join("notes")).unwrap();
    std::fs::write(dir.join("index.html"), HOME).unwrap();
    std::fs::write(dir.join("notes/plain.txt"), "plain\n").unwrap();
    std::fs::write(top.join("secret.txt"), SECRET).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(top.join("secret.txt"), dir.join("out")).unwrap();
    Site { dir: dir.display().to_string(), top }
}

/// `text` to `at`, and the whole answer: its head, then what came until the
/// listener closed the connection.
fn whole(at: &str, text: &str) -> String {
    let (mut stream, head) = asked(at, text);
    let mut body = Vec::new();
    let _ = stream.read_to_end(&mut body);
    format!("{head}{}", String::from_utf8_lossy(&body))
}

/// A listener of `--cover`, with the echo target as its other side: the
/// process, its stderr, and its address.
fn covered(site: &Site) -> (Running, Arc<Mutex<Vec<u8>>>, String) {
    let other = format!("tcp:127.0.0.1:{}", echo_target());
    let mut server = spawn(podssh(&["ws-listen:127.0.0.1:0", &other, "--cover", &site.dir]));
    let err = collect(server.0.stderr.take().unwrap());
    let at = listening_at(&err);
    (server, err, at)
}

#[test]
fn a_covered_ws_listen_serves_its_pages_and_the_first_good_upgrade_still_opens_the_other_side() {
    let site = site("pages");
    let (_server, err, at) = covered(&site);
    let home = whole(&at, "GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n");
    assert!(home.starts_with("HTTP/1.1 200 OK\r\n"), "{home}");
    assert!(home.contains("Content-Type: text/html; charset=utf-8\r\n"), "{home}");
    assert!(home.ends_with(&format!("\r\n\r\n{HOME}")), "{home}");
    let head = whole(&at, "HEAD /?from=a.test HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(head.contains(&format!("Content-Length: {}\r\n", HOME.len())) && head.ends_with("\r\n\r\n"), "{head}");
    let plain = whole(&at, "GET /notes/plain.txt HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(plain.contains("Content-Type: text/plain; charset=utf-8\r\n"), "{plain}");
    assert!(plain.ends_with("\r\n\r\nplain\n"), "{plain}");
    // A missing page, a directory with no index, and four ways out of DIR.
    for path in
        ["/nothing.html", "/notes/", "/../secret.txt", "/%2e%2e/secret.txt", "/notes/..%2f..%2fsecret.txt", "/out"]
    {
        let answer = whole(&at, &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"), "{path}: {answer}");
        assert!(!answer.contains("secret") && !answer.contains("nothing to see"), "{path}: {answer}");
    }
    wait_for(&err, "GET /nothing.html: the cover answered 404", "the line of a visit");
    // Each visit was no session: this upgrade is the listener's one client.
    let (mut stream, head) = asked(&at, &upgrade(""));
    let accept = format!("Sec-WebSocket-Accept: {ACCEPT}\r\n");
    assert!(head.starts_with("HTTP/1.1 101 ") && head.contains(&accept), "{head}");
    let masked = Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"past the cover".to_vec() };
    stream.write_all(&frame::encode(&masked, Role::Client, [1, 2, 3, 4])).unwrap();
    let (mut buf, mut echoed) = (Vec::new(), Vec::new());
    while echoed.len() < 14 {
        echoed.extend(server_frame(&mut stream, &mut buf).payload);
    }
    assert_eq!(echoed, b"past the cover");
}

#[test]
fn a_post_to_the_cover_gets_405_and_an_upgrade_keeps_its_refusals() {
    let site = site("refusals");
    let (_server, _err, at) = covered(&site);
    let post = whole(&at, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert!(post.starts_with("HTTP/1.1 405 Method Not Allowed: ") && post.contains("Allow: GET, HEAD\r\n"), "{post}");
    assert!(!post.contains("nothing to see"), "no page for a POST: {post}");
    assert!(whole(&at, "GET / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 400 "), "HTTP/1.1 names its Host");
    let (_, head) = asked(&at, &upgrade("Origin: https://page.example\r\n"));
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    let (_, head) = asked(&at, &upgrade("").replace("Version: 13", "Version: 8"));
    assert!(head.starts_with("HTTP/1.1 426 ") && head.contains("Sec-WebSocket-Version: 13\r\n"), "{head}");
    let (_, head) = asked(&at, &upgrade("").replace(KEY, "c2hvcnQ="));
    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
}

#[test]
fn cover_is_for_ws_listen_alone_and_its_dir_is_a_directory() {
    let site = site("flag");
    let file = format!("{}/index.html", site.dir);
    let runs = [
        (["tcp-listen:127.0.0.1:0", "tcp:127.0.0.1:9", "--cover", site.dir.as_str()], "--cover is for ws-listen:"),
        (["ws-listen:127.0.0.1:0", "tcp:127.0.0.1:9", "--cover", "/no/such/podssh/cover"], "--cover /no/such"),
        (["ws-listen:127.0.0.1:0", "tcp:127.0.0.1:9", "--cover", file.as_str()], "not a directory"),
    ];
    for (args, want) in runs {
        let mut child = spawn(podssh(&args));
        let err = collect(child.0.stderr.take().unwrap());
        assert_eq!(ended(&mut child.0, "podssh"), 64, "{args:?}: {}", text(&err));
        wait_for(&err, want, "the refusal");
        assert!(!text(&err).contains("listening on"), "nothing listens: {}", text(&err));
    }
}
