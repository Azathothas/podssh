//! The pages of `--cover` (T-639): what a path may name under DIR, and what
//! it may never open.

use super::*;

/// A scratch tree, removed at the end: DIR with its index page, a directory
/// with a page and no index, one with its own index, a dot file; and a
/// secret beside DIR, outside it.
struct Tree {
    top: PathBuf,
    cover: Cover,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.top);
    }
}

fn tree(name: &str) -> Tree {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let top = std::env::temp_dir().join(format!("podssh-cover-{name}-{}-{nanos}", std::process::id()));
    let root = top.join("site");
    std::fs::create_dir_all(root.join("bare")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("index.html"), "<h1>home</h1>\n").unwrap();
    std::fs::write(root.join("bare/page.txt"), "a page\n").unwrap();
    std::fs::write(root.join("docs/index.html"), "<h1>docs</h1>\n").unwrap();
    std::fs::write(root.join(".env"), "TOKEN=x\n").unwrap();
    std::fs::write(top.join("secret.txt"), "outside\n").unwrap();
    let cover = Cover::open(root.to_str().unwrap()).unwrap();
    Tree { top, cover }
}

/// The text of the page that `target` names, when one is served.
fn found(tree: &Tree, target: &str) -> Option<String> {
    find(&tree.cover.root, target).map(|(_, body)| String::from_utf8(body).unwrap())
}

#[test]
fn a_path_above_the_root_is_never_opened() {
    let tree = tree("above");
    for target in [
        "/../secret.txt",
        "/bare/../../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E%2Fsecret.txt",
        "/..%2fsecret.txt",
        "/bare/..%5c..%5csecret.txt",
        "/./index.html",
        "/.env",
        "/%2eenv",
        "/a%00b",
        "/%zz",
        "/%2",
        "/%+f",
        "/%c0%ae%c0%ae/secret.txt",
        "/C:%5csecret.txt",
        "http://x/../secret.txt",
        "*",
        "",
    ] {
        assert_eq!(found(&tree, target), None, "{target:?}");
    }
    // Empty parts name nothing: this is DIR/etc/passwd, which is not there.
    assert_eq!(found(&tree, "//etc/passwd"), None);
}

#[test]
fn a_directory_is_served_by_its_index_page_and_not_listed() {
    let tree = tree("index");
    for (target, page) in [
        ("/", "<h1>home</h1>\n"),
        ("/index.html", "<h1>home</h1>\n"),
        ("/?q=1", "<h1>home</h1>\n"),
        ("/docs", "<h1>docs</h1>\n"),
        ("/docs/", "<h1>docs</h1>\n"),
        ("//docs//index.html", "<h1>docs</h1>\n"),
        ("/bare/page.txt", "a page\n"),
        ("/bare/page%2Etxt#top", "a page\n"),
    ] {
        assert_eq!(found(&tree, target).as_deref(), Some(page), "{target:?}");
    }
    for target in ["/bare", "/bare/", "/missing.html", "/bare/missing.txt"] {
        assert_eq!(found(&tree, target), None, "a directory with no index, or no file: {target:?}");
    }
    assert_eq!(find(&tree.cover.root, "/").unwrap().0, "text/html; charset=utf-8");
    assert_eq!(find(&tree.cover.root, "/bare/page.txt").unwrap().0, "text/plain; charset=utf-8");
    assert_eq!(kind_of(Path::new("a/b.WASM")), "application/wasm");
    assert_eq!(kind_of(Path::new("a/b")), "application/octet-stream");
}

/// A link in DIR whose target is out of DIR is refused, also as a
/// directory's index page; one whose target is in DIR is served.
#[cfg(unix)]
#[test]
fn a_link_out_of_the_directory_is_never_followed() {
    let tree = tree("link");
    let root = tree.cover.root.clone();
    std::os::unix::fs::symlink(tree.top.join("secret.txt"), root.join("out")).unwrap();
    std::os::unix::fs::symlink(&tree.top, root.join("up")).unwrap();
    std::fs::create_dir(root.join("trap")).unwrap();
    std::os::unix::fs::symlink(tree.top.join("secret.txt"), root.join("trap/index.html")).unwrap();
    std::os::unix::fs::symlink("bare/page.txt", root.join("inner")).unwrap();
    for target in ["/out", "/up/secret.txt", "/trap", "/trap/", "/trap/index.html"] {
        assert_eq!(found(&tree, target), None, "{target:?} leads out of DIR");
    }
    assert_eq!(found(&tree, "/inner").as_deref(), Some("a page\n"), "a link inside DIR");
}

#[test]
fn a_file_that_is_no_page_is_not_served() {
    let tree = tree("big");
    let root = tree.cover.root.clone();
    std::fs::write(root.join("big.bin"), vec![7u8; MAX_PAGE as usize + 1]).unwrap();
    std::fs::write(root.join("most.bin"), vec![7u8; MAX_PAGE as usize]).unwrap();
    assert_eq!(found(&tree, "/big.bin"), None, "over 1 MiB");
    assert_eq!(find(&root, "/most.bin").map(|(_, b)| b.len() as u64), Some(MAX_PAGE));
    // A socket in DIR is no regular file; where this host refuses the bind,
    // there is nothing to check.
    #[cfg(unix)]
    if let Ok(_socket) = std::os::unix::net::UnixListener::bind(root.join("sock")) {
        assert_eq!(found(&tree, "/sock"), None, "a socket");
    }
}

#[test]
fn a_cover_that_is_no_directory_is_refused_at_the_start() {
    let tree = tree("start");
    let refused = Cover::open("/no/such/podssh/cover").unwrap_err();
    assert_eq!(refused.code, 64, "{}", refused.message);
    assert!(refused.message.starts_with("--cover /no/such/podssh/cover: "), "{}", refused.message);
    let file = tree.cover.root.join("index.html");
    let refused = Cover::open(file.to_str().unwrap()).unwrap_err();
    assert_eq!((refused.code, refused.message.ends_with(": not a directory")), (64, true), "{}", refused.message);
}

fn parsed(text: &str) -> Request {
    podssh_ws::http::request::parse_request(text.as_bytes()).unwrap()
}

/// GET and HEAD get a page or 404, HEAD with no body; another method 405
/// with the methods that it may use; an HTTP/1.1 request with no Host 400.
#[tokio::test]
async fn a_visit_gets_its_page_or_its_status() {
    let tree = tree("visit");
    let answer = |text: &'static str| {
        let cover = tree.cover.clone();
        async move {
            let (status, bytes) = cover.visit(&parsed(text)).await;
            (status, String::from_utf8(bytes).unwrap())
        }
    };
    let (status, page) = answer("GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
    assert!(status == 200 && page.starts_with("HTTP/1.1 200 OK\r\n") && page.ends_with("\r\n\r\n<h1>home</h1>\n"));
    let (status, head) = answer("HEAD / HTTP/1.1\r\nHost: h\r\n\r\n").await;
    assert!(status == 200 && head.contains("\r\nContent-Length: 14\r\n") && head.ends_with("\r\n\r\n"), "{head}");
    let (status, page) = answer("GET /bare/ HTTP/1.0\r\n\r\n").await;
    assert!(status == 404 && page.starts_with("HTTP/1.1 404 Not Found\r\n"), "{page}");
    assert_eq!(answer("GET / HTTP/1.0\r\n\r\n").await.0, 200, "HTTP/1.0 may name no Host");
    let (status, post) = answer("POST / HTTP/1.1\r\nHost: h\r\n\r\n").await;
    assert!(status == 405 && post.contains("\r\nAllow: GET, HEAD\r\n") && !post.contains("home"), "{post}");
    assert_eq!(answer("GET / HTTP/1.1\r\n\r\n").await.0, 400);
    assert_eq!(shown(&parsed("GET /a/b?token=x HTTP/1.1\r\n\r\n")), "GET /a/b");
}
