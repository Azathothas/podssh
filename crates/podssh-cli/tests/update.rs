//! `podssh update` against a stand-in release on the loopback (T-375): a
//! release signed by the test's own Sigstore and served by a TLS server of
//! the test's own CA, as GitHub serves one. The newest release replaces a
//! binary, which then runs; a planted sum, a planted signature, a leaf of
//! another tag, issuer or time, and a release with no binary of this target
//! are each refused, the old binary left as it was; the API's refusal sends
//! the update to the feed; `--check` writes nothing; and the newest release
//! of this build is nothing to do. The new binary runs once before it takes
//! the old one's place, and the old one is kept, which `--rollback` puts
//! back (T-396, `update_keep`).

mod update_keep;
mod update_support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_cli::update::fetch::Fetcher;
use podssh_cli::update::release::Version;
use podssh_cli::update::{asset, trial, update, Failure, Options};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use update_support::{hex, Answer, Leaf, Server, Sigstore, REPO};

const OLD: &[u8] = b"the old binary\n";
const TAG: &str = "v1.0.0-beta.3";

struct Stand {
    server: Server,
    sigstore: Sigstore,
    dir: PathBuf,
    exe: PathBuf,
    name: String,
}

impl Stand {
    async fn new(name: &str) -> Stand {
        let dir = std::env::temp_dir().join(format!("podssh-update-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let exe = dir.join("bin").join(if cfg!(windows) { "podssh.exe" } else { "podssh" });
        std::fs::write(&exe, OLD).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let target = podssh_cli::update::target().expect("a target of the release");
        Stand { server: Server::start(&dir).await, sigstore: Sigstore::new(), dir, exe, name: asset(target) }
    }

    fn options(&self, current: &str) -> Options {
        Options {
            repo: REPO.into(),
            api: self.server.url(),
            web: self.server.url(),
            fetcher: Fetcher {
                trust: Trust::File(self.server.ca_file.clone()),
                proxy: ProxyChoice::Direct,
                timeout: Duration::from_secs(20),
            },
            roots: self.sigstore.roots.clone(),
            exe: self.exe.clone(),
            target: podssh_cli::update::target().unwrap().into(),
            current: Version::parse(current).unwrap(),
            trial: if cfg!(windows) { says_its_version } else { trial::by_version },
        }
    }

    fn sums_of(&self, binary: &[u8]) -> Vec<u8> {
        let other = "0".repeat(64);
        format!("{}  {}\n{other}  podssh-another-target\n", hex(&Sha256::digest(binary)), self.name).into_bytes()
    }

    /// The release `tag` of `binary`, with `sums` signed as `leaf` says;
    /// the binary behind a redirect to a signed URL, as GitHub's assets are.
    fn release(&self, tag: &str, binary: &[u8], sums: Vec<u8>, leaf: &Leaf<'_>) {
        let bundle = self.sigstore.bundle(&sums, leaf);
        let base = format!("/{REPO}/releases/download/{tag}");
        self.server.body(&format!("{base}/SHA256SUMS"), sums);
        self.server.body(&format!("{base}/SHA256SUMS.sigstore.json"), bundle);
        let signed = format!("/assets/{}?sig=s3cret", self.name);
        self.server.route(&format!("{base}/{}", self.name), Answer::Redirect(format!("{}{signed}", self.server.url())));
        self.server.body(&signed, binary.to_vec());
    }

    fn list(&self, tags: &[&str]) {
        let list: Vec<serde_json::Value> = tags
            .iter()
            .map(|t| serde_json::json!({"tag_name": t, "draft": false, "prerelease": t.contains('-')}))
            .collect();
        self.server.body(&format!("/repos/{REPO}/releases?per_page=20"), serde_json::to_vec(&list).unwrap());
    }

    fn binary_asked(&self) -> bool {
        self.server.was_asked(&format!("/assets/{}?sig=s3cret", self.name))
    }

    /// The old binary as it was, and nothing beside it.
    fn assert_untouched(&self) {
        assert_eq!(std::fs::read(&self.exe).unwrap(), OLD);
        let left: Vec<_> =
            std::fs::read_dir(self.exe.parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 1, "{left:?}");
    }
}

impl Drop for Stand {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn run(opts: &Options, check: bool, asked: Option<&str>) -> (Result<(), Failure>, String) {
    let asked = asked.map(|t| Version::of_tag(t).unwrap());
    let mut out = Vec::new();
    let result = update(opts, check, asked.as_ref(), &mut out).await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn refused(result: Result<(), Failure>) -> String {
    match result {
        Err(Failure::Refused(why)) => why,
        other => panic!("refused, not {other:?}"),
    }
}

/// The trial of the new binary on Windows, where no small program of the
/// test's own runs: it says the release's version. The real trial runs on
/// each system in `update_keep`, on the podssh of this build.
fn says_its_version(_: &Path, want: &Version) -> Result<String, String> {
    Ok(format!("podssh {want}"))
}

/// A release's binary that passes the trial of TAG: on Unix a script that
/// answers `--version` as podssh does; on Windows, where the trial is
/// `says_its_version`, any bytes.
fn release_binary() -> Vec<u8> {
    if cfg!(windows) {
        b"a binary of the release".to_vec()
    } else {
        update_keep::script("1.0.0-beta.3", "podssh stand-in")
    }
}

/// A small file that runs, and what it prints: on Unix a script that
/// answers `--version` as the release's binary would, padded to 1 MiB so
/// that it crosses many records of TLS (the shell stops at its `exit`); on
/// Windows the system's `whoami.exe`. A release's own binary replaced and
/// ran in the live run of T-375 (`docs/STATUS.md`); here, in a debug build,
/// its 100 MB cross the stand-in's TLS in a minute.
fn runnable() -> (Vec<u8>, &'static str) {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        (std::fs::read(Path::new(&root).join("System32").join("whoami.exe")).unwrap(), "\\")
    } else {
        let mut script = update_keep::script("1.0.0-beta.3", "podssh stand-in");
        while script.len() < 1 << 20 {
            script.extend_from_slice(b"# a line of the release that the shell never reads\n");
        }
        (script, "podssh stand-in")
    }
}

/// What `exe` prints, again while another test's child still holds the new
/// file open between its fork and its exec (ETXTBSY).
fn output_of(exe: &Path) -> String {
    for _ in 0..50 {
        match std::process::Command::new(exe).output() {
            Err(e) if e.raw_os_error() == Some(26) => std::thread::sleep(Duration::from_millis(100)),
            Ok(out) => return String::from_utf8_lossy(&out.stdout).into_owned(),
            Err(e) => panic!("{}: {e}", exe.display()),
        }
    }
    panic!("{} stayed busy", exe.display())
}

#[tokio::test]
async fn the_newest_release_replaces_the_binary_which_then_runs() {
    let stand = Stand::new("replace").await;
    let (binary, prints) = runnable();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    stand.list(&["v1.0.0-beta.2", TAG, "v0.9.0", "nightly"]);
    let (result, out) = run(&stand.options("1.0.0-beta.2"), false, None).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains("the newest release, a prerelease too: v1.0.0-beta.3 (from GitHub's API)"), "{out}");
    assert!(out.contains("logged by Rekor at"), "{out}");
    assert!(out.contains("replaced; it is podssh 1.0.0-beta.3 now"), "{out}");
    // T-396: it ran first, and the binary before it is kept.
    assert!(out.contains("it ran here, and said podssh 1.0.0-beta.3"), "{out}");
    assert!(out.contains("podssh update --rollback puts it back"), "{out}");
    assert!(!out.contains("s3cret"), "a signed URL's query is shown: {out}");
    assert!(stand.binary_asked());
    assert!(std::fs::read(&stand.exe).unwrap() == binary, "the file is not the release's binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&stand.exe).unwrap().permissions().mode() & 0o777, 0o755);
    }
    let left = std::fs::read_dir(stand.exe.parent().unwrap()).unwrap().count();
    assert_eq!(left, 2, "only the binary, and the one before it");
    let prev = podssh_cli::update::keep::prev_of(&stand.exe);
    assert_eq!(std::fs::read(&prev).unwrap(), OLD, "{}", prev.display());
    let printed = output_of(&stand.exe);
    assert!(printed.contains(prints), "{printed:?}");
}

#[tokio::test]
async fn a_planted_sum_is_refused_and_the_old_binary_stays() {
    let stand = Stand::new("sum").await;
    // SHA256SUMS signed as it should be, its line of this target another
    // binary's: the binary served is not the one that it names.
    stand.release(TAG, b"a binary of the release", stand.sums_of(b"another binary"), &Leaf::of_tag(TAG));
    let (result, out) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
    let why = refused(result);
    assert!(
        why.contains(&format!("{} of {TAG}: its SHA-256 is", stand.name)) && why.contains("nothing was replaced"),
        "{why}"
    );
    assert!(!out.contains("replaced;"), "{out}");
    stand.assert_untouched();
}

#[tokio::test]
async fn a_planted_signature_is_refused_before_the_binary_comes() {
    let stand = Stand::new("signature").await;
    let binary = b"a binary of the release".to_vec();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    // SHA256SUMS changed after it was signed.
    let mut planted = stand.sums_of(&binary);
    planted[0] = if planted[0] == b'0' { b'1' } else { b'0' };
    stand.server.body(&format!("/{REPO}/releases/download/{TAG}/SHA256SUMS"), planted);
    let why = refused(run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await.0);
    assert!(why.contains("the bundle signs another file") && why.contains("download the release by hand"), "{why}");
    assert!(!stand.binary_asked(), "the binary came before its check");
    stand.assert_untouched();
}

#[tokio::test]
async fn a_leaf_of_another_tag_issuer_time_or_use_is_refused() {
    let stand = Stand::new("leaf").await;
    let binary = b"a binary of the release".to_vec();
    let mut other_tag = Leaf::of_tag("v1.0.0-beta.2");
    let mut other_issuer = Leaf::of_tag(TAG);
    other_issuer.issuer = "https://accounts.google.com";
    let mut past = Leaf::of_tag(TAG);
    past.years = Some((2020, 2021));
    let mut no_code_signing = Leaf::of_tag(TAG);
    no_code_signing.code_signing = false;
    other_tag.code_signing = true;
    for (leaf, says) in [
        (other_tag, "not https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/v1.0.0-beta.3"),
        (other_issuer, "the leaf's token came from"),
        (past, "did not hold when the entry was logged"),
        (no_code_signing, "not for code signing"),
    ] {
        stand.release(TAG, &binary, stand.sums_of(&binary), &leaf);
        let why = refused(run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await.0);
        assert!(why.contains(says), "{says}: {why}");
        stand.assert_untouched();
    }
    // A leaf of another Fulcio, logged by this Rekor.
    let sums = stand.sums_of(&binary);
    stand.release(TAG, &binary, sums.clone(), &Leaf::of_tag(TAG));
    let bundle = stand.sigstore.other_fulcio().bundle(&sums, &Leaf::of_tag(TAG));
    stand.server.body(&format!("/{REPO}/releases/download/{TAG}/SHA256SUMS.sigstore.json"), bundle);
    let why = refused(run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await.0);
    assert!(why.contains("'s signature by") && why.contains("test-sigstore-intermediate"), "{why}");
    stand.assert_untouched();
    // Another Sigstore's bundle, by the roots of this one.
    let other = Sigstore::new();
    let sums = stand.sums_of(&binary);
    stand.release(TAG, &binary, sums.clone(), &Leaf::of_tag(TAG));
    stand.server.body(
        &format!("/{REPO}/releases/download/{TAG}/SHA256SUMS.sigstore.json"),
        other.bundle(&sums, &Leaf::of_tag(TAG)),
    );
    let why = refused(run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await.0);
    assert!(why.contains("a log whose key is not compiled in"), "{why}");
    assert!(!stand.binary_asked());
    stand.assert_untouched();
}

#[tokio::test]
async fn a_release_with_no_binary_of_this_target_is_refused() {
    let stand = Stand::new("target").await;
    let sums = format!("{}  podssh-another-target\n", "0".repeat(64)).into_bytes();
    stand.release(TAG, b"another target's binary", sums, &Leaf::of_tag(TAG));
    let (result, _) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
    match result {
        Err(failure @ Failure::Unavailable(_)) => {
            assert!(failure.why().contains(&format!("{TAG} has no {}", stand.name)), "{failure:?}");
            assert_eq!(failure.code(), 69);
        }
        other => panic!("unavailable, not {other:?}"),
    }
    assert!(!stand.binary_asked());
    stand.assert_untouched();
}

#[tokio::test]
async fn the_feed_answers_when_the_api_refuses() {
    let stand = Stand::new("feed").await;
    let binary = release_binary();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    stand.server.route(&format!("/repos/{REPO}/releases?per_page=20"), Answer::Status(403));
    let feed = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\">\
         <entry><link rel=\"alternate\" type=\"text/html\" href=\"https://github.com/{REPO}/releases/tag/{TAG}\"/></entry>\
         <entry><link rel=\"alternate\" type=\"text/html\" href=\"https://github.com/{REPO}/releases/tag/v1.0.0-beta.2\"/></entry></feed>"
    );
    stand.server.body(&format!("/{REPO}/releases.atom"), feed.into_bytes());
    let (result, out) = run(&stand.options("1.0.0-beta.2"), false, None).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains("v1.0.0-beta.3 (from the releases' feed)"), "{out}");
    assert_eq!(std::fs::read(&stand.exe).unwrap(), binary);
}

#[tokio::test]
async fn check_checks_the_signature_and_writes_nothing() {
    let stand = Stand::new("check").await;
    let binary = b"a binary of the release".to_vec();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    stand.list(&[TAG]);
    let (result, out) = run(&stand.options("1.0.0-beta.2"), true, None).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains(&format!("SHA256SUMS of {TAG}: signed by")), "{out}");
    assert!(
        out.contains(&format!("podssh update would replace {} with {} of {TAG}", stand.exe.display(), stand.name)),
        "{out}"
    );
    assert!(!stand.binary_asked());
    stand.assert_untouched();
}

#[tokio::test]
async fn this_build_s_release_or_a_newer_build_is_nothing_to_do_and_an_old_one_is_asked_for() {
    let stand = Stand::new("nothing").await;
    let binary = release_binary();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    stand.list(&[TAG, "v1.0.0-beta.2"]);
    let (result, out) = run(&stand.options("1.0.0-beta.3"), false, None).await;
    assert!(result.is_ok() && out.contains("podssh 1.0.0-beta.3 is the newest release: nothing to do"), "{out}");
    let (result, out) = run(&stand.options("1.0.0-beta.4"), false, None).await;
    assert!(
        result.is_ok() && out.contains("this build, 1.0.0-beta.4, is newer than v1.0.0-beta.3: nothing to do"),
        "{out}"
    );
    assert!(!stand.server.was_asked(&format!("/{REPO}/releases/download/{TAG}/SHA256SUMS")));
    stand.assert_untouched();
    // A stable build takes no prerelease: before the first release it finds
    // none to follow, which is nothing to do, not a list that failed.
    let (result, out) = run(&stand.options("1.0.0"), false, None).await;
    assert!(
        result.is_ok()
            && out.contains("holds no release (not a prerelease) newer than this build, 1.0.0: nothing to do"),
        "{result:?}\n{out}"
    );
    assert!(!stand.server.was_asked(&format!("/{REPO}/releases/download/{TAG}/SHA256SUMS")));
    stand.assert_untouched();
    // No list read at all stays a failure.
    let bare = Stand::new("no-list").await;
    let (result, _) = run(&bare.options("1.0.0"), false, None).await;
    assert!(matches!(&result, Err(Failure::Unavailable(why)) if why.contains("no list of the releases")), "{result:?}");
    // An older release, named.
    let (result, out) = run(&stand.options("1.0.0-beta.4"), false, Some(TAG)).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains("v1.0.0-beta.3 is older than this build, as --version asked"), "{out}");
    assert_eq!(std::fs::read(&stand.exe).unwrap(), binary);
}

#[tokio::test]
async fn a_release_that_is_not_there_and_a_loop_of_redirects_are_unavailable() {
    let stand = Stand::new("missing").await;
    let (result, _) = run(&stand.options("1.0.0-beta.2"), false, Some("v9.9.9")).await;
    assert!(matches!(&result, Err(Failure::Unavailable(why)) if why.contains("not found (HTTP 404)")), "{result:?}");
    stand.server.route(&format!("/{REPO}/releases/download/{TAG}/SHA256SUMS"), Answer::Redirect("/loop".into()));
    stand.server.route("/loop", Answer::Redirect("/loop".into()));
    let (result, _) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
    assert!(matches!(&result, Err(Failure::Unavailable(why)) if why.contains("more than 5 redirects")), "{result:?}");
    stand.assert_untouched();
}
