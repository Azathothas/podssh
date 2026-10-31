//! `podssh update` (T-375): the release for this binary's own target,
//! fetched through the proxy, its `SHA256SUMS` checked against the
//! signature that the release workflow made (`sigstore`), and its binary
//! against that file, then in place of the running one (`replace`). It runs
//! only when asked: no other command looks for a release.

pub mod fetch;
pub mod release;
pub mod replace;
pub mod sigstore;

use std::cmp::Ordering;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_CONFIG, EX_DATAERR, EX_UNAVAILABLE};
use fetch::{FetchError, Fetcher};
use release::Version;

/// The largest list of releases, from the API or the feed: each release's
/// notes are in it, up to 120 kB each.
const MAX_LIST: usize = 8 << 20;
/// The largest `SHA256SUMS` and bundle: a few kB each.
const MAX_SMALL: usize = 256 << 10;
/// The largest binary: a release's is about a tenth of this.
const MAX_BINARY: usize = 256 << 20;
/// Each small file, the connection and its answer.
const SMALL_LIMIT: Duration = Duration::from_secs(60);
/// The binary, on a slow link.
const BINARY_LIMIT: Duration = Duration::from_secs(900);

/// Every value `podssh update` accepts, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArgs {
    pub check: bool,
    pub version: Option<String>,
    pub ca_file: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl UpdateArgs {
    pub fn from_matches(matches: &clap::ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> UpdateArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        UpdateArgs { check: matches.get_flag("check"), version: get("version"), ca_file: get("ca-file"), refused }
    }
}

/// Where the releases are, and what this binary is.
#[derive(Debug, Clone)]
pub struct Options {
    /// `OWNER/REPO` on GitHub.
    pub repo: String,
    /// `https://api.github.com`, or a stand-in's.
    pub api: String,
    /// `https://github.com`, or a stand-in's.
    pub web: String,
    pub fetcher: Fetcher,
    pub roots: sigstore::Roots,
    /// The file that the update replaces.
    pub exe: PathBuf,
    /// The release's name of this build's target.
    pub target: String,
    /// This build's version.
    pub current: Version,
}

/// Why an update stopped, each with its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// GitHub, the release, or one of its files did not come (69).
    Unavailable(String),
    /// A file came and failed its check (65).
    Refused(String),
    /// The binary could not be replaced (73).
    CantWrite(String),
    /// This build has no release to come from (78).
    Config(String),
}

impl Failure {
    pub fn code(&self) -> i32 {
        match self {
            Failure::Unavailable(_) => EX_UNAVAILABLE,
            Failure::Refused(_) => EX_DATAERR,
            Failure::CantWrite(_) => EX_CANTCREAT,
            Failure::Config(_) => EX_CONFIG,
        }
    }

    pub fn why(&self) -> &str {
        match self {
            Failure::Unavailable(why) | Failure::Refused(why) | Failure::CantWrite(why) | Failure::Config(why) => why,
        }
    }
}

/// The release's name of this build's target: the triple of its binary.
/// On Linux the release's binary is static (musl), so it is the one for a
/// build of either libc; a 32-bit ARM build takes the armv7 one, the only
/// one of the release.
pub fn target() -> Option<&'static str> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    Some(match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("linux", "arm") if cfg!(target_abi = "eabihf") => "armv7-unknown-linux-musleabihf",
        ("linux", "riscv64") => "riscv64gc-unknown-linux-musl",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

/// The file of a target's binary in a release.
pub fn asset(target: &str) -> String {
    if target.contains("-windows-") {
        format!("podssh-{target}.exe")
    } else {
        format!("podssh-{target}")
    }
}

/// The SHA-256 that `sums` (a `sha256sum` file) gives `name`.
pub fn sum_for(sums: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(sums).lines().find_map(|line| {
        let (digest, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        let ok = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
        (ok && file == name).then(|| digest.to_ascii_lowercase())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mib(bytes: usize) -> String {
    format!("{:.1} MiB", bytes as f64 / (1 << 20) as f64)
}

impl Options {
    /// This binary, the releases of its repository on GitHub, and Sigstore's
    /// roots; `trust` for TLS to GitHub.
    pub fn of_this_build(trust: Trust) -> Result<Options, Failure> {
        let repository = env!("CARGO_PKG_REPOSITORY");
        let repo = repository
            .strip_prefix("https://github.com/")
            .filter(|r| r.split('/').count() == 2)
            .ok_or_else(|| Failure::Config(format!("this build's repository, {repository}, is not one of GitHub")))?;
        let target = target().ok_or_else(|| {
            Failure::Config(format!(
                "no release has a binary for {} {}: build podssh from its source",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
        })?;
        let current = Version::parse(env!("CARGO_PKG_VERSION"))
            .ok_or_else(|| Failure::Config("this build's version is not one of semver".into()))?;
        Ok(Options {
            repo: repo.to_string(),
            api: "https://api.github.com".into(),
            web: "https://github.com".into(),
            fetcher: Fetcher { trust, proxy: ProxyChoice::FromEnvironment, timeout: Duration::from_secs(30) },
            roots: sigstore::Roots::sigstore(),
            exe: replace::running().map_err(Failure::Config)?,
            target: target.to_string(),
            current,
        })
    }
}

/// A file of the release, or why it did not come.
async fn get(opts: &Options, url: &str, max: usize, limit: Duration) -> Result<Vec<u8>, Failure> {
    opts.fetcher.get(url, "application/octet-stream", max, limit).await.map_err(|e| Failure::Unavailable(e.to_string()))
}

/// A reader of the tags of a list of releases.
type ReadTags = fn(&[u8]) -> Result<Vec<String>, String>;

/// The newest release, and where its tag was read.
async fn newest(opts: &Options) -> Result<(Version, &'static str), Failure> {
    let pre = opts.current.is_prerelease();
    let mut why = Vec::new();
    let api = format!("{}/repos/{}/releases?per_page=20", opts.api, opts.repo);
    let feed = format!("{}/{}/releases.atom", opts.web, opts.repo);
    let sources: [(&str, &str, &str, ReadTags); 2] = [
        (api.as_str(), "application/vnd.github+json", "GitHub's API", release::tags_of_api),
        (feed.as_str(), "application/atom+xml", "the releases' feed", release::tags_of_atom),
    ];
    for (url, accept, name, read) in sources {
        match opts.fetcher.get(url, accept, MAX_LIST, SMALL_LIMIT).await {
            Ok(body) => match read(&body).map(|tags| release::newest(&tags, pre)) {
                Ok(Some(version)) => return Ok((version, name)),
                Ok(None) => why.push(format!("{name} lists no release of a version")),
                Err(e) => why.push(format!("{name}: {e}")),
            },
            Err(FetchError::NotFound(e) | FetchError::Failed(e)) => why.push(e),
        }
    }
    Err(Failure::Unavailable(format!("no list of the releases: {}", why.join("; "))))
}

/// The update: the release that `asked` names, else the newest one; its
/// `SHA256SUMS` and its signature, checked; with `check`, no more; else the
/// binary of this target, checked, in place of `opts.exe`.
pub async fn update(opts: &Options, check: bool, asked: Option<&Version>, out: &mut dyn Write) -> Result<(), Failure> {
    let _ = writeln!(out, "podssh {}, {}: {}", opts.current, opts.target, replace::shown(&opts.exe));
    let version = match asked {
        Some(version) => version.clone(),
        None => {
            let (newest, from) = newest(opts).await?;
            let which = if opts.current.is_prerelease() {
                "the newest release, a prerelease too"
            } else {
                "the newest release"
            };
            let _ = writeln!(out, "{which}: {} (from {from})", newest.tag());
            match newest.cmp(&opts.current) {
                Ordering::Equal => {
                    let _ = writeln!(out, "podssh {} is the newest release: nothing to do", opts.current);
                    return Ok(());
                }
                Ordering::Less => {
                    let _ = writeln!(
                        out,
                        "this build, {}, is newer than {}: nothing to do (--version TAG installs a release)",
                        opts.current,
                        newest.tag()
                    );
                    return Ok(());
                }
                Ordering::Greater => newest,
            }
        }
    };
    if asked.is_some() && version < opts.current {
        let _ = writeln!(out, "{} is older than this build, as --version asked", version.tag());
    }
    let tag = version.tag();
    let base = format!("{}/{}/releases/download/{tag}", opts.web, opts.repo);
    let sums = get(opts, &format!("{base}/SHA256SUMS"), MAX_SMALL, SMALL_LIMIT).await?;
    let bundle = get(opts, &format!("{base}/SHA256SUMS.sigstore.json"), MAX_SMALL, SMALL_LIMIT).await?;
    let who = sigstore::Identity { repo: &opts.repo, tag: &tag };
    let logged = sigstore::verify_with(&bundle, &sums, &who, &opts.roots).map_err(|why| {
        Failure::Refused(format!(
            "the signature of {tag}'s SHA256SUMS: {why}; nothing was replaced. If Sigstore changed its roots, \
             download the release by hand: {}/{}/releases/tag/{tag}",
            opts.web, opts.repo
        ))
    })?;
    let at = crate::doctor::clock::format_utc(logged.time);
    let _ =
        writeln!(out, "SHA256SUMS of {tag}: signed by {}, logged by Rekor at {at} (entry {})", who.uri(), logged.index);
    let name = asset(&opts.target);
    let want = sum_for(&sums, &name)
        .ok_or_else(|| Failure::Unavailable(format!("{tag} has no {name}: its SHA256SUMS names none")))?;
    if cfg!(feature = "ts") {
        let _ = writeln!(out, "this build has the feature ts, which the release's binary has not");
    }
    if check {
        let _ = writeln!(out, "podssh update would replace {} with {name} of {tag}", replace::shown(&opts.exe));
        return Ok(());
    }
    let binary = get(opts, &format!("{base}/{name}"), MAX_BINARY, BINARY_LIMIT).await?;
    let got = hex(&Sha256::digest(&binary));
    if got != want {
        return Err(Failure::Refused(format!(
            "{name} of {tag}: its SHA-256 is {got}, and SHA256SUMS gives {want}; nothing was replaced"
        )));
    }
    let _ = writeln!(out, "{name}: {}, its SHA-256 is the one of SHA256SUMS", mib(binary.len()));
    replace::replace(&opts.exe, &binary)
        .map_err(|why| Failure::CantWrite(format!("{why}; {} is as it was", replace::shown(&opts.exe))))?;
    let _ = writeln!(out, "{}: replaced; it is podssh {version} now", replace::shown(&opts.exe));
    Ok(())
}

/// The trust of TLS to GitHub: `--ca-file`, else `SSL_CERT_FILE`, else the
/// settings file's `CaFile`, else the default, as doctor's.
fn trust(args: &UpdateArgs) -> Trust {
    let cert_env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    match (&args.ca_file, cert_env, &crate::settings::here().ca_file) {
        (Some(file), ..) => Trust::File(file.into()),
        (None, Some(file), _) => Trust::File(file.into()),
        (None, None, Some(value)) => Trust::File(value.text.clone().into()),
        (None, None, None) => Trust::Default,
    }
}

pub fn run(args: &UpdateArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let asked = match args.version.as_deref() {
        None => None,
        Some(text) => match Version::parse(text.strip_prefix('v').unwrap_or(text)) {
            Some(version) => Some(version),
            None => {
                let _ = writeln!(err, "podssh update: --version {text}: the version of a release, as v1.0.0-beta.3");
                return EXIT_USAGE;
            }
        },
    };
    let fail = |failure: Failure, err: &mut dyn Write| {
        let _ = writeln!(err, "podssh update: {}", failure.why());
        failure.code()
    };
    let opts = match Options::of_this_build(trust(args)) {
        Ok(opts) => opts,
        Err(failure) => return fail(failure, err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => return fail(Failure::Config(format!("a runtime: {e}")), err),
    };
    match runtime.block_on(update(&opts, args.check, asked.as_ref(), out)) {
        Ok(()) => 0,
        Err(failure) => fail(failure, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_target_of_the_release_has_its_file() {
        assert_eq!(asset("x86_64-unknown-linux-musl"), "podssh-x86_64-unknown-linux-musl");
        assert_eq!(asset("aarch64-pc-windows-msvc"), "podssh-aarch64-pc-windows-msvc.exe");
        // The build of the tests has a target of the release.
        assert!(target().is_some(), "{} {}", std::env::consts::OS, std::env::consts::ARCH);
    }

    #[test]
    fn a_line_of_sha256sum_gives_its_file_s_digest() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums =
            format!("{a}  podssh-x86_64-unknown-linux-musl\n{b} *podssh-x86_64-pc-windows-msvc.exe\nshort  podssh-x\n");
        assert_eq!(sum_for(sums.as_bytes(), "podssh-x86_64-unknown-linux-musl"), Some(a));
        assert_eq!(sum_for(sums.as_bytes(), "podssh-x86_64-pc-windows-msvc.exe"), Some("b".repeat(64)));
        assert_eq!(sum_for(sums.as_bytes(), "podssh-x"), None);
        assert_eq!(sum_for(sums.as_bytes(), "podssh-aarch64-apple-darwin"), None);
    }

    /// beta.2's own SHA256SUMS names each target of the release.
    #[test]
    fn the_published_sums_name_each_target() {
        let sums = include_bytes!("../../tests/fixtures/update/SHA256SUMS-v1.0.0-beta.2");
        for target in [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "armv7-unknown-linux-musleabihf",
            "riscv64gc-unknown-linux-musl",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
        ] {
            assert!(sum_for(sums, &asset(target)).is_some(), "{target}");
        }
    }
}
