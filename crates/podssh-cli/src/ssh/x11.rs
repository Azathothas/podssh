//! `-X`, `-Y`, `-x` and the keywords of X11 forwarding (T-037), read as
//! OpenSSH reads them, and the probe before the connection: `DISPLAY`, an X
//! server that answers, and a cookie that it takes. `-Y` takes the cookie of
//! the authority file; `-X` an untrusted one that `xauth` makes, and with no
//! `xauth` it is refused, naming `-Y`. A probe that fails ends the run before
//! anything connects (255): the user asked for X11, and would not see why it
//! is missing.

use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_ssh::x11::{self, Display, Forward};
use zeroize::Zeroizing;

use super::args::SshArgs;
use super::options::Settings;

/// What a run asks of X11 forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// `-Y`, or `ForwardX11Trusted`: the X server's own cookie, full access.
    pub trusted: bool,
    /// `ForwardX11Timeout` of `-X`: no new X11 channel after it; `None`
    /// for none (`0`).
    pub timeout: Option<Duration>,
    /// `XAuthLocation`.
    pub xauth: Option<String>,
}

/// The default of `ForwardX11Timeout`, as OpenSSH's: 20 minutes.
pub const TIMEOUT: Duration = Duration::from_secs(1200);

/// The plan of `args` and `settings`: none without `-X`, `-Y` or
/// `ForwardX11`, or with `-x` last.
pub fn plan(args: &SshArgs, settings: &Settings) -> Option<Plan> {
    if !args.forward_x11.or(settings.forward_x11).unwrap_or(false) {
        return None;
    }
    Some(Plan {
        trusted: args.x11_trusted || settings.forward_x11_trusted.unwrap_or(false),
        timeout: match settings.forward_x11_timeout {
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => Some(TIMEOUT),
        },
        xauth: settings.xauth_location.clone(),
    })
}

/// What the probe reads of the process: `DISPLAY`, `XAUTHORITY`, the home,
/// this host's name and `PATH`.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub display: Option<String>,
    pub authority: Option<String>,
    pub home: Option<PathBuf>,
    pub host: Option<String>,
    pub path: Option<std::ffi::OsString>,
}

impl Env {
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Env {
            display: var("DISPLAY"),
            authority: var("XAUTHORITY"),
            home: var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None }).map(PathBuf::from),
            host: super::tokens::local_host_name(),
            path: std::env::var_os("PATH"),
        }
    }
}

/// The probe: the display to forward to, and its cookie.
pub async fn probe(plan: &Plan, env: &Env) -> Result<Forward, String> {
    let text =
        env.display.as_deref().ok_or("X11 forwarding: DISPLAY is not set, so there is no X server to forward to")?;
    let display = Display::parse(text).map_err(|why| format!("X11 forwarding: {why}"))?;
    let host = env.host.as_deref();
    let (cookie, from) = if plan.trusted {
        let file = x11::authority_file(env.authority.as_deref(), env.home.as_deref());
        let cookie =
            file.as_deref().and_then(|f| std::fs::read(f).ok()).and_then(|b| x11::cookie_in(&b, &display, host));
        let from =
            file.map_or_else(|| "no authority file (no XAUTHORITY, no home)".to_string(), |f| f.display().to_string());
        (cookie, from)
    } else {
        (Some(untrusted(text, &display, plan, env).await?), "xauth".to_string())
    };
    let cookie = match cookie {
        Some(cookie) => {
            x11::answers(&display).await.map_err(|why| format!("X11 forwarding: DISPLAY={text}: {why}"))?;
            Some(cookie)
        }
        None => match x11::takes_no_cookie(&display)
            .await
            .map_err(|why| format!("X11 forwarding: DISPLAY={text}: {why}"))?
        {
            true => None,
            false => {
                return Err(format!(
                    "X11 forwarding: no {} cookie for DISPLAY={text} in {from}, and its X server refuses a connection \
                     with none",
                    x11::PROTOCOL
                ))
            }
        },
    };
    let lasts = if plan.trusted { None } else { plan.timeout };
    Ok(Forward::new(display, cookie, lasts))
}

/// `-X`: an untrusted cookie that `xauth` makes for the display, with the
/// time of `ForwardX11Timeout` and a minute more, as OpenSSH asks for it.
async fn untrusted(text: &str, display: &Display, plan: &Plan, env: &Env) -> Result<Zeroizing<Vec<u8>>, String> {
    let xauth = match &plan.xauth {
        Some(path) => Some(PathBuf::from(path)).filter(|p| p.is_file()),
        None => find(env.path.as_deref(), if cfg!(windows) { "xauth.exe" } else { "xauth" }),
    };
    let Some(xauth) = xauth else {
        return Err("X11 forwarding: -X needs an untrusted cookie that xauth makes, and there is no xauth here \
                    (XAuthLocation, PATH); -Y gives the X server's own cookie, with full access"
            .into());
    };
    let dir = std::env::temp_dir().join(format!("podssh-x11-{}", std::process::id()));
    podssh_relay::cache::private_dir(&dir).map_err(|e| format!("X11 forwarding: {}: {e}", dir.display()))?;
    let file = dir.join("xauthfile");
    let seconds = plan.timeout.map_or(0, |t| t.as_secs() + 60).to_string();
    let made = tokio::process::Command::new(&xauth)
        .arg("-f")
        .arg(&file)
        .args(["generate", text, x11::PROTOCOL, "untrusted", "timeout", &seconds])
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    let cookie = std::fs::read(&file).ok().and_then(|bytes| x11::cookie_in(&bytes, display, env.host.as_deref()));
    let _ = std::fs::remove_dir_all(&dir);
    match (made, cookie) {
        (Ok(out), Some(cookie)) if out.status.success() => Ok(cookie),
        (Ok(out), _) => Err(format!(
            "X11 forwarding: {} could not make an untrusted cookie for DISPLAY={text}: {}; -Y gives the X server's \
             own cookie",
            xauth.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        (Err(e), _) => Err(format!("X11 forwarding: {}: {e}", xauth.display())),
    }
}

/// `name` in a directory of `path`.
fn find(path: Option<&std::ffi::OsStr>, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path?).map(|dir| dir.join(name)).find(|p| Path::new(p).is_file())
}
