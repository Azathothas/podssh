//! Which agent podssh logs in with (`IdentityAgent`), and which one the
//! destination's server may use (`-A`, `-a` and `ForwardAgent`, T-036), as
//! OpenSSH 10.3p1 reads them.

use std::path::{Path, PathBuf};

use podssh_ssh::Agent;

use super::options::Settings;

/// The `%`, `${NAME}` and `~` expansion of a path; the setting names it in
/// a refusal.
type Expand<'a> = &'a dyn Fn(&str, &str) -> Result<PathBuf, String>;

/// The two agents of a run, and what `-G` prints of them.
#[derive(Debug, Clone)]
pub struct Agents {
    /// The agent that podssh logs in with.
    pub identity: Agent,
    /// The agent that the destination's server may use: `Agent::Off` by
    /// default, as in OpenSSH.
    pub forward: Agent,
    /// Said without `-v` when forwarding was asked for and no agent can be.
    pub warning: Option<String>,
    /// The `identityagent` line of `-G`, when one is printed.
    pub shown_identity: Option<String>,
    /// The `forwardagent` line of `-G`: `no`, `yes`, or the value as given.
    pub shown_forward: String,
}

/// Read `IdentityAgent`, then `-A` and `-a` (the last one, as `flag`) or
/// `ForwardAgent`.
pub fn choose(flag: Option<bool>, settings: &Settings, expand: Expand) -> Result<Agents, String> {
    let (identity, shown_identity) = identity(settings.identity_agent.as_deref(), expand)?;
    let mut agents =
        Agents { identity, forward: Agent::Off, warning: None, shown_identity, shown_forward: "no".into() };
    // The flags win over the keyword, in any order, as in OpenSSH.
    if !flag.or(settings.forward_agent).unwrap_or(false) {
        return Ok(agents);
    }
    let Some(given) = settings.forward_agent_path.as_deref() else {
        // OpenSSH sets SSH_AUTH_SOCK to IdentityAgent, so yes forwards the
        // agent that it logs in with; its -G says yes even with none.
        agents.shown_forward = "yes".into();
        if agents.identity == Agent::Off {
            agents.warning = Some("agent forwarding: IdentityAgent is none, so no agent is forwarded".into());
        } else {
            agents.forward = agents.identity.clone();
        }
        return Ok(agents);
    };
    const SETTING: &str = "-o ForwardAgent=";
    agents.shown_forward = given.to_string();
    match place(SETTING, given, expand)? {
        Some(path) => {
            // OpenSSH's -G prints a path expanded, and a whole $NAME as given.
            if !legacy(given) {
                agents.shown_forward = path.display().to_string();
            }
            // OpenSSH warns too, and the agent may come later.
            if !cfg!(windows) && !Path::new(&path).exists() {
                agents.warning = Some(format!("{SETTING}{given}: there is no agent at {} yet", path.display()));
            }
            agents.forward = Agent::Path(path);
        }
        None => {
            agents.warning = Some(format!("{SETTING}{given}: {} is not set, so no agent is forwarded", &given[1..]))
        }
    }
    Ok(agents)
}

/// `IdentityAgent`: `SSH_AUTH_SOCK` when not given; `none`; `$NAME`, the
/// variable that holds the path (no agent when it is not set, as in
/// OpenSSH); else a path. With the line of `-G`, which keeps `$NAME`.
fn identity(value: Option<&str>, expand: Expand) -> Result<(Agent, Option<String>), String> {
    Ok(match value {
        None | Some("SSH_AUTH_SOCK") => (Agent::FromEnvironment, None),
        Some(v) if v.eq_ignore_ascii_case("none") => (Agent::Off, Some("none".into())),
        Some(v) => {
            let path = place("-o IdentityAgent=", v, expand)?;
            let shown = if legacy(v) {
                v.to_string()
            } else {
                path.as_ref().map_or_else(|| "none".into(), |p| p.display().to_string())
            };
            (path.map_or(Agent::Off, Agent::Path), Some(shown))
        }
    })
}

/// A value that names an agent: `$NAME`, a whole value, is the variable that
/// holds its path, read now (`None` when it is not set or empty); else a
/// path, with `${NAME}`, the `%` tokens and `~` expanded.
fn place(setting: &str, value: &str, expand: Expand) -> Result<Option<PathBuf>, String> {
    if !legacy(value) {
        return expand(setting, value).map(Some);
    }
    let name = &value[1..];
    if !valid_name(name) {
        return Err(format!("{setting}{value}: not the name of a variable (letters, digits and _)"));
    }
    Ok(std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from))
}

/// Whether a value is a whole `$NAME`, OpenSSH's older form of a variable,
/// and not a path that starts with `${NAME}`.
fn legacy(value: &str) -> bool {
    value.starts_with('$') && !value.starts_with("${")
}

/// A variable's name, as OpenSSH's `valid_env_name` takes one.
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
