//! The list of `podssh containers` (T-190), with nothing that connects: the
//! script that the far host runs, the parse of what it prints, the check of
//! each name, and the command that enters a container. The far tools are
//! probed by the script (`command -v`), never assumed.

use podssh_ssh::exec;

use crate::ssh::args::SshArgs;

/// A tool that lists containers, in the order that the script asks them: a
/// name that two of them list is taken from the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Docker,
    Podman,
    Kubectl,
}

impl Tool {
    pub const ALL: [Tool; 3] = [Tool::Docker, Tool::Podman, Tool::Kubectl];

    /// The program's name on the far `PATH`.
    pub fn name(self) -> &'static str {
        match self {
            Tool::Docker => "docker",
            Tool::Podman => "podman",
            Tool::Kubectl => "kubectl",
        }
    }

    pub fn parse(word: &str) -> Option<Tool> {
        Tool::ALL.into_iter().find(|t| t.name() == word)
    }
}

/// The first word of each line of the script's own: no name of a container
/// holds a blank, and each of these lines does.
pub const MARK: &str = "podssh-containers";

/// How long kubectl may wait for each answer of its cluster.
const KUBECTL_WAIT: &str = "20s";

/// The longest name that podssh takes: a Kubernetes name has 253 bytes.
const NAME_MAX: usize = 253;

/// The script for `tools`, in their order. For each tool on the far `PATH`:
/// a line `MARK TOOL` on stdout and on stderr, its list on stdout and its
/// errors on stderr, then `MARK end TOOL STATUS`; and `MARK done` at the
/// end, so that a list that was cut is known. One line with no `'`, for the
/// `sh -c '...'` of [`command`].
pub fn script(tools: &[Tool]) -> String {
    let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    format!(
        "for t in {}; do command -v \"$t\" >/dev/null 2>&1 || continue; \
         printf \"%s %s\\n\" {MARK} \"$t\"; printf \"%s %s\\n\" {MARK} \"$t\" >&2; \
         if [ \"$t\" = kubectl ]; then kubectl get pods -o name --request-timeout={KUBECTL_WAIT} </dev/null; \
         else \"$t\" ps --format \"{{{{.Names}}}}\" </dev/null; fi; \
         printf \"%s end %s %s\\n\" {MARK} \"$t\" \"$?\"; done; printf \"%s done\\n\" {MARK}",
        names.join(" ")
    )
}

/// The command for the login shell: `sh -c 'SCRIPT'`, so that a login
/// shell that is not POSIX (csh, fish) only starts `sh`.
pub fn command(tools: &[Tool]) -> String {
    let script = script(tools);
    debug_assert!(!script.contains('\''), "the script goes inside single quotes");
    format!("sh -c '{script}'")
}

/// What one tool gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub tool: Tool,
    /// Each name that it listed and podssh takes, in its order.
    pub names: Vec<String>,
    /// Each line of its list that is no name that podssh takes, made safe
    /// for a terminal.
    pub refused: Vec<String>,
    /// Its exit status, once its end came; `None` when the list was cut.
    pub status: Option<i32>,
    /// What it wrote on stderr, each line made safe for a terminal.
    pub errors: Vec<String>,
}

impl Listed {
    fn new(tool: Tool) -> Self {
        Listed { tool, names: Vec::new(), refused: Vec::new(), status: None, errors: Vec::new() }
    }

    /// Whether the tool gave its whole list.
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// What the script printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// Each tool that the far `PATH` has, in the script's order.
    pub tools: Vec<Listed>,
    /// Whether the script ran to its end: its last line came.
    pub whole: bool,
}

impl Listing {
    /// A line of the script's own, after `MARK `.
    fn marked(&mut self, rest: &str) {
        match rest.split(' ').collect::<Vec<_>>().as_slice() {
            ["done"] => self.whole = true,
            ["end", tool, status] => {
                let tool = Tool::parse(tool);
                if let Some(listed) = self.tools.iter_mut().rev().find(|t| Some(t.tool) == tool) {
                    // A status that is no number is no success.
                    listed.status = Some(status.parse().unwrap_or(255));
                }
            }
            [tool] => self.tools.extend(Tool::parse(tool).map(Listed::new)),
            _ => {}
        }
    }
}

/// The listing in what the script wrote. Text before the first mark is the
/// login's own (a start-up file, a banner), and is dropped.
pub fn parse(stdout: &[u8], stderr: &[u8]) -> Listing {
    let mut listing = Listing::default();
    for line in String::from_utf8_lossy(stdout).lines().map(|l| l.trim_end_matches('\r')) {
        if let Some(rest) = line.strip_prefix(MARK).and_then(|r| r.strip_prefix(' ')) {
            listing.marked(rest);
            continue;
        }
        // A tool's list ends at its end line.
        let Some(listed) = listing.tools.last_mut().filter(|t| t.status.is_none()) else { continue };
        if line.trim().is_empty() {
            continue;
        }
        if valid_name(listed.tool, line) {
            listed.names.push(line.to_string());
        } else {
            listed.refused.push(podssh_ws::text::one_line(line));
        }
    }
    let mut current: Option<usize> = None;
    for line in String::from_utf8_lossy(stderr).lines() {
        let line = line.trim_end_matches('\r');
        if let Some(tool) = line.strip_prefix(MARK).and_then(|r| r.strip_prefix(' ')).and_then(Tool::parse) {
            current = listing.tools.iter().rposition(|t| t.tool == tool);
            continue;
        }
        let said = podssh_ws::text::one_line(line);
        if let (Some(at), false) = (current, said.is_empty()) {
            listing.tools[at].errors.push(said);
        }
    }
    listing
}

/// Whether `name` is one that podssh takes from `tool` and passes to a far
/// shell: letters, digits, `_`, `.` and `-`, with a letter or a digit
/// first, as Docker, Podman and Kubernetes name them; with `pod/` first for
/// kubectl, which names its pods so. Such a word means the same to each
/// shell, so no quoting of it can be wrong.
pub fn valid_name(tool: Tool, name: &str) -> bool {
    match tool {
        Tool::Kubectl => name.strip_prefix("pod/").is_some_and(plain_name),
        Tool::Docker | Tool::Podman => plain_name(name),
    }
}

fn plain_name(name: &str) -> bool {
    name.len() <= NAME_MAX
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The value of `--exec`: a name of [`valid_name`], `pod/` first or not.
pub fn check_name(name: &str) -> Result<(), String> {
    if plain_name(name.strip_prefix("pod/").unwrap_or(name)) {
        return Ok(());
    }
    Err(format!(
        "--exec {name:?}: a container's name has letters, digits, _, . and - alone, a letter or a digit first; \
         pod/ may come before a pod's"
    ))
}

/// The value of `--shell`: one program, as `sh`, `bash` or `/bin/ash`.
pub fn check_shell(shell: &str) -> Result<(), String> {
    let fits = !shell.is_empty()
        && !shell.starts_with('-')
        && shell.len() <= 255
        && shell.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'));
    if fits {
        return Ok(());
    }
    Err(format!("--shell {shell:?}: one program, of letters, digits, _, ., - and /, as sh or /bin/bash"))
}

/// The tools whose whole list holds `name`, in the script's order, each with
/// the name as it listed it: kubectl's with `pod/` first.
pub fn holders<'a>(listing: &'a Listing, name: &str) -> Vec<(&'a Listed, String)> {
    let mut out = Vec::new();
    for listed in listing.tools.iter().filter(|t| t.ok()) {
        let full = match listed.tool {
            Tool::Kubectl if !name.starts_with("pod/") => format!("pod/{name}"),
            _ => name.to_string(),
        };
        if listed.names.contains(&full) {
            out.push((listed, full));
        }
    }
    out
}

/// The command that enters `name` of `tool` with `shell`: `-it` with a pty,
/// else `-i`, as docker refuses `-t` when its input is no terminal.
pub fn enter(tool: Tool, name: &str, shell: &str, pty: bool) -> Vec<String> {
    let mut words = vec![tool.name(), "exec", if pty { "-it" } else { "-i" }, name];
    if tool == Tool::Kubectl {
        words.push("--");
    }
    words.push(shell);
    words.into_iter().map(word).collect()
}

/// `text` as one word of a shell: as it is when each character is plain,
/// else in single quotes ([`exec::shell_word`]); a word with a newline,
/// which no quoting carries, in Rust's debug form, for a person to read.
pub fn word(text: &str) -> String {
    let plain = !text.is_empty()
        && !text.starts_with(['=', '~'])
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:@+,=-".contains(&b));
    if plain {
        return text.to_string();
    }
    exec::shell_word(text).unwrap_or_else(|| format!("{text:?}"))
}

/// The connection flags of `ssh` as the user gave them, for the command that
/// a line of the list shows.
pub fn flags(ssh: &SshArgs) -> Vec<String> {
    let mut out = Vec::new();
    for (flag, value) in [("-p", &ssh.port), ("-l", &ssh.login)] {
        if let Some(value) = value {
            pair(&mut out, flag, value);
        }
    }
    for file in &ssh.identity_files {
        pair(&mut out, "-i", file);
    }
    for option in &ssh.options {
        pair(&mut out, "-o", option);
    }
    let named = [
        ("-F", &ssh.config),
        ("-J", &ssh.jump),
        ("--relay-host", &ssh.relay_host),
        ("--relay-failover", &ssh.relay_failover),
        ("--relay-addr", &ssh.relay_addr),
        ("--ca-file", &ssh.ca_file),
    ];
    for (flag, value) in named {
        if let Some(value) = value {
            pair(&mut out, flag, value);
        }
    }
    if ssh.direct {
        out.push("--direct".to_string());
    }
    out
}

fn pair(out: &mut Vec<String>, flag: &str, value: &str) {
    out.push(flag.to_string());
    out.push(word(value));
}

/// The line of one container: its tool, its name, and the command that
/// enters it, padded so that the names line up.
pub fn line(tool: Tool, name: &str, width: usize, command: &str) -> String {
    format!("{:<7}  {name:<width$}  {command}", tool.name())
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod tests;
