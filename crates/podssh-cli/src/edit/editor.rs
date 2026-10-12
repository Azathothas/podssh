//! The editor of `podssh edit` (T-149): `VISUAL`, else `EDITOR`, else `vi`
//! when a probe finds it on `PATH`. podssh starts no other program
//! (`AGENTS.md`, rule 3). The editor runs on this terminal with no time
//! limit, as a person decides, and its keys are its own while it runs:
//! SIGINT and SIGQUIT do not end podssh, nor Ctrl-C on Windows.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

/// The names of `vi` that the probe looks for on `PATH`.
#[cfg(windows)]
const VI: &[&str] = &["vi.exe", "vi"];
#[cfg(not(windows))]
const VI: &[&str] = &["vi"];

/// What the choice of an editor reads from the environment.
#[derive(Clone, Debug, Default)]
pub struct EditorEnv {
    pub visual: Option<OsString>,
    pub editor: Option<OsString>,
    /// `vi` on `PATH`, when the probe found it.
    pub vi: Option<PathBuf>,
}

impl EditorEnv {
    pub fn from_process() -> Self {
        EditorEnv {
            visual: std::env::var_os("VISUAL"),
            editor: std::env::var_os("EDITOR"),
            vi: VI.iter().find_map(|name| crate::pager::find_program(name, std::env::var_os("PATH"))),
        }
    }
}

/// The editor to start: its program and its words, and where the choice
/// came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Editor {
    pub words: Vec<OsString>,
    /// `VISUAL`, `EDITOR` or `PATH`, for the messages.
    pub from: &'static str,
}

impl Editor {
    /// The words on one line, for the messages.
    pub fn shown(&self) -> String {
        self.words.iter().map(|w| w.to_string_lossy()).collect::<Vec<_>>().join(" ")
    }
}

/// `VISUAL`, else `EDITOR`, else `vi` on `PATH`. An empty value is no
/// value. With none, the refusal names `EDITOR`.
pub fn choose(env: &EditorEnv) -> Result<Editor, String> {
    for (from, value) in [("VISUAL", &env.visual), ("EDITOR", &env.editor)] {
        let words = value.as_deref().map(words).unwrap_or_default();
        if !words.is_empty() {
            return Ok(Editor { words, from });
        }
    }
    match &env.vi {
        Some(vi) => Ok(Editor { words: vec![vi.clone().into_os_string()], from: "PATH" }),
        None => {
            Err("no editor: set EDITOR to the program of one; neither VISUAL nor EDITOR is set, and PATH has no vi"
                .into())
        }
    }
}

/// The words of a value: the whole value when it names a file (a path with
/// a blank, as Windows has them), else the value split at blanks, as `PAGER`
/// is. No shell reads it.
pub fn words(value: &OsStr) -> Vec<OsString> {
    if Path::new(value).is_file() {
        return vec![value.to_os_string()];
    }
    match value.to_str() {
        Some(text) => text.split_whitespace().map(OsString::from).collect(),
        None => vec![value.to_os_string()],
    }
}

/// Start the editor on `file`, on this terminal, and wait for it for as long
/// as it runs. `Err` only when it did not start.
pub fn run(runtime: &tokio::runtime::Runtime, editor: &Editor, file: &Path) -> std::io::Result<ExitStatus> {
    let Some((program, args)) = editor.words.split_first() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no editor program"));
    };
    let mut child = std::process::Command::new(program).args(args).arg(file).spawn()?;
    // After the start, so that the editor gets the usual actions.
    let _keys = crate::pager::Interrupts::ignore();
    // A listener of Ctrl-C keeps the console's Ctrl-C from ending podssh
    // while the editor reads it.
    #[cfg(windows)]
    let _held = {
        let _in = runtime.enter();
        tokio::signal::windows::ctrl_c().ok()
    };
    #[cfg(not(windows))]
    let _ = runtime;
    child.wait()
}

/// The exit code that an editor's status gives podssh: its own, or 128 + N
/// for signal N, as a shell gives it.
pub fn code_of(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(visual: Option<&str>, editor: Option<&str>, vi: bool) -> EditorEnv {
        EditorEnv {
            visual: visual.map(OsString::from),
            editor: editor.map(OsString::from),
            vi: vi.then(|| PathBuf::from("/usr/bin/vi")),
        }
    }

    #[test]
    fn visual_wins_then_editor_then_vi() {
        let chosen = |e: &EditorEnv| choose(e).map(|c| (c.shown(), c.from));
        assert_eq!(chosen(&env(Some("emacs -nw"), Some("nano"), true)), Ok(("emacs -nw".into(), "VISUAL")));
        assert_eq!(chosen(&env(None, Some("nano"), true)), Ok(("nano".into(), "EDITOR")));
        assert_eq!(chosen(&env(Some(""), Some("nano"), true)), Ok(("nano".into(), "EDITOR")));
        assert_eq!(chosen(&env(Some("  "), Some(""), true)), Ok(("/usr/bin/vi".into(), "PATH")));
        let none = choose(&env(None, None, false)).unwrap_err();
        assert!(none.contains("EDITOR") && none.contains("vi"), "{none}");
    }

    #[test]
    fn a_value_is_split_at_blanks_unless_it_names_a_file() {
        assert_eq!(words(OsStr::new("code --wait")), vec![OsString::from("code"), OsString::from("--wait")]);
        let dir = std::env::temp_dir().join(format!("podssh-editor-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("my editor");
        std::fs::write(&program, b"").unwrap();
        assert_eq!(words(program.as_os_str()), vec![program.clone().into_os_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
