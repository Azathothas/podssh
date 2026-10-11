//! The scorer of the interop harnesses (T-199) on scripts written here: the
//! ids that a script can print against the baseline with no log, each kind
//! of disagreement planted once, and the result lines of a run's log.

mod common;

use std::path::Path;

use common::Tree;
use podssh_todo::interop::{self, Log};

/// The repository's own harnesses and baseline agree: each run of the tests,
/// on each system, sees a check that is gone, new or renamed, and the gate
/// then scores the logs of the run.
#[test]
fn the_harnesses_of_this_repository_meet_their_baseline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let checked = interop::check(&root);
    let problems: Vec<String> = checked.problems.iter().map(|p| p.to_string()).collect();
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(checked.ids > 300, "{} ids: the harnesses were not read", checked.ids);
}

const SCRIPT: &str = r#"# A harness, as the real ones are written.
. "$HERE/interop-lib.sh"
for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    [ "$port" ] && ok "ssh.exit.${srv%%:*}" "port $port answers" || bad "ssh.exit.${srv%%:*}" "port $port" "$W/err"
done
expect_rc ssh.one "a command's status" 3 "$rc"
case $out in
/dev/pts/*) ok ssh.pty "a pty ($out)" ;;
*) bad ssh.pty "no pty: $out" ;;
esac
cat >"$W/x.sh" <<'EOF'
ok ssh.in_a_heredoc "never read"
EOF
[ -f "$W/pam" ] && expect_rc ssh.pam "PAM" 6 "$rc" || unmet ssh.pam "sshd.pam is not in this image"
"#;

const LIB: &str = r#"# The helpers: each passes the id of its caller on.
ok() { pass=$((pass + 1)); printf 'ok    %s %s\n' "$1" "$2"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s %s\n' "$1" "$2"; return 0; }
unmet() { printf 'env   %s %s\n' "$1" "$2"; }
expect_rc() { if [ "$4" = "$3" ]; then ok "$1" "$2"; else bad "$1" "$2: got $4"; fi; }
"#;

const PTY: &str = r#"def check(name, text, cond, detail=""):
    print(("ok    " if cond else "FAIL  ") + name + " " + text)

check("pty.size", "the window size is sent", True)
check('pty.exit', "the exit status", True)  # a comment: check("pty.not_read")
"#;

const BASELINE: &str = "# The result that each check must give.
support scripts/interop-lib.sh
harness ssh interop 4 scripts/interop.sh
harness pty interop 2 scripts/interop-pty.py
ssh.exit.openssh pass
ssh.exit.dropbear pass
ssh.one pass
ssh.pty pass
ssh.pam env-allowed sshd.pam is in no image of musl
pty.size pass
pty.exit pass
";

fn tree(name: &str) -> Tree {
    let t = Tree::new(&format!("interop-{name}"));
    t.write("scripts/interop.sh", SCRIPT);
    t.write("scripts/interop-lib.sh", LIB);
    t.write("scripts/interop-pty.py", PTY);
    t.write("scripts/interop-baseline.txt", BASELINE);
    t
}

fn problems(t: &Tree) -> Vec<String> {
    interop::check(t.path()).problems.iter().map(|p| p.to_string()).collect()
}

fn one(t: &Tree, want: &str) {
    let p = problems(t);
    assert!(p.iter().any(|p| p.contains(want)), "wanted {want:?} in {p:#?}");
}

#[test]
fn the_scripts_and_the_baseline_agree() {
    let t = tree("agree");
    let checked = interop::check(t.path());
    assert!(checked.problems.is_empty(), "{:#?}", checked.problems);
    assert_eq!(checked.ids, 7, "the loop gives two ids, and the heredoc and the comment none");
}

#[test]
fn a_deleted_check_is_named() {
    let t = tree("deleted");
    t.plant("scripts/interop.sh", "expect_rc ssh.one \"a command's status\" 3 \"$rc\"\n", "");
    one(&t, "ssh.one is printed by no line of scripts/interop.sh");
}

#[test]
fn a_new_check_and_a_new_loop_word_are_named() {
    let t = tree("new");
    t.plant("scripts/interop.sh", "openssh:2201 dropbear:2203", "openssh:2201 dropbear:2203 tiny:2204");
    one(&t, "ssh.exit.tiny is not in scripts/interop-baseline.txt");
}

#[test]
fn a_line_that_prints_only_on_failure_is_refused() {
    let t = tree("failonly");
    t.plant("scripts/interop.sh", "/dev/pts/*) ok ssh.pty \"a pty ($out)\" ;;", "/dev/pts/*) ;;");
    one(&t, "ssh.pty has no line that prints ok");
}

#[test]
fn a_loop_over_words_that_are_not_literal_is_refused() {
    let t = tree("literal");
    t.plant("scripts/interop.sh", "for srv in openssh:2201 dropbear:2203; do", "for srv in $SERVERS; do");
    one(&t, "is not literal");
}

#[test]
fn an_id_with_another_dollar_is_refused() {
    let t = tree("dollar");
    t.plant("scripts/interop.sh", "ok ssh.pty \"a pty", "ok \"ssh.pty.$out\" \"a pty");
    one(&t, "names a `$` that is not ${NAME}");
}

#[test]
fn the_baseline_is_read_strictly() {
    let t = tree("baseline");
    t.plant(
        "scripts/interop-baseline.txt",
        "ssh.one pass\n",
        "ssh.one pass\nssh.one pass\nSSH.Bad pass\nssh.x maybe\n",
    );
    one(&t, "ssh.one is listed twice");
    one(&t, "\"SSH.Bad\" is not an id");
    one(&t, "not a line of the baseline");
    let t = tree("floor");
    t.plant("scripts/interop-baseline.txt", "harness ssh interop 4", "harness ssh interop 5");
    one(&t, "the floor of ssh is 5, and 4 of its ids must pass");
}

#[test]
fn a_harness_that_the_baseline_does_not_name_is_refused() {
    let t = tree("unnamed");
    t.write("scripts/interop-new.sh", "ok new.one \"x\" || bad new.one \"y\"\n");
    one(&t, "scripts/interop-new.sh: a harness that scripts/interop-baseline.txt does not name");
}

/// A log of the run `interop` with these result lines.
fn log(lines: &[&str]) -> Log {
    Log { shown: "interop.log".into(), run: "interop".into(), text: lines.join("\n") }
}

const GREEN: &[&str] = &[
    "== servers",
    "ok    ssh.exit.openssh port 2201 answers",
    "ok    ssh.exit.dropbear port 2203 answers",
    "ok    ssh.one a command's status",
    "ok    ssh.pty a pty (/dev/pts/0)",
    "env   ssh.pam sshd.pam is not in this image",
    "ok    pty.size the window size is sent",
    "ok    pty.exit the exit status",
    "interop: 6 passed, 0 failed",
];

fn scored(lines: &[&str]) -> (Vec<String>, Vec<String>) {
    let t = tree("score");
    let checked = interop::check(t.path());
    let (rows, problems) = interop::score(&checked.baseline, &[log(lines)]);
    (rows, problems.iter().map(|p| p.to_string()).collect())
}

#[test]
fn a_green_run_meets_the_baseline_and_gives_its_table() {
    let (rows, problems) = scored(GREEN);
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(rows, ["score ssh 4 0 1 0 0 4", "score pty 2 0 0 0 0 2"]);
}

#[test]
fn each_way_that_a_run_misses_the_baseline_is_named() {
    let swap = |from: &str, to: &str| -> Vec<String> {
        GREEN.iter().map(|l| if *l == from { to.to_string() } else { l.to_string() }).collect()
    };
    let cases: [(Vec<String>, &str); 6] = [
        (
            swap("ok    ssh.one a command's status", "FAIL  ssh.one a command's status: got 1"),
            "ssh.one gave FAIL, where ok is due",
        ),
        (swap("ok    ssh.one a command's status", "env   ssh.one no sshd"), "ssh.one gave env, where ok is due"),
        (swap("ok    ssh.one a command's status", "== nothing"), "ssh.one printed no line"),
        (swap("== servers", "ok    ssh.one again"), "ssh.one printed 2 lines"),
        (swap("== servers", "ok    ssh.typo a check that is not listed"), "ssh.typo is no id of the run interop"),
        (swap("== servers", "ok    a check with no id"), "a result line with no id"),
    ];
    for (lines, want) in cases {
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let (_, problems) = scored(&lines);
        assert!(problems.iter().any(|p| p.contains(want)), "wanted {want:?} in {problems:#?}");
    }
}
