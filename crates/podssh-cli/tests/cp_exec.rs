//! The copy by exec's pure parts (T-135): the probe's script and its parser,
//! the quoting of each path for the far shell, and the marker that drops what
//! a login prints before the data. The exec cases against OpenSSH and
//! Dropbear are in `scripts/interop-cp.sh`.

use podssh_cli::cp::byexec::{after_marker, command, parse_probe, probe_script, Strip, TOOLS};

const MARKER: &str = "podssh-0123456789abcdef";

#[test]
fn the_probe_names_each_tool_and_its_script_fits_in_single_quotes() {
    let script = probe_script(MARKER);
    assert!(!script.contains('\''), "{script}");
    assert!(script.starts_with(&format!("printf \"%s\\n\" {MARKER};")), "{script}");
    for tool in TOOLS {
        assert!(script.contains(tool), "{tool} is not probed: {script}");
    }
}

#[test]
fn the_probe_answer_is_read_after_the_marker_only() {
    let out = format!("Welcome!\ncat\n{MARKER}\ncat\nwc\nmv\nrm\nnot-a-tool\nsha256sum\n");
    let tools = parse_probe(out.as_bytes(), MARKER).expect("the marker came");
    let names: Vec<&str> = tools.iter().map(String::as_str).collect();
    assert_eq!(names, ["cat", "mv", "rm", "sha256sum", "wc"]);
    // No marker: no POSIX sh ran the script, whatever else came.
    assert_eq!(parse_probe(b"cat\nwc\nmv\n", MARKER), None);
    assert_eq!(parse_probe(b"", MARKER), None);
}

#[test]
fn the_marker_may_follow_text_with_no_newline() {
    let out = format!("a banner with no newline{MARKER}\ndata");
    let at = after_marker(out.as_bytes(), MARKER).expect("found");
    assert_eq!(&out.as_bytes()[at..], b"data");
}

#[test]
fn strip_drops_a_banner_and_passes_the_data_unchanged() {
    let mut strip = Strip::new(MARKER);
    let mut data = Vec::new();
    // A banner, the marker split across two pieces, then bytes that look
    // like the marker again: those are data.
    let line = format!("{MARKER}\n");
    let (head, tail) = line.as_bytes().split_at(10);
    for piece in [&b"motd: hello\n"[..], head, tail, b"\x00\xffbinary", line.as_bytes()] {
        data.extend(strip.feed(piece).expect("within the limit"));
    }
    assert!(strip.opened());
    let mut want = b"\x00\xffbinary".to_vec();
    want.extend_from_slice(line.as_bytes());
    assert_eq!(data, want);
}

#[test]
fn strip_refuses_a_stream_with_no_marker() {
    let mut strip = Strip::new(MARKER);
    let mut failed = false;
    for _ in 0..100 {
        if strip.feed(&[b'x'; 1024]).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "64 KiB with no marker must end the step");
    assert!(!strip.opened());
}

#[test]
fn each_path_is_one_quoted_word_for_the_far_shell() {
    let cmd = command("exec cat -- \"$1\"", &["a b", "it's", "-n", "/srv/x"]).expect("each has a word");
    assert_eq!(cmd, r#"sh -c 'exec cat -- "$1"' sh 'a b' 'it'\''s' '-n' '/srv/x'"#);
    for bad in ["a\nb", "a\0b"] {
        assert!(command("exec cat -- \"$1\"", &[bad]).is_err(), "{bad:?} must be refused");
    }
}
