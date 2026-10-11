use super::*;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-record-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn size(cols: u32, rows: u32) -> Size {
    Size { cols, rows, px_width: 0, px_height: 0 }
}

/// The header, then one event of each kind, each a line of JSON.
#[test]
fn asciicast_header_and_events() {
    let dir = scratch("events");
    let path = dir.join("s.cast");
    let mut r = Recorder::start(File::create(&path).unwrap(), size(80, 24), "xterm-256color", 1_700_000_000).unwrap();
    r.output(b"hi\r\n").unwrap();
    r.resize(size(100, 30)).unwrap();
    drop(r);
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        r#"{"version": 2, "width": 80, "height": 24, "timestamp": 1700000000, "env": {"TERM": "xterm-256color"}}"#
    );
    assert!(lines[1].starts_with('[') && lines[1].ends_with(r#", "o", "hi\r\n"]"#), "{}", lines[1]);
    assert!(lines[2].ends_with(r#", "r", "100x30"]"#), "{}", lines[2]);
    assert_eq!(lines.len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Quotes, backslashes and each control byte are escaped as JSON escapes
/// them; other text, multibyte too, goes as it is.
#[test]
fn asciicast_escapes_quotes_and_control_bytes() {
    assert_eq!(json_string("a\"b\\c"), r#""a\"b\\c""#);
    assert_eq!(json_string("\n\r\t\u{8}\u{c}"), r#""\n\r\t\b\f""#);
    assert_eq!(json_string("\u{1b}[0m\u{0}\u{7f}"), r#""\u001b[0m\u0000\u007f""#);
    assert_eq!(json_string("é→😀"), "\"é→😀\"");
}

/// A character split across two reads is written whole with the second; a
/// byte that begins no character is replaced; a character that never ends
/// is replaced at the end.
#[test]
fn asciicast_keeps_a_character_split_across_two_reads() {
    let mut pending = Vec::new();
    let smile = "😀".as_bytes();
    assert_eq!(decode(&mut pending, &[b'a', smile[0], smile[1]]), "a");
    assert_eq!(pending, &smile[..2]);
    assert_eq!(decode(&mut pending, &[smile[2], smile[3], b'b']), "😀b");
    assert!(pending.is_empty());
    assert_eq!(decode(&mut pending, &[0xff, b'c']), "\u{fffd}c");

    let dir = scratch("split");
    let path = dir.join("s.cast");
    let mut r = Recorder::start(File::create(&path).unwrap(), size(80, 24), "dumb", 0).unwrap();
    r.output(&smile[..1]).unwrap();
    drop(r);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.lines().nth(1).unwrap().ends_with("\"o\", \"\u{fffd}\"]"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file goes to the first session alone.
#[test]
fn asciicast_target_is_taken_once() {
    let dir = scratch("target");
    let target = Target::new(File::create(dir.join("s.cast")).unwrap());
    let copy = target.clone();
    assert!(copy.take().is_some());
    assert!(target.take().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
