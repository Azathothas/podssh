//! The keys of the broadcast in a Windows console (T-185), typed into a
//! pseudo console where podssh runs (`conpty_harness`): Ctrl-Break, the
//! emergency stop, which the console turns into CTRL_BREAK_EVENT and at
//! which it drops the line that is half typed; and Ctrl-C, which goes to no
//! host. A pseudo console takes Ctrl-Break as a key of the win32 input mode
//! (VK_CANCEL with Ctrl), as Windows Terminal sends it: there is no byte for
//! it.

use super::*;
use crate::conpty_harness::Console;

/// Ctrl-Break down and up, as `ESC [ Vk ; Sc ; Uc ; Kd ; Cs ; Rc _`:
/// VK_CANCEL (3), the scan code of Break (70), no character, and the left
/// Ctrl key (8).
const CTRL_BREAK: &[u8] = b"\x1b[3;70;0;1;8;1_\x1b[3;70;0;0;8;1_";

/// A command line of `words`, each quoted when it holds a space.
fn line(words: &[String]) -> String {
    let quoted: Vec<String> =
        words.iter().map(|w| if w.contains(' ') { format!("\"{w}\"") } else { w.clone() }).collect();
    quoted.join(" ")
}

/// The Prove's planted defect, the stop ignored, fails here: no word comes,
/// and the line after the stop reaches the hosts.
#[test]
fn interactive_ctrl_break_in_a_console_stops_the_broadcast() {
    let home = scratch("broadcast-console");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut words = vec![env!("CARGO_BIN_EXE_podssh").to_string()];
    words.extend(super::words(&home, &[], &[&a, &b]));
    let home_text = home.display().to_string();
    let changes = [
        ("PODSSH_SSH_CONFIG", Some("none")),
        ("PODSSH_SETTINGS", Some("none")),
        ("HOME", Some(home_text.as_str())),
        ("USERPROFILE", Some(home_text.as_str())),
        ("PODSSH_OFFLINE", None),
        ("HTTPS_PROXY", None),
        ("ALL_PROXY", None),
        ("SSH_AUTH_SOCK", None),
    ];
    let mut console = Console::start(&line(&words), &changes, 30, 160);
    console.send(b"echo go\r");
    for host in [&a, &b] {
        assert!(console.expect(&format!("{host}: go"), LIMIT), "the console: {:?}", console.text());
    }
    console.send(format!("touch {}", at("half")).as_bytes());
    console.send(CTRL_BREAK);
    assert!(console.expect("broadcast stopped; :all starts it again", LIMIT), "the console: {:?}", console.text());
    console.send(format!("touch {}\r", at("nowhere")).as_bytes());
    console.send(b"\x03");
    assert!(console.expect("Ctrl-C goes to no host", LIMIT), "the console: {:?}", console.text());
    console.send(format!(":all\rtouch {}\r", at("after")).as_bytes());
    assert!(until(LIMIT, || left(&home, "after", "a") && left(&home, "after", "b")), "{:?}", console.text());
    console.send(b"\x1a");
    assert_eq!(console.wait(LIMIT), Some(0), "the console: {:?}", console.text());
    assert!(!left(&home, "half", "a") && !left(&home, "half", "b"), "the half line went out: {:?}", console.text());
    assert!(!left(&home, "nowhere", "a") && !left(&home, "nowhere", "b"), "a line after the stop went out");
}
