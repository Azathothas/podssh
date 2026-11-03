use super::*;

fn markers() -> Markers {
    Markers { prompt: "podssh-00-password".into(), started: "podssh-00-started".into() }
}

/// The command quotes the user's for the remote shell, and sudo prints the
/// prompt that podssh chose.
#[test]
fn elevate_quotes_the_command() {
    let m = markers();
    assert_eq!(
        command(Elevate::Sudo, "echo 'a b' \"$HOME\"", &m),
        r#"sudo -S -k -p podssh-00-password -- sh -c 'printf %s podssh-00-started >&2; echo '\''a b'\'' "$HOME"'"#
    );
    assert_eq!(command(Elevate::Su, "id -u", &m), "su -c 'printf %s podssh-00-started >&2; id -u'");
    let fresh = (Markers::new(), Markers::new());
    assert_ne!(fresh.0.prompt, fresh.1.prompt, "each run has markers of its own");
    assert!(fresh.0.prompt.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
}

/// sudo: the prompt asks for the password once, a second prompt is a
/// refusal, the start of the command releases the input, and neither marker
/// reaches the output, which goes out as it comes.
#[test]
fn elevate_removes_the_markers_and_asks_once_for_each_prompt() {
    let mut f = Filter::new(Elevate::Sudo, markers());
    assert_eq!(f.feed(b"podssh-00-password", true), (Vec::new(), vec![Event::Ask]));
    assert_eq!(
        f.feed(b"Sorry, try again.\npodssh-00-password", true),
        (b"Sorry, try again.\n".to_vec(), vec![Event::Again])
    );
    assert_eq!(f.feed(b"podssh-00-startedroot\n", true), (b"root\n".to_vec(), vec![Event::Started]));
    assert!(f.started());
    assert_eq!(
        f.feed(b"podssh-00-password", false),
        (b"podssh-00-password".to_vec(), Vec::new()),
        "after the start, as is"
    );
}

/// A NOPASSWD rule: no prompt, so no password; the command starts.
#[test]
fn elevate_sends_no_password_without_a_prompt() {
    let mut f = Filter::new(Elevate::Sudo, markers());
    assert_eq!(f.feed(b"podssh-00-started", true), (Vec::new(), vec![Event::Started]));
    assert_eq!(f.feed(b"0\n", false), (b"0\n".to_vec(), Vec::new()));
}

/// A marker split across two reads is held back, then found; an end that
/// turns out to be no marker is written with the next read, or at the end.
#[test]
fn elevate_finds_a_marker_split_across_two_reads() {
    let mut f = Filter::new(Elevate::Sudo, markers());
    assert_eq!(f.feed(b"lecture\npodssh-00-pa", true), (b"lecture\n".to_vec(), Vec::new()));
    assert_eq!(f.feed(b"ssword", true), (Vec::new(), vec![Event::Ask]));
    assert_eq!(f.feed(b"podssh-0", true), (Vec::new(), Vec::new()));
    assert_eq!(f.feed(b"1 other", true), (b"podssh-01 other".to_vec(), Vec::new()));
    assert_eq!(f.feed(b"podssh-00-sta", true), (Vec::new(), Vec::new()));
    assert_eq!(f.finish(), b"podssh-00-sta".to_vec(), "never started: what was held back");
}

/// su: its prompt is its own output that ends with no newline; that output
/// is dropped once the command starts, and written when it never does.
#[test]
fn elevate_su_asks_at_its_prompt_and_keeps_its_own_output() {
    let mut f = Filter::new(Elevate::Su, markers());
    assert_eq!(f.feed(b"Password: ", false), (Vec::new(), vec![Event::Ask]));
    assert_eq!(f.feed(b"\r\n", false), (Vec::new(), Vec::new()), "asked once");
    assert_eq!(f.feed(b"podssh-00-started0\r\n", false), (b"0\r\n".to_vec(), vec![Event::Started]));
    assert!(f.finish().is_empty(), "su's own output is gone once the command started");

    let mut refused = Filter::new(Elevate::Su, markers());
    assert_eq!(refused.feed(b"Password: ", false).1, vec![Event::Ask]);
    assert_eq!(refused.feed(b"\r\nsu: Authentication failure\r\n", false), (Vec::new(), Vec::new()));
    assert_eq!(refused.finish(), b"Password: \r\nsu: Authentication failure\r\n".to_vec());

    // A line of su's own that ends with a newline is no prompt.
    let mut quiet = Filter::new(Elevate::Su, markers());
    assert_eq!(quiet.feed(b"su: warning\n", false).1, Vec::new());
}

/// su on a pty gets the kill key and the end of file key before the
/// channel's EOF (T-501): the pty's defaults, or the keys of the modes that
/// podssh asked for, never one that the modes turned off. sudo, and a
/// command with no pty, read the channel, whose EOF is enough.
#[test]
fn elevate_ends_su_read_with_the_keys_of_its_pty() {
    assert_eq!(end_keys(Elevate::Su, true, &[]), vec![0x15, 0x04], "the pty's defaults");
    let modes = [(Pty::VINTR, 3), (Pty::VKILL, 0x18), (Pty::VEOF, 0x1a)];
    assert_eq!(end_keys(Elevate::Su, true, &modes), vec![0x18, 0x1a], "the local terminal's keys");
    let off = [(Pty::VKILL, 255), (Pty::VEOF, 0x04)];
    assert_eq!(end_keys(Elevate::Su, true, &off), vec![0x04], "a key turned off is not sent");
    assert_eq!(end_keys(Elevate::Su, false, &[]), Vec::<u8>::new(), "no pty: the EOF reaches su's stdin");
    assert_eq!(end_keys(Elevate::Sudo, true, &modes), Vec::<u8>::new(), "sudo -S reads the channel");
}

/// The lines of a password that was not sent and of a time that ran out
/// name the cause and what podssh did (T-501): a command that asked is
/// never said to have asked nothing.
#[test]
fn elevate_says_why_no_password_went_and_what_did_not_end() {
    let helper = PromptError::Exited("exited 1".into()).to_string();
    assert_eq!(
        unanswered(Elevate::Su, &helper),
        "the password for the remote command: SSH_ASKPASS exited 1, so podssh sends su no password"
    );
    assert_eq!(
        expired_line(Elevate::Su, &Phase::Ended(helper)),
        "su did not end within 30 s after podssh sent it no password: SSH_ASKPASS exited 1"
    );
    assert_eq!(
        expired_line(Elevate::Su, &Phase::Starting),
        "the remote command neither asked for a password nor started within 30 s"
    );
    assert!(expired_line(Elevate::Sudo, &Phase::Sent).starts_with("the remote command asked for a password"));
    assert!(expired_line(Elevate::Sudo, &Phase::Refused).starts_with("sudo refused the password"));
}
