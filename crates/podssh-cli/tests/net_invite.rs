//! The net's invitation by a short code (T-616) from end to end, between two
//! homes, through `podssh relay serve` on the loopback with a certificate
//! of a test CA, its mailbox the meeting point (`--pair-mailbox
//! wss://HOST/v1/mailbox`): the owner's host runs `podssh net invite lab`
//! on a pseudo terminal, which shows the code there; the new device runs
//! `podssh net join`, its code from a pipe with `--owner`, or at a pseudo
//! terminal, where it asks. The new member is in the owner's document with
//! the device's key, and the device holds that document, byte for byte; a
//! wrong code, another owner, a no at the question, and a member's name for
//! another key each add no member, keep the owner's serial, and leave the
//! device with no net. The refusals that come before the network, offline.
//! Planted (`scripts/plants/t616-*.patch`): the owner not checked at the
//! join; a member's name given to another key. A host with no Python or no
//! openssl, for the role's certificate, says that the test did not run.
// Linux alone, as the pseudo terminal of `pty_harness` is Linux's.
#![cfg(target_os = "linux")]

mod pty_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_relay::code::words;
use podssh_relay::identity::Identity;
use pty_harness::Pty;
use throughput_harness::{command_in, without_proxy, Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);
/// What precedes the code on the owner's terminal.
const SHOWN: &str = "valid for 10 minutes: ";
/// What the device asks at its terminal.
const ASKED: &str = "yes or no: ";

/// The relay role of a test: its mailbox's URL and its CA.
struct Role {
    mailbox: String,
    ca: String,
}

/// The role, or `None` when this host cannot make its certificate.
fn role(s: &Session) -> Option<Role> {
    let cell = match Cell::podssh_relay(s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    Some(Role { mailbox: format!("wss://{}/v1/mailbox", at("--relay-host")), ca: at("--ca-file") })
}

/// One home of a test: a private directory, its HOME and cache, and the
/// file of its net's document.
struct Home {
    dir: PathBuf,
    doc: PathBuf,
}

impl Home {
    fn new(s: &Session, name: &str) -> Home {
        let dir = s.home.join(name);
        podssh_relay::cache::private_dir(&dir).unwrap();
        Home { doc: dir.join("net.doc"), dir }
    }

    /// `podssh ARGS` in this home, with no proxy of the machine.
    fn command(&self, args: &[&str]) -> Command {
        let words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
        let mut cmd = without_proxy(command_in(&self.dir, &words));
        cmd.env("PODSSH_NET", &self.doc).env_remove("PODSSH_PAIR_MAILBOX");
        cmd
    }

    /// [`Home::command`], which reaches `role` by its name and its CA.
    fn reaching(&self, role: &Role, args: &[&str]) -> Command {
        let mut cmd = self.command(args);
        cmd.env("SSL_CERT_FILE", &role.ca).env("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1");
        cmd
    }

    /// `podssh ARGS` with `stdin` on a pipe, and with no controlling terminal,
    /// so that a run has none to show a code on: its code, stdout and stderr.
    fn ran(&self, args: &[&str], stdin: &str) -> (i32, String, String) {
        ran(detached(self.command(args)), stdin)
    }

    /// A private key file of an end, from one byte: its path and fingerprint.
    fn device_key(&self, seed: u8) -> (String, String) {
        let path = self.dir.join(format!("device-{seed:02x}.key"));
        let hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
        podssh_relay::cache::create_private(&path, format!("{hex}\n").as_bytes()).unwrap();
        (path.display().to_string(), Identity::from_seed(&[seed; 32]).public().fingerprint())
    }

    /// The serial of the net held, by `net ls`; `None` when none is held.
    fn serial(&self) -> Option<u64> {
        let (rc, _, err) = self.ran(&["net", "ls"], "");
        if rc == 78 && err.contains("holds no net") {
            return None;
        }
        assert_eq!(rc, 0, "podssh net ls: {err}");
        let after = err.split("serial ").nth(1)?;
        after.split(',').next()?.parse().ok()
    }

    /// The members of the net held, as `net ls` lists them.
    fn members(&self) -> String {
        let (rc, out, err) = self.ran(&["net", "ls"], "");
        assert_eq!(rc, 0, "podssh net ls: {err}");
        out
    }
}

/// `cmd` with no controlling terminal: a session of its own.
fn detached(mut cmd: Command) -> Command {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe and touches no memory of the
    // parent; its result is ignored, as a child that leads a group already
    // has no terminal to lose.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd
}

/// `cmd` run to its end within [`LIMIT`], `stdin` on its stdin: its code,
/// stdout and stderr.
fn ran(mut cmd: Command, stdin: &str) -> (i32, String, String) {
    let mut child: Child =
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    // A run refused before it reads stdin may have closed it already.
    if let Some(mut input) = child.stdin.take() {
        let _ = input.write_all(stdin.as_bytes());
    }
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh did not end within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// An owner's key, made by podssh keygen in `home`: its path and its public
/// line.
fn owner(home: &Home, name: &str) -> (String, String) {
    let path = home.dir.join(name);
    let shown = path.display().to_string();
    let (rc, _, err) = home.ran(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &shown], "");
    assert_eq!(rc, 0, "podssh keygen: {err}");
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (shown, public.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
}

/// The net `home` of the owner of `key`, serial 1.
fn init(home: &Home, key: &str) {
    let (rc, _, err) = home.ran(&["net", "init", "home", "--owner-key", key], "");
    assert_eq!(rc, 0, "podssh net init: {err}");
}

/// `podssh net invite lab` of the owner's host on a pseudo terminal, and the
/// code that it shows there.
fn invite(owner: &Home, role: &Role, key: &str) -> (Pty, String) {
    let args = ["net", "invite", "lab", "--owner-key", key, "--pair-mailbox", role.mailbox.as_str()];
    let giver = Pty::start(owner.reaching(role, &args), 24, 200);
    assert!(giver.expect(SHOWN, LIMIT), "the code shows on the terminal: {}", giver.text());
    let text = giver.text();
    let after = text.split(SHOWN).nth(1).unwrap_or_default();
    let code = after.split(['\r', '\n']).next().unwrap_or_default().trim().to_string();
    assert_eq!(code.split('-').count(), 4, "a nameplate and three words: {code:?}");
    (giver, code)
}

/// `podssh net join ARGS` of the device, the code on one line of a pipe.
fn join(device: &Home, role: &Role, code: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["net", "join", "--pair-mailbox", role.mailbox.as_str()];
    args.extend_from_slice(extra);
    ran(device.reaching(role, &args), &format!("{code}\n"))
}

/// The code with its last word another of its list: the right nameplate,
/// so that the device reaches the owner's host, and the wrong key.
fn wrong(code: &str) -> String {
    let (head, last) = code.rsplit_once('-').expect("a word");
    let other = if last == words::ODD[0] { words::ODD[1] } else { words::ODD[0] };
    format!("{head}-{other}")
}

/// The owner key's fingerprint, as the owner's `net ls` says it.
fn owner_print(owner: &Home) -> String {
    let (rc, _, err) = owner.ran(&["net", "ls"], "");
    assert_eq!(rc, 0, "{err}");
    let after = err.split("of the owner ").nth(1).expect("the owner in the net's line");
    after.split(',').next().unwrap().to_string()
}

#[test]
fn a_new_device_joins_by_a_code_and_holds_the_owner_s_document() {
    let s = Session::start("invite-join");
    let Some(role) = role(&s) else { return };
    let (owner_home, device) = (Home::new(&s, "owner"), Home::new(&s, "device"));
    let (key, public) = owner(&owner_home, "owner");
    init(&owner_home, &key);
    let print = owner_print(&owner_home);
    let (giver, code) = invite(&owner_home, &role, &key);
    assert!(giver.text().contains(&format!("of the owner {print}, for one device")), "{}", giver.text());
    let (device_key, device_print) = device.device_key(0x51);
    let (rc, out, err) = join(&device, &role, &code, &["--owner", &public, "--key", &device_key]);
    assert_eq!(rc, 0, "podssh net join: {out}{err}");
    assert_eq!(out, format!("lab: joined the net home of the owner {print}\n"));
    assert!(err.contains(&format!("the net home of the owner {print} names this device lab")), "{err}");
    for word in code.split('-').skip(1) {
        assert!(!out.contains(word) && !err.contains(word), "a word of the code in the device's output");
    }
    assert_eq!(giver.wait(LIMIT), Some(0), "podssh net invite: {}", giver.text());
    let joined = format!("lab: joined the net home with the key {device_print}, serial 2");
    assert!(giver.text().contains(&joined), "{}", giver.text());
    // The new member, with the device's key, at both ends, of one document.
    for home in [&owner_home, &device] {
        assert_eq!(home.serial(), Some(2));
        assert_eq!(home.members(), format!("lab\tnode\t{device_print}\t-\n"));
    }
    let shown = |home: &Home| home.ran(&["net", "show"], "").1;
    assert_eq!(shown(&owner_home), shown(&device), "the device holds the owner's document");
}

#[test]
fn a_wrong_code_or_another_owner_adds_no_member() {
    let s = Session::start("invite-refused");
    let Some(role) = role(&s) else { return };
    let (owner_home, device) = (Home::new(&s, "owner"), Home::new(&s, "device"));
    let (key, public) = owner(&owner_home, "owner");
    init(&owner_home, &key);
    let unmade = device.dir.join("unmade.key");
    let unmade_arg = unmade.display().to_string();
    // A wrong code: both ends fail, and the code is spent.
    let (giver, code) = invite(&owner_home, &role, &key);
    let (rc, _, err) = join(&device, &role, &wrong(&code), &["--owner", &public, "--key", &unmade_arg]);
    assert_eq!(rc, 77, "a wrong code: {err}");
    assert!(err.contains("the code did not match"), "{err}");
    assert_eq!(giver.wait(LIMIT), Some(77), "podssh net invite: {}", giver.text());
    assert_eq!((owner_home.serial(), device.serial()), (Some(1), None), "a wrong code added a member");
    assert!(!unmade.exists(), "a key was made for a wrong code");
    // Another owner than --owner names: the device refuses before it says a
    // word of its own, and the owner's host signs nothing.
    let (_, stranger) = owner(&device, "stranger");
    let (giver, code) = invite(&owner_home, &role, &key);
    let (rc, _, err) = join(&device, &role, &code, &["--owner", &stranger, "--key", &unmade_arg]);
    assert_eq!(rc, 77, "another owner was taken: {err}");
    assert!(err.contains("which --owner names; nothing is kept"), "{err}");
    assert_eq!(giver.wait(LIMIT), Some(77), "podssh net invite: {}", giver.text());
    assert!(giver.text().contains("the device refused to join, and nothing is signed"), "{}", giver.text());
    assert_eq!((owner_home.serial(), device.serial()), (Some(1), None), "another owner's net was joined");
    assert!(!unmade.exists(), "a key was made for another owner");
}

#[test]
fn the_device_asks_at_its_terminal_and_a_no_adds_no_member() {
    let s = Session::start("invite-asked");
    let Some(role) = role(&s) else { return };
    let (owner_home, device) = (Home::new(&s, "owner"), Home::new(&s, "device"));
    let (key, _) = owner(&owner_home, "owner");
    init(&owner_home, &key);
    let print = owner_print(&owner_home);
    let (device_key, device_print) = device.device_key(0x52);
    for (answer, code_of_join, serial) in [("no", 77, None), ("yes", 0, Some(2))] {
        let (giver, code) = invite(&owner_home, &role, &key);
        let args = ["net", "join", "--pair-mailbox", role.mailbox.as_str(), "--key", device_key.as_str()];
        let mut taker = Pty::start(device.reaching(&role, &args), 24, 200);
        assert!(taker.expect("the code that the owner's host shows: ", LIMIT), "{}", taker.text());
        taker.send(format!("{code}\n").as_bytes());
        assert!(taker.expect(ASKED, LIMIT), "the device asks: {}", taker.text());
        assert!(taker.text().contains(&format!("join the net home of the owner {print}?")), "{}", taker.text());
        taker.send(format!("{answer}\n").as_bytes());
        assert_eq!(taker.wait(LIMIT), Some(code_of_join), "{answer}: {}", taker.text());
        assert_eq!(giver.wait(LIMIT), Some(code_of_join), "{answer}: {}", giver.text());
        assert_eq!(device.serial(), serial, "{answer}");
        assert_eq!(owner_home.serial(), Some(serial.unwrap_or(1)), "{answer}");
    }
    assert_eq!(owner_home.members(), format!("lab\tnode\t{device_print}\t-\n"));
}

#[test]
fn a_member_s_name_goes_to_its_own_key_alone() {
    let s = Session::start("invite-member");
    let Some(role) = role(&s) else { return };
    let (owner_home, device) = (Home::new(&s, "owner"), Home::new(&s, "device"));
    let (key, public) = owner(&owner_home, "owner");
    init(&owner_home, &key);
    let (own_key, own_print) = device.device_key(0x61);
    let (other_key, _) = device.device_key(0x62);
    let own_hex: String = Identity::from_seed(&[0x61; 32]).public().hex();
    let (rc, _, err) = owner_home.ran(&["net", "add", "lab", &own_hex, "--owner-key", &key], "");
    assert_eq!(rc, 0, "podssh net add: {err}");
    let listed = format!("lab\tnode\t{own_print}\t-\n");
    // Another key under the member's name: refused, and nothing is signed.
    let (giver, code) = invite(&owner_home, &role, &key);
    let (rc, _, err) = join(&device, &role, &code, &["--owner", &public, "--key", &other_key]);
    assert_eq!(rc, 77, "a member's name went to another key: {err}");
    assert!(err.contains("is a member of the net already, with another key"), "{err}");
    assert_eq!(giver.wait(LIMIT), Some(77), "podssh net invite: {}", giver.text());
    assert_eq!((owner_home.serial(), device.serial()), (Some(2), None));
    assert_eq!(owner_home.members(), listed, "the member keeps its key");
    // The member's own key gets the document held, with no new serial: the
    // way back after a last word lost.
    let (giver, code) = invite(&owner_home, &role, &key);
    let (rc, out, err) = join(&device, &role, &code, &["--owner", &public, "--key", &own_key]);
    assert_eq!(rc, 0, "the member's own key: {out}{err}");
    assert_eq!(giver.wait(LIMIT), Some(0), "podssh net invite: {}", giver.text());
    assert_eq!((owner_home.serial(), device.serial()), (Some(2), Some(2)));
    assert_eq!(device.members(), listed);
}

#[test]
fn each_refusal_before_the_network_says_why() {
    let s = Session::start("invite-offline");
    let (owner_home, device) = (Home::new(&s, "owner"), Home::new(&s, "device"));
    let (key, public) = owner(&owner_home, "owner");
    let offline = |home: &Home, args: &[&str], set: &[(&str, &str)], stdin: &str| {
        let mut cmd = detached(home.command(args));
        cmd.env("PODSSH_OFFLINE", "1").envs(set.iter().copied());
        ran(cmd, stdin)
    };
    for (args, code, says) in [
        (vec!["net", "join", "--roles", "node"], 64, "--roles is for podssh net add, invite"),
        (vec!["net", "invite"], 64, "podssh net invite NAME: 0 words given"),
        (vec!["net", "join", "lab"], 64, "podssh net join: 1 words given"),
        (vec!["net", "invite", "lab", "--key", "k"], 64, "--key is for podssh net join"),
        (vec!["net", "invite", "lab.example"], 64, "is not a name"),
        (vec!["net", "invite", "lab"], 78, "holds no net"),
    ] {
        let (rc, out, err) = offline(&owner_home, &args, &[], "");
        assert!(rc == code && err.contains(says) && out.is_empty(), "{args:?}: {rc} {err}");
    }
    init(&owner_home, &key);
    let (rc, _, err) = offline(&owner_home, &["net", "invite", "lab", "--owner-key", &key], &[], "");
    assert!(rc == 64 && err.contains("on this run's terminal alone"), "no terminal: {rc} {err}");
    let other = Identity::from_seed(&[0x71; 32]).public().hex();
    assert_eq!(offline(&owner_home, &["net", "add", "lab", &other, "--owner-key", &key], &[], "").0, 0);
    let (rc, _, err) = offline(&owner_home, &["net", "invite", "lab", "--roles", "exit"], &[], "");
    assert!(rc == 64 && err.contains("lab is a member of the net home already"), "{rc} {err}");
    assert_eq!(owner_home.serial(), Some(2), "no refusal signed a document");
    // The device: an owner that nobody can check, the code off, and codes.
    let (code, p, off) = ("7-crossover-clockwork-adroitness", public.as_str(), vec![("PODSSH_PAIR_MAILBOX", "no")]);
    for (args, set, code_of, says) in [
        (vec!["net", "join"], vec![], 64, "--owner KEY names it"),
        (vec!["net", "join", "--owner", "nope"], vec![], 64, "--owner \"nope\": not a key's fingerprint"),
        (vec!["net", "join", "--owner", p], off, 78, "podssh net add NAME KEY"),
        (vec!["net", "join", "--owner", p, "--pair-mailbox", "no"], vec![], 64, "turns pairing by code off"),
        (vec!["net", "join", "--owner", p], vec![], 69, "PODSSH_OFFLINE"),
    ] {
        let (rc, out, err) = offline(&device, &args, &set, &format!("{code}\n"));
        assert!(rc == code_of && err.contains(says) && out.is_empty(), "{args:?}: {rc} {err}");
        for word in code.split('-').skip(1) {
            assert!(!err.contains(word), "{args:?}: a word of the code in {err:?}");
        }
    }
    let (rc, _, err) = offline(&device, &["net", "join", "--owner", &public], &[], "7-notaword-clockwork\n");
    assert!(rc == 64 && err.contains("word 1 of the code") && !err.contains("notaword"), "{rc} {err}");
    assert_eq!(device.serial(), None, "no refusal kept a net");
}
