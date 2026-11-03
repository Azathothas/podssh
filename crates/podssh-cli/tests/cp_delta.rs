//! The plan of a delta copy (T-142): which blocks of 1 MiB go, for a file
//! that is equal, changed, grown or shrunk against its older version, and the
//! digest of each local block. The copy itself runs against OpenSSH in the
//! gate (`scripts/interop-cp.sh`, `cp.delta.*`), where the far side has `dd`
//! and a digest tool. Against the test's server, whose `sftp-server` names
//! no `copy-data` for a user `nocopy-...` (T-470): with its commands run in
//! sh, a command makes the temporary file and one block of five goes; with
//! none, the whole file goes, and one line says why, with no `-v`.

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use podssh_cli::cp::delta::{local_blocks, plan, BLOCK};
use sha2::{Digest, Sha256};

fn sums(blocks: &[&str]) -> Vec<[u8; 32]> {
    blocks.iter().map(|b| Sha256::digest(b.as_bytes()).into()).collect()
}

#[test]
fn an_equal_file_sends_no_block() {
    let old = sums(&["a", "b", "c"]);
    let p = plan(&old, &old, 3 * BLOCK);
    assert_eq!((p.send, p.kept), (Vec::<u64>::new(), 3));
}

#[test]
fn a_changed_block_is_the_only_one_sent() {
    let p = plan(&sums(&["a", "x", "c"]), &sums(&["a", "b", "c"]), 3 * BLOCK);
    assert_eq!((p.send.clone(), p.kept, p.bytes()), (vec![1], 2, BLOCK));
}

#[test]
fn a_grown_file_sends_its_new_blocks_and_a_changed_last_one() {
    // The old file ended inside its last block: that block differs too.
    let p = plan(&sums(&["a", "b", "c2", "d"]), &sums(&["a", "b", "c"]), 3 * BLOCK + 9);
    assert_eq!((p.send.clone(), p.kept, p.bytes()), (vec![2, 3], 2, BLOCK + 9));
}

#[test]
fn a_shrunk_file_keeps_its_blocks_and_its_size_cuts_the_rest() {
    let p = plan(&sums(&["a", "b2"]), &sums(&["a", "b", "c", "d"]), BLOCK + 100);
    assert_eq!((p.send.clone(), p.kept, p.size, p.bytes()), (vec![1], 1, BLOCK + 100, 100));
}

#[test]
fn the_local_blocks_are_the_digest_of_each_mib() {
    let dir = std::env::temp_dir().join(format!("podssh-cp-delta-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("f");
    let data: Vec<u8> = (0..(3 * BLOCK + 1)).map(|i| (i % 253) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    let want: Vec<[u8; 32]> = data.chunks(BLOCK as usize).map(|c| Sha256::digest(c).into()).collect();
    assert_eq!(local_blocks(&path).unwrap(), want);
    assert_eq!(want.len(), 4, "three whole blocks and a byte");
    let _ = std::fs::remove_dir_all(&dir);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-delta-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server with a new host key in `home`, where its
/// `sftp-server` runs: each command run in sh with `shell`, else answered
/// as that server answers a command that it does not know (a greeting and
/// 0), which runs nothing.
fn server(home: &Path, shell: bool) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = if shell {
        let path = std::env::var("PATH").unwrap_or_default();
        let shell = ssh_harness::Shell { home: home.to_path_buf(), path };
        runtime.block_on(ssh_harness::start_shell(&key, shell)).0
    } else {
        runtime.block_on(ssh_harness::start(&key))
    };
    (runtime, port)
}

/// `podssh cp` with `args` in `home`, with no `-v` unless `args` holds it:
/// its code, stdout and stderr.
fn cp(home: &Path, port: u16, args: &[&str]) -> (i32, String, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["cp", "--timeout", "120s", "--direct", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

macro_rules! need_server {
    () => {
        if ssh_harness::sftp::server_path().is_none() {
            eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
            return;
        }
    };
}

/// A file of 5 MiB, and its older version with 13 bytes changed in its
/// fourth block, as GitHub #87 changed them.
fn versions() -> (Vec<u8>, Vec<u8>) {
    let new: Vec<u8> = (0..(5u32 << 20)).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let mut old = new.clone();
    for b in &mut old[(3 << 20) + 100..(3 << 20) + 113] {
        *b ^= 0xff;
    }
    (new, old)
}

/// The `done` object of a run with `--jsonl`.
fn done_object(out: &str) -> serde_json::Value {
    let mut objects = out.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok());
    objects.find(|v| v["event"] == "done").unwrap_or_default()
}

/// With no `copy-data` and a server that runs commands in sh: one command
/// makes the temporary file from the old one there, and only the changed
/// block goes (T-470).
#[cfg(unix)]
#[test]
fn up_with_no_copy_data_a_command_copies_the_old_file_and_one_block_goes() {
    need_server!();
    let home = scratch("command");
    let (_runtime, port) = server(&home, true);
    let (new, old) = versions();
    std::fs::write(home.join("new.bin"), &new).unwrap();
    std::fs::write(home.join("far.bin"), &old).unwrap();
    let (rc, out, err) = cp(&home, port, &["-v", "--delta", "--jsonl", "new.bin", "nocopy-u@127.0.0.1:far.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("far.bin")).unwrap(), new, "the far file is the new one");
    assert!(err.contains("--delta: no copy-data: a command there copies the old file"), "{err}");
    assert!(err.contains("delta: 1 of 5 blocks sent, 1048576 bytes"), "{err}");
    assert!(!err.contains("this copy sends the whole file"), "{err}");
    let delta = &done_object(&out)["delta"];
    assert_eq!(*delta, serde_json::json!({ "blocks": 5, "sent": 1, "bytes": 1_048_576 }), "{out}");
}

/// With no `copy-data` and no command that runs: the whole file goes, exit
/// 0, and one line says why at the default level; none with `-q`; the
/// reason in the `done` object of `--jsonl`; a first copy says nothing
/// without `-v` (T-470).
#[test]
fn with_no_copy_data_and_no_command_the_whole_file_goes_and_one_line_says_why() {
    need_server!();
    let home = scratch("full");
    let (_runtime, port) = server(&home, false);
    let (new, old) = versions();
    std::fs::write(home.join("new.bin"), &new).unwrap();
    let why = "--delta: the server has no copy-data and runs no command";
    for (quiet, said) in [(false, 1), (true, 0)] {
        std::fs::write(home.join("far.bin"), &old).unwrap();
        let mut args = vec!["--delta", "new.bin", "nocopy-u@127.0.0.1:far.bin"];
        if quiet {
            args.insert(0, "-q");
        }
        let (rc, _, err) = cp(&home, port, &args);
        assert_eq!(rc, 0, "{err}");
        assert_eq!(std::fs::read(home.join("far.bin")).unwrap(), new, "-q {quiet}: the whole file");
        assert_eq!(err.matches(why).count(), said, "-q {quiet}: {err}");
        assert_eq!(err.contains("this copy sends the whole file"), !quiet, "-q {quiet}: {err}");
    }
    std::fs::write(home.join("far.bin"), &old).unwrap();
    let (rc, out, err) = cp(&home, port, &["--delta", "--jsonl", "new.bin", "nocopy-u@127.0.0.1:far.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(done_object(&out)["delta"], serde_json::json!({ "full": "no-copy-data" }), "{out}");
    let (rc, _, err) = cp(&home, port, &["--delta", "new.bin", "nocopy-u@127.0.0.1:first.bin"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!err.contains("--delta"), "a first copy, said at -v alone: {err}");
    assert_eq!(std::fs::read(home.join("first.bin")).unwrap(), new);
}
