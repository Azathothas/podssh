//! The plan of a delta copy (T-142): which blocks of 1 MiB go, for a file
//! that is equal, changed, grown or shrunk against its older version, and the
//! digest of each local block. The copy itself runs against OpenSSH in the
//! gate (`scripts/interop-cp.sh`, `cp.delta.*`), where the far side has `dd`
//! and a digest tool.

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
