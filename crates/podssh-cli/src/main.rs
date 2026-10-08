//! `podssh`. ⛔ Everything is in the library; this is the shell around it.
//!
//! ⛔ **`main` decides nothing.** ⛔ The parse, the two streams and the exit
//! code are all in [`podssh_cli::dispatch`], so a test can exercise the whole
//! path with no process and no pipe — and the shell assertions still run the
//! real binary, because a unit test proves the dispatch and only the binary
//! proves the streams.

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(podssh_cli::dispatch::main_with_args(args));
}