//! `podssh`. Everything is in the library; this is the shell around it.
//!
//! **`main` decides nothing.** The parse, the two streams and the exit
//! code are all in [`podssh_cli::dispatch`], so a test can exercise the whole
//! path with no process and no pipe — and the shell assertions still run the
//! real binary, because a unit test proves the dispatch and only the binary
//! proves the streams.
//!
//! **The run is on a thread of 16 MiB.** Windows gives the main thread 1
//! MiB, which the futures of a session nested in another road (`podssh ssh
//! --upgrade`, T-167) passed in a debug build; the stack of each thread
//! that podssh starts itself is its own.

/// The stack of the thread that runs the command.
const STACK: usize = 16 << 20;

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let kept = args.clone();
    let run = std::thread::Builder::new().stack_size(STACK).spawn(move || podssh_cli::dispatch::main_with_args(args));
    let code = match run {
        // A panic was said on stderr by the thread; 101 is Rust's code for it.
        Ok(thread) => thread.join().unwrap_or(101),
        Err(_) => podssh_cli::dispatch::main_with_args(kept),
    };
    std::process::exit(code);
}
