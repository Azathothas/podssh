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
//! that podssh starts itself is its own. The first thread waits, and runs
//! what the command sends it, as Linux keeps capabilities for each thread
//! (`podssh_cli::first_thread`, T-629).

/// The stack of the thread that runs the command.
const STACK: usize = 16 << 20;

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // A detached child releases what it inherited before any thread runs.
    podssh_cli::detach::prepare_process(&args);
    // Each verb's descriptors within the hard limit, not the shell's soft one (T-564).
    podssh_cli::nofile::start();
    let kept = args.clone();
    let first = podssh_cli::first_thread::Waiter::new();
    let run = std::thread::Builder::new().stack_size(STACK).spawn(move || {
        // Its drop, also in a panic, ends the first thread's wait.
        let _ended = podssh_cli::first_thread::Ended;
        podssh_cli::dispatch::main_with_args(args)
    });
    let code = match run {
        // A panic was said on stderr by the thread; 101 is Rust's code for it.
        Ok(thread) => first.wait(thread),
        // This thread runs the command: a job for the first thread runs here.
        Err(_) => podssh_cli::dispatch::main_with_args(kept),
    };
    std::process::exit(code);
}
