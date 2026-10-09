//! `podssh pipe A B` (T-174): join two byte streams, as socat does, with no
//! listener. Each address is `KIND:REST` (`address`); both are checked
//! before anything starts. The pump (`pump`) copies both ways; the local
//! ends are stdin and stdout, an inherited descriptor, and a child
//! (`local`). The exit status is a child's, B's when both are children, as a
//! shell gives it; with no child, a clean end gives 0.

use std::io::Write;

pub mod address;
pub mod local;
pub mod pump;

use crate::exit_codes::EXIT_SOFTWARE;

/// What `podssh pipe` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipeArgs {
    pub a: Option<String>,
    pub b: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_pipe(args: &PipeArgs, err: &mut dyn Write) -> i32 {
    let (a, b) = match address::both(args.a.as_deref(), args.b.as_deref()) {
        Ok(both) => both,
        Err(refusal) => return refusal.report("pipe", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh pipe: could not start the async runtime: {e}");
            return EXIT_SOFTWARE;
        }
    };
    let code = runtime.block_on(run(a, b, err));
    // A read of stdin may still wait in its thread; the pipe has ended.
    runtime.shutdown_background();
    code
}

async fn run(a: address::Address, b: address::Address, err: &mut dyn Write) -> i32 {
    let a = match local::open(&a) {
        Ok(end) => end,
        Err(unopened) => return refused(unopened, err),
    };
    let b = match local::open(&b) {
        Ok(end) => end,
        Err(unopened) => {
            // A's child, if any, would wait for input that never comes.
            if let Some(mut child) = a.child {
                let _ = child.kill().await;
            }
            return refused(unopened, err);
        }
    };
    let pumped = pump::pump(a, b).await;
    // Each child got the end of its input with the pump's handles; podssh
    // waits for it, as a shell waits.
    let a = waited(pumped.a).await;
    let b = waited(pumped.b).await;
    b.or(a).unwrap_or(0)
}

fn refused(unopened: local::Unopened, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh pipe: {}", unopened.why);
    unopened.code
}

/// The child's exit code, when there is a child.
async fn waited(child: Option<tokio::process::Child>) -> Option<i32> {
    let mut child = child?;
    Some(match child.wait().await {
        Ok(status) => local::code_of(status),
        Err(_) => EXIT_SOFTWARE,
    })
}
