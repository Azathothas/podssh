//! The agent of `SSH_AUTH_SOCK`, and the passwords and passphrases that
//! `podssh agent` keeps (T-228): how many, never which.

use podssh_ssh::credential_store::{self, StoreError};
use podssh_ssh::Agent;

use super::Report;

/// One line: no agent, an agent with no store of podssh, or the count.
pub(super) fn check(report: &mut Report<'_>) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => return report.unknown("agent", format!("not asked: no runtime: {e}")),
    };
    match runtime.block_on(credential_store::count(&Agent::FromEnvironment)) {
        None => report.ok("agent", "none runs (SSH_AUTH_SOCK)"),
        Some(Ok(kept)) => {
            let what = if kept == 1 { "password or passphrase" } else { "passwords and passphrases" };
            report.ok("agent", format!("podssh agent, which keeps {kept} {what}"))
        }
        Some(Err(StoreError::NoStore)) => {
            report.ok("agent", "an agent that keeps no passwords: it is not podssh agent, or it is locked")
        }
        Some(Err(e)) => report.fail("agent", format!("the agent of SSH_AUTH_SOCK: {e}")),
    }
}
