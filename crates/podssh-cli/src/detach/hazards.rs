//! What a detached run cannot outlive, probed before it detaches
//! (`docs/detach.md`, section 1): PID 1 refuses, as the namespace ends with
//! it; the others are said, as the run may still be what the user wants. A
//! CI's end of a job is not said: the user asked to outlive the caller, and
//! a CI's tracking variable is never touched.

/// Why no detached run can outlive this one here, or `None`.
pub fn refusal() -> Option<String> {
    refusal_for(std::process::id())
}

fn refusal_for(pid: u32) -> Option<String> {
    (cfg!(unix) && pid == 1).then(|| {
        "podssh is the first process of its namespace (PID 1), which ends with it: a run in the background would end \
         at once; run it in the foreground, as the container's own process"
            .to_string()
    })
}

/// The lines of what may end a detached run here, from the environment.
pub fn lines() -> Vec<String> {
    let first = std::fs::read_to_string("/proc/1/comm").ok();
    lines_from(&|name| std::env::var_os(name).filter(|v| !v.is_empty()).is_some(), first.as_deref())
}

fn lines_from(set: &dyn Fn(&str) -> bool, first_process: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if set("INVOCATION_ID") {
        out.push("a unit of systemd started this run (INVOCATION_ID): stopping the unit ends this run too".to_string());
    }
    if set("WSL_DISTRO_NAME") {
        out.push(
            "WSL may stop its machine when no terminal of it is open (instanceIdleTimeout), and this run with it"
                .to_string(),
        );
    }
    if set("TERMUX_VERSION") {
        out.push("Android may end Termux's processes in the background (its limit of phantom processes)".to_string());
    }
    if let Some(name) = first_process.map(str::trim).filter(|n| *n == "bwrap") {
        out.push(format!("the first process of this namespace is {name}: when it ends, this run ends with it"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_1_refuses_on_unix_and_each_other_pid_does_not() {
        assert_eq!(refusal_for(1).is_some(), cfg!(unix));
        assert_eq!(refusal_for(4242), None);
    }

    #[test]
    fn each_hazard_is_said_from_its_variable() {
        let none = |_: &str| false;
        assert!(lines_from(&none, Some("init\n")).is_empty());
        let all = |name: &str| ["INVOCATION_ID", "WSL_DISTRO_NAME", "TERMUX_VERSION"].contains(&name);
        let said = lines_from(&all, Some("bwrap\n"));
        assert_eq!(said.len(), 4, "{said:?}");
        assert!(said[0].contains("systemd") && said[1].contains("WSL") && said[2].contains("Termux"));
        assert!(said[3].contains("bwrap"));
    }
}
