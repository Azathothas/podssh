//! The measures of what a user feels (T-660), as `podssh ping` is asked for
//! them: `--under-load` and `--connect-runs N`, checked before anything
//! connects, and the first hop of each connection that they open.

use std::sync::Arc;

use podssh_ssh::Log;

use super::{cold, keys, PingArgs};
use crate::ssh::resolve::{Resolved, Transport};
use crate::ssh::transport::{NotReached, Reached};

/// What a run measures beside, or in place of, the plain measures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plan {
    pub under_load: bool,
    pub connect_runs: Option<usize>,
}

impl Plan {
    /// The plan of `args`, or why it is refused before anything connects (64).
    pub fn read(args: &PingArgs) -> Result<Plan, String> {
        let connect_runs = match args.connect_runs.as_deref() {
            None => None,
            Some(text) => match text.parse::<usize>() {
                Ok(n) if (1..=cold::MAX_RUNS).contains(&n) => Some(n),
                _ => return Err(format!("--connect-runs {text}: from 1 to {}", cold::MAX_RUNS)),
            },
        };
        let flag = if args.under_load { Some("--under-load") } else { connect_runs.map(|_| "--connect-runs") };
        if let (Some(flag), None) = (flag, &args.ssh.destination) {
            return Err(format!("{flag} measures through a host: name one, as for the echo and the throughput"));
        }
        // The plain measures beside the download would pass the relay's
        // 64 MiB for one session, and their figures would be of another run.
        if args.under_load {
            for (given, other) in [(&args.size, "--size"), (&args.count, "--count")] {
                if given.is_some() {
                    let (n, gap) = (keys::KEYS, keys::GAP.as_millis());
                    return Err(format!(
                        "{other} is for the plain echo and throughput, which --under-load replaces: {n} keys {gap} ms \
                         apart, idle and beside a download"
                    ));
                }
            }
        }
        Ok(Plan { under_load: args.under_load, connect_runs })
    }
}

/// The first hop of a connection to the destination: a node over the roads
/// that `podssh ssh` races to it, or over its carrier, as `podssh cp`
/// reaches one; any other as `ssh` reaches it.
pub async fn reach(resolved: &Resolved, log: &Arc<Log>) -> Result<Reached, NotReached> {
    match &resolved.transport {
        Transport::Node { label, channel, carrier: Some(text), .. } => {
            crate::ssh::carried::reach(label, text, channel, log).await
        }
        Transport::Node { .. } => crate::ssh::node_roads::reach(&resolved.transport, log).await,
        _ => crate::ssh::transport::reach(resolved, log).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::args::SshArgs;

    fn args(destination: Option<&str>, flags: &[(&str, &str)]) -> PingArgs {
        let ssh = SshArgs { destination: destination.map(String::from), ..SshArgs::default() };
        let mut args = PingArgs { ssh, ..PingArgs::default() };
        for (flag, value) in flags {
            match *flag {
                "--under-load" => args.under_load = true,
                "--connect-runs" => args.connect_runs = Some(value.to_string()),
                "--count" => args.count = Some(value.to_string()),
                "--size" => args.size = Some(value.to_string()),
                other => panic!("{other}"),
            }
        }
        args
    }

    #[test]
    fn the_runs_are_counted_from_1_to_20() {
        for bad in ["0", "21", "five", "-1", ""] {
            let why = Plan::read(&args(Some("host"), &[("--connect-runs", bad)])).unwrap_err();
            assert!(why.contains("from 1 to 20"), "{bad:?}: {why}");
        }
        let plan = Plan::read(&args(Some("host"), &[("--connect-runs", "5")])).unwrap();
        assert_eq!(plan, Plan { under_load: false, connect_runs: Some(5) });
        assert_eq!(Plan::read(&args(None, &[])), Ok(Plan::default()));
    }

    #[test]
    fn each_measure_of_feel_needs_a_host() {
        for flags in [&[("--under-load", "")][..], &[("--connect-runs", "3")][..]] {
            let why = Plan::read(&args(None, flags)).unwrap_err();
            assert!(why.contains("measures through a host"), "{flags:?}: {why}");
        }
    }

    #[test]
    fn under_load_refuses_the_flags_of_the_plain_measures() {
        for (flag, value) in [("--count", "5"), ("--size", "1M")] {
            let why = Plan::read(&args(Some("host"), &[("--under-load", ""), (flag, value)])).unwrap_err();
            assert!(why.starts_with(&format!("{flag} is for the plain echo and throughput")), "{why}");
            assert!(why.contains("40 keys 150 ms apart"), "{why}");
        }
        let plan = Plan::read(&args(Some("host"), &[("--under-load", ""), ("--connect-runs", "2")])).unwrap();
        assert_eq!(plan, Plan { under_load: true, connect_runs: Some(2) });
    }
}
