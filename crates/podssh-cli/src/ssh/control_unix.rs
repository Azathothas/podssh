//! The start of a run with connection sharing (T-039), on Unix: an `-O`
//! request; a run through the master that answers on the socket, which
//! takes the run's forwards too, as OpenSSH's client sends them; or, with
//! `-M` or `ControlMaster auto` and no master there, this run as the master,
//! on a socket made before anything connects, as `-L` is.

use std::path::Path;
use std::sync::Arc;

use podssh_ssh::local::{LocalForward, Target};
use podssh_ssh::mux::client::{self, MuxClient, SessionRequest, Unreached};
use podssh_ssh::mux::master::{self, Binder, Control};
use podssh_ssh::mux::proto::{Fwd, FwdKind, PORT_STREAMLOCAL};
use podssh_ssh::mux::ControlSlot;
use podssh_ssh::{Agent, Log, RemoteForward, Request, RequestTty, EXIT_FAILURE};

use super::{Command, Mode, Persist, Plan};
use crate::ssh::local_spec::{Listen, LocalSpec};
use crate::ssh::resolve::Resolved;

/// What the run does next.
pub enum Start {
    /// The run is over: the exit code.
    Exit(i32),
    /// Connect, as the master when `Options::control` is set.
    Go,
}

pub async fn start(resolved: &mut Resolved, log: &Arc<Log>) -> Start {
    let plan = resolved.control.clone();
    if let Some(command) = plan.command {
        return Start::Exit(command_run(resolved, &plan, command, log).await);
    }
    let Some(path) = plan.path.clone() else {
        if plan.mode != Mode::No {
            log.verbose("ControlMaster has no ControlPath: no connection is shared");
        }
        return Start::Go;
    };
    if resolved.persist.is_some() {
        log.verbose("connection sharing does not go with --persist: this run connects alone");
        return Start::Go;
    }
    if matches!(plan.mode, Mode::No | Mode::Auto | Mode::AutoAsk) {
        match client::connect(&path).await {
            Ok(mux) => return Start::Exit(through(mux, resolved, log).await),
            Err(Unreached::NoMaster(e)) if plan.mode == Mode::No => {
                log.verbose(&format!("no control master at {}: {e}; this run connects alone", path.display()));
                return Start::Go;
            }
            Err(Unreached::NoMaster(_)) => {}
            Err(Unreached::Broken(why)) => {
                log.info(&format!("control socket {}: {why}; this run connects alone", path.display()));
                return Start::Go;
            }
        }
    }
    let required = matches!(plan.mode, Mode::Yes | Mode::Ask);
    match be_master(resolved, &plan, &path, log) {
        Ok(()) => Start::Go,
        Err((code, line)) if required => {
            log.error(&line);
            Start::Exit(code)
        }
        Err((_, line)) => {
            log.info(&format!("{line}; this run connects alone"));
            Start::Go
        }
    }
}

/// Make the socket and give it to the run, which serves it once connected.
fn be_master(resolved: &mut Resolved, plan: &Plan, path: &Path, log: &Arc<Log>) -> Result<(), (i32, String)> {
    if let Err(refusal) = crate::pipe::listen::allowed() {
        return Err((refusal.code, format!("ControlMaster: {}", refusal.message)));
    }
    let shown = path.display().to_string();
    let listener = crate::pipe::listen::control_socket(&shown)
        .map_err(|(_, line)| (EXIT_FAILURE, format!("ControlMaster: {line}")))?;
    let opts = &resolved.options;
    let persist = match plan.persist {
        Persist::No => master::Persist::No,
        Persist::Forever => master::Persist::Forever,
        Persist::Seconds(n) => master::Persist::For(std::time::Duration::from_secs(n)),
    };
    if plan.persist != Persist::No && !matches!(opts.request, Request::Nothing) {
        log.info(
            "ControlPersist keeps a -N master only: podssh does not go to the background, so this master \
             ends with its session; start one with podssh ssh -M -N -S PATH HOST &",
        );
    }
    let control = Control {
        listener,
        path: path.to_path_buf(),
        persist,
        binder: Some(binder(resolved.gateway_ports, log.clone())),
        ask: matches!(plan.mode, Mode::Ask | Mode::AutoAsk),
        agent: opts.forward_agent != Agent::Off,
        host: opts.destination.host.clone(),
    };
    log.verbose(&format!("ControlMaster: listening on {shown}, mode 0600, for this user's programs only"));
    resolved.options.control = Some(ControlSlot::new(control));
    Ok(())
}

/// The run through a master: its forwards first, then its request.
async fn through(mut mux: MuxClient, resolved: &Resolved, log: &Arc<Log>) -> i32 {
    let opts = &resolved.options;
    let host = opts.destination.host.clone();
    log.verbose("a control master answers: the run goes through it");
    let forwards = resolved.local.iter().map(fwd_of).chain(opts.remote_forwards.iter().map(remote_fwd));
    for fwd in forwards {
        match mux.forward(fwd.clone(), false).await {
            Ok(Some(port)) => {
                log.info(&format!(
                    "Allocated port {port} for remote forward to {}:{}",
                    fwd.connect_host, fwd.connect_port
                ));
            }
            Ok(None) => {}
            Err(why) => {
                log.error(&format!("Master refused forwarding request: {why}"));
                return EXIT_FAILURE;
            }
        }
    }
    match &opts.request {
        // The forwards stay with the master, as OpenSSH's client leaves them.
        Request::Nothing => 0,
        Request::StdioForward { host, port } => mux.stdio(host, *port, log).await,
        request => {
            let stdin_tty = podssh_ssh::terminal::stdin_is_terminal();
            let tty = match opts.request_tty {
                RequestTty::No => false,
                RequestTty::Force => true,
                RequestTty::Yes => stdin_tty,
                RequestTty::Auto => stdin_tty && *request == Request::Shell,
            };
            let (command, subsystem) = match request {
                Request::Exec(command) => (command.as_bytes().to_vec(), false),
                Request::Subsystem(name) => (name.as_bytes().to_vec(), true),
                _ => (Vec::new(), false),
            };
            let env = podssh_ssh::session::environment(opts).into_iter().map(|(n, v)| format!("{n}={v}")).collect();
            let asked = SessionRequest {
                tty,
                agent: opts.forward_agent != Agent::Off,
                subsystem,
                escape: opts.escape_char,
                term: podssh_ssh::terminal::term_name(),
                command,
                env,
                host,
            };
            mux.session(asked, log).await
        }
    }
}

/// `-O check`, `exit`, `stop`, `forward` and `cancel`, with OpenSSH's words.
async fn command_run(resolved: &Resolved, plan: &Plan, command: Command, log: &Arc<Log>) -> i32 {
    let Some(path) = &plan.path else {
        log.error("No ControlPath specified for \"-O\" command");
        return EXIT_FAILURE;
    };
    if command == Command::Proxy {
        log.error("-O proxy: podssh's client speaks no proxy mode; give the command to run, or -W");
        return EXIT_FAILURE;
    }
    let mut mux = match client::connect(path).await {
        Ok(mux) => mux,
        Err(e) => {
            log.error(&format!("Control socket connect({}): {e}", path.display()));
            return EXIT_FAILURE;
        }
    };
    let said = match command {
        Command::Check => mux.alive().await.map(|pid| format!("Master running (pid={pid})")),
        Command::Exit => mux.terminate().await.map(|()| "Exit request sent.".to_string()),
        Command::Stop => mux.stop().await.map(|()| "Stop listening request sent.".to_string()),
        Command::Forward | Command::Cancel => {
            let cancel = command == Command::Cancel;
            let opts = &resolved.options;
            for fwd in resolved.local.iter().map(fwd_of).chain(opts.remote_forwards.iter().map(remote_fwd)) {
                match mux.forward(fwd, cancel).await {
                    Ok(Some(port)) => println!("{port}"),
                    Ok(None) => {}
                    Err(why) => {
                        let what = if cancel { "cancel forwarding" } else { "forwarding" };
                        log.error(&format!("Master refused {what} request: {why}"));
                        return EXIT_FAILURE;
                    }
                }
            }
            return 0;
        }
        Command::Proxy => unreachable!("refused above"),
    };
    match said {
        Ok(line) => {
            log.info(&line);
            0
        }
        Err(why) => {
            log.error(&format!("Control master: {why}"));
            EXIT_FAILURE
        }
    }
}

/// A forward of `-L` or `-D` as the control protocol names it.
fn fwd_of(spec: &LocalSpec) -> Fwd {
    let (listen_host, listen_port) = match &spec.listen {
        Listen::Port { bind, port } => (bind.clone().unwrap_or_default(), u32::from(*port)),
        Listen::Path(path) => (path.clone(), PORT_STREAMLOCAL),
    };
    let (kind, connect_host, connect_port) = match &spec.target {
        Target::Socks => (FwdKind::Dynamic, "socks".to_string(), 0),
        Target::Tcp { host, port } => (FwdKind::Local, host.clone(), u32::from(*port)),
        Target::Socket(path) => (FwdKind::Local, path.clone(), PORT_STREAMLOCAL),
    };
    Fwd { kind, listen_host, listen_port, connect_host, connect_port }
}

fn remote_fwd(forward: &RemoteForward) -> Fwd {
    Fwd {
        kind: FwdKind::Remote,
        listen_host: forward.bind.clone().unwrap_or_default(),
        listen_port: u32::from(forward.port),
        connect_host: forward.host.clone(),
        connect_port: u32::from(forward.host_port),
    }
}

/// A forward of a client as `-L` or `-D` would give it to this master.
fn spec_of(fwd: &Fwd) -> Result<LocalSpec, String> {
    let port = |p: u32| u16::try_from(p).map_err(|_| format!("{p} is not a port"));
    let listen = if fwd.listen_port == PORT_STREAMLOCAL {
        Listen::Path(fwd.listen_host.clone())
    } else {
        Listen::Port {
            bind: (!fwd.listen_host.is_empty()).then(|| fwd.listen_host.clone()),
            port: port(fwd.listen_port)?,
        }
    };
    let target = match fwd.kind {
        FwdKind::Dynamic => Target::Socks,
        _ if fwd.connect_port == PORT_STREAMLOCAL => Target::Socket(fwd.connect_host.clone()),
        _ => Target::Tcp { host: fwd.connect_host.clone(), port: port(fwd.connect_port)? },
    };
    let flag = if fwd.kind == FwdKind::Dynamic { "-D" } else { "-L" };
    Ok(LocalSpec { listen, target, shown: format!("-O forward {flag} (a client's)") })
}

/// The binder of this master: a client's forward gets its listeners as the
/// run's own `-L` and `-D` get theirs.
fn binder(gateway_ports: bool, log: Arc<Log>) -> Binder {
    Arc::new(move |fwd: Fwd| {
        let log = log.clone();
        Box::pin(async move {
            let spec = spec_of(&fwd)?;
            let mut forwards: Vec<LocalForward> =
                crate::ssh::local_bind::listeners(std::slice::from_ref(&spec), gateway_ports, &log)
                    .await
                    .map_err(|(_, line)| line)?;
            forwards.pop().ok_or_else(|| "no listener was made".to_string())
        })
    })
}
