//! The service of a Windows user (T-121): a task of the Task Scheduler at
//! this user's logon, made from XML by `schtasks /Create /XML`, as a logon
//! trigger for a user with no privilege must name that user and run with
//! its own token. A Windows service needs an administrator, and is never
//! made.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{run, said, text, Made, Spec};
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;

fn schtasks_program() -> Option<PathBuf> {
    crate::pager::find_program("schtasks.exe", std::env::var_os("PATH"))
}

fn task_name(name: &str) -> String {
    format!("podssh-node-{name}")
}

/// `DOMAIN\USER`, as the logon trigger names this user.
fn user() -> Option<String> {
    let name = std::env::var("USERNAME").ok().filter(|u| !u.is_empty())?;
    Some(match std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty()) {
        Some(domain) => format!("{domain}\\{name}"),
        None => name,
    })
}

/// `schtasks ARGS`, as a step that must pass.
fn step(program: &Path, args: &[&str]) -> Result<(), String> {
    match run(Command::new(program).args(args)) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!("schtasks {}: {}", args.first().unwrap_or(&""), said(&output))),
        Err(why) => Err(why),
    }
}

/// The task at logon, made or replaced, and started now.
pub(super) fn schtasks(spec: &Spec) -> Made {
    let Some(program) = schtasks_program() else { return Made::Absent("no schtasks.exe on PATH".into()) };
    let Some(user) = user() else { return Made::Absent("USERNAME is not set, for the logon trigger".into()) };
    let xml = text::task_xml(spec, &user);
    // schtasks reads a task's XML in UTF-16, as the Task Scheduler writes it.
    let bytes: Vec<u8> = [0xFFu8, 0xFE].into_iter().chain(xml.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    let file = match podssh_relay::cache::store_file(&format!("node-{}.task.xml", spec.name), &bytes) {
        Ok(file) => file,
        Err(why) => return Made::Failed(Refusal::config(format!("the task's XML: {why}"))),
    };
    let name = task_name(&spec.name);
    let shown = file.display().to_string();
    let made = step(&program, &["/Create", "/TN", &name, "/XML", &shown, "/F"]);
    let _ = std::fs::remove_file(&file);
    if let Err(why) = made {
        return Made::Failed(Refusal { message: format!("the task at logon: {why}"), code: EX_UNAVAILABLE });
    }
    // A run of an older task ends first, so that the new words take.
    let _ = step(&program, &["/End", "/TN", &name]);
    let started = match step(&program, &["/Run", "/TN", &name]) {
        Ok(()) => "started now".to_string(),
        Err(why) => format!("not started now ({why}): it starts at the next logon"),
    };
    Made::Done(vec![format!("a task at the logon of {user}, {name}, {started}")])
}

/// Remove the task of NAME, ended first.
pub(super) fn remove(name: &str) -> Vec<String> {
    let Some(program) = schtasks_program() else { return Vec::new() };
    let task = task_name(name);
    if step(&program, &["/Query", "/TN", &task]).is_err() {
        return Vec::new();
    }
    let _ = step(&program, &["/End", "/TN", &task]);
    match step(&program, &["/Delete", "/TN", &task, "/F"]) {
        Ok(()) => vec![format!("removed the task {task}")],
        Err(why) => vec![format!("kept the task {task}, which schtasks did not delete: {why}")],
    }
}
