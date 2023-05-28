use std::path::PathBuf;

use sysinfo::{Pid, Process, ProcessExt, System, SystemExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("process not found with criteria {0}")]
    NotFound(String),
    #[error("unknown err: {0}")]
    Unknown(String),
}

pub fn find_osu_process_id() -> Result<Pid, ProcessError> {
    // TODO: is there a way to optimise this?
    let mut sys = System::new_all();
    sys.refresh_all();

    let process: Option<&Process> = sys.processes_by_name("osu!").take(1).next();
    process
        .map(|process| process.pid())
        .ok_or_else(|| ProcessError::NotFound("osu!".to_string()))
}

pub fn retrieve_process_exe(pid: &Pid) -> Result<PathBuf, ProcessError> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let process = sys
        .process(*pid)
        .ok_or_else(|| ProcessError::NotFound(pid.to_string()))?;

    Ok(process.exe().to_owned())
}
