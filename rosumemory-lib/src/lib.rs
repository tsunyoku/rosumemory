use std::path::PathBuf;

use sysinfo::{Pid, Process, ProcessExt, System, SystemExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("process not found with criteria {0}")]
    NotFound(String),
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

fn retrieve_process_exe(pid: &Pid) -> Result<PathBuf, ProcessError> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let process = sys
        .process(*pid)
        .ok_or_else(|| ProcessError::NotFound(pid.to_string()))?;

    Ok(process.exe().to_owned())
}

#[derive(Error, Debug)]
pub enum SongsError {
    #[error("osu is not running")]
    OsuNotRunning,
    #[error("songs folder not found")]
    NotFound,
    #[error("songs folder doesn't exist")]
    DoesntExist,
    #[error("unknown err: {0}")]
    Unknown(String),
}

pub fn find_songs_folder() -> Result<String, SongsError> {
    let osu_process = find_osu_process_id().map_err(|e| match e {
        ProcessError::NotFound(_) => SongsError::OsuNotRunning,
    })?;

    let osu_process_exe = retrieve_process_exe(&osu_process).map_err(|e| match e {
        ProcessError::NotFound(_) => SongsError::OsuNotRunning,
    })?;

    let osu_path = osu_process_exe
        .parent()
        .ok_or(SongsError::Unknown("osu! path not found".to_string()))?;

    let username = whoami::username();
    let osu_config_path = osu_path.join(format!("osu!.{username}.cfg"));

    let osu_config =
        std::fs::read_to_string(osu_config_path).map_err(|e| SongsError::Unknown(e.to_string()))?;
    let osu_config_lines = osu_config.lines().collect::<Vec<&str>>();

    for line in osu_config_lines {
        if line.starts_with("BeatmapDirectory") {
            let songs_folder = line.split('=').nth(1).ok_or(SongsError::Unknown(
                "BeatmapDirectory not found in osu! config".to_string(),
            ))?;

            let songs_folder = songs_folder.trim();
            let mut songs_path: PathBuf = songs_folder.into();

            // if no separator, it's a relative path
            if !songs_folder.contains(std::path::MAIN_SEPARATOR) {
                songs_path = osu_path.join(songs_folder);
            }

            if !songs_path.exists() {
                return Err(SongsError::DoesntExist);
            }

            return Ok(String::from(songs_path.to_str().unwrap_or_else(|| {
                panic!(
                    "failed to convert songs path to string: {:?}",
                    songs_path.to_owned()
                )
            })));
        }
    }

    Err(SongsError::NotFound)
}
