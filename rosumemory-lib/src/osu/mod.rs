pub mod beatmap;
pub mod game_mode;
pub mod menu_mods;
pub mod play_time;

use std::path::PathBuf;

use thiserror::Error;

use crate::process::{find_osu_process_id, retrieve_process_exe, ProcessError};

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
        ProcessError::Unknown(e) => SongsError::Unknown(e),
    })?;

    let osu_process_exe = retrieve_process_exe(&osu_process).map_err(|e| match e {
        ProcessError::NotFound(_) => SongsError::OsuNotRunning,
        ProcessError::Unknown(e) => SongsError::Unknown(e),
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
