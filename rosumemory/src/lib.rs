use rosumemory_lib::{
    memory::{pattern, read::read_ptr},
    osu::{find_songs_folder, SongsError},
    process::{find_osu_process_id, ProcessError},
};

use crate::context::Context;

pub mod api;
pub mod context;
pub mod models;

pub async fn ensure_osu() -> anyhow::Result<Context> {
    println!("waiting for osu! to start... (press ctrl+c to exit)");

    let mut osu_pid: Option<usize> = None;
    let mut osu_songs_folder: Option<String> = None;

    while osu_pid.is_none() || osu_songs_folder.is_none() {
        osu_pid = match find_osu_process_id() {
            Ok(pid) => {
                println!("found osu! process");
                Some(pid.into())
            }
            Err(ProcessError::NotFound(_)) => None,
            Err(ProcessError::Unknown(e)) => {
                anyhow::bail!("unknown error {}", e);
            }
        };

        osu_songs_folder = match find_songs_folder() {
            Ok(folder) => {
                println!("found osu! songs folder");
                Some(folder)
            }
            Err(SongsError::OsuNotRunning) => None,
            Err(SongsError::NotFound) | Err(SongsError::DoesntExist) => {
                anyhow::bail!("failed to find songs folder, please specify manually");
            }
            Err(e) => {
                anyhow::bail!("unknown error {}", e);
            }
        };
    }

    let osu_pid = osu_pid.unwrap();
    let osu_songs_folder = osu_songs_folder.unwrap();

    println!("osu! pid: {}", osu_pid);
    println!("osu! songs folder: {}", osu_songs_folder);

    let mut base_addr: *mut u8 = std::ptr::null_mut();
    while base_addr.is_null() {
        base_addr = match pattern::find_pattern(osu_pid.into(), "F8 01 74 04 83 65") {
            Ok(addr) => {
                println!("found base address");
                addr
            }
            Err(_) => {
                eprintln!("failed to find base address, retrying...");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                std::ptr::null_mut()
            }
        };
    }

    let _beatmap_ptr = unsafe {
        read_ptr(osu_pid.into(), base_addr.sub(0xC) as usize).expect("failed to find beatmap ptr")
    };

    Ok(Context::new(
        osu_pid,
        osu_songs_folder,
        base_addr as usize,
        _beatmap_ptr as usize,
    ))
}
