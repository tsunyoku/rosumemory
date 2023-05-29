use std::io::{Read, Write};

use rosumemory::api;
use rosumemory_lib::{
    memory::{pattern, read::read_ptr},
    osu::{find_songs_folder, SongsError},
    process::{find_osu_process_id, ProcessError},
};

async fn wrapped_main() -> anyhow::Result<()> {
    let mut osu_pid: Option<usize> = None;
    let mut osu_songs_folder: Option<String> = None;

    println!("waiting for osu! to start... (press ctrl+c to exit)");

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

    let base_addr = pattern::find_pattern(osu_pid.into(), "F8 01 74 04 83 65")
        .expect("failed to find base address");

    let _beatmap_ptr = unsafe {
        read_ptr(osu_pid.into(), base_addr.sub(0xC) as usize).expect("failed to find beatmap ptr")
    };

    api::serve().await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    wrapped_main().await.unwrap_or_else(|err| {
        eprintln!("error: {}", err);

        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        write!(stdout, "Press any key to continue...").unwrap();
        stdout.flush().unwrap();

        let _ = stdin.read(&mut [0u8]).unwrap();
    })
}
