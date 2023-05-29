use rosumemory_lib::{
    memory::{pattern, MemoryMapping},
    models::beatmap::Beatmap,
    osu::{find_songs_folder, SongsError},
    process::{find_osu_process_id, ProcessError},
};

fn main() {
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
                eprintln!("unknown error {e}");
                std::process::exit(1);
            }
        };

        osu_songs_folder = match find_songs_folder() {
            Ok(folder) => {
                println!("found osu! songs folder");
                Some(folder)
            }
            Err(SongsError::OsuNotRunning) => None,
            Err(SongsError::NotFound) | Err(SongsError::DoesntExist) => {
                eprintln!("failed to find songs folder, please specify manually");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("unknown error {e}");
                std::process::exit(1);
            }
        };
    }

    let osu_pid = osu_pid.unwrap();
    let osu_songs_folder = osu_songs_folder.unwrap();

    println!("osu! pid: {}", osu_pid);
    println!("osu! songs folder: {}", osu_songs_folder);

    let base_addr = pattern::find_pattern(osu_pid.into(), "F8 01 74 04 83 65")
        .expect("failed to find base address");

    unsafe {
        let beatmap_addr = base_addr.sub(0x1C);
        let beatmap = Beatmap::from_memory(osu_pid, beatmap_addr).expect("failed to read beatmap");

        println!("beatmap artist: {}", beatmap.artist);
    }
}
