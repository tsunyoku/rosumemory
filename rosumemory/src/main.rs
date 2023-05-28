use rosumemory_lib::{find_osu_process_id, find_songs_folder, ProcessError, SongsError};

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

    println!("osu! pid: {}", osu_pid.unwrap());
    println!("osu! songs folder: {}", osu_songs_folder.unwrap());
}
