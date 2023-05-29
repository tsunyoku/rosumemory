pub struct Context {
    pub osu_pid: usize,
    pub osu_songs_folder: String,
    pub base_address: usize,
    pub beatmap_ptr: usize,
}

impl Context {
    pub fn new(
        osu_pid: usize,
        osu_songs_folder: String,
        base_address: usize,
        beatmap_ptr: usize,
    ) -> Self {
        Self {
            osu_pid,
            osu_songs_folder,
            base_address,
            beatmap_ptr,
        }
    }
}
