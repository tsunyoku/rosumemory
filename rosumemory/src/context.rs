use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Context {
    pub ready: bool,
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
            ready: true,
            osu_pid,
            osu_songs_folder,
            base_address,
            beatmap_ptr,
        }
    }

    pub fn make_empty(&mut self) {
        self.ready = false;
        self.osu_pid = 0;
        self.osu_songs_folder = String::new();
        self.base_address = 0;
        self.beatmap_ptr = 0;
    }
}

pub struct Shared {
    pub state: Mutex<Context>,
}

#[derive(Clone)]
pub struct SharedContext {
    pub shared: Arc<Shared>,
}
