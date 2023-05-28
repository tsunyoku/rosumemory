use crate::memory::{
    read::{self, ReadMemoryError},
    MemoryMapping,
};

pub struct Beatmap {
    pub artist: String,
}

impl MemoryMapping for Beatmap {
    unsafe fn from_memory(pid: usize, memory: *mut u8) -> Result<Self, ReadMemoryError> {
        let artist_string_ptr = memory.add(0x18);
        let artist_string = read::read_string(pid.into(), artist_string_ptr)?;

        Ok(Self {
            artist: artist_string,
        })
    }

    fn size() -> usize {
        0x6C
    }
}
