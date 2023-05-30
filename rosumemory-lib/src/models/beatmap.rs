use crate::memory::read::{
    self, offset_string, offset_type, read_f32, read_string, ReadMemoryError,
};

#[derive(Debug)]
pub struct Beatmap {
    pub artist: String,
    pub artist_romanised: String,
    pub title: String,
    pub title_romanised: String,
    pub ar: f32,
    pub cs: f32,
    pub hp: f32,
    pub od: f32,
    // TODO: add remaining fields
}

impl Beatmap {
    /// # Safety
    ///
    /// This function is unsafe because it dereferences a raw pointer.
    pub unsafe fn from_ptr(pid: usize, ptr: *mut u8) -> Result<Self, ReadMemoryError> {
        let deref_ptr = read::read_ptr(pid.into(), ptr as usize)?;

        let artist_romanised = offset_string!(pid, deref_ptr, 0x18);
        let artist = offset_string!(pid, deref_ptr, 0x1C);
        let title_romanised = offset_string!(pid, deref_ptr, 0x24);
        let title = offset_string!(pid, deref_ptr, 0x28);
        let ar = offset_type!(pid, deref_ptr, 0x2C, f32);
        let cs = offset_type!(pid, deref_ptr, 0x30, f32);
        let hp = offset_type!(pid, deref_ptr, 0x34, f32);
        let od = offset_type!(pid, deref_ptr, 0x38, f32);

        Ok(Self {
            artist,
            artist_romanised,
            title_romanised,
            title,
            ar,
            cs,
            hp,
            od,
        })
    }
}
