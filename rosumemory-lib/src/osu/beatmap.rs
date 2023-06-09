use crate::{
    memory::read::{self, read_f32, read_i32, read_string, read_type_at_offset, ReadMemoryError},
    models::beatmap::Beatmap,
};

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn from_ptr(pid: usize, ptr: *mut u8) -> Result<Beatmap, ReadMemoryError> {
    let deref_ptr = read::read_ptr(pid.into(), ptr)?;

    macro_rules! beatmap_read_type_at_offset {
        ($type:ty, $offset:expr) => {
            read_type_at_offset!(pid, deref_ptr, $offset, $type)
        };
    }

    let artist_romanised = beatmap_read_type_at_offset!(String, 0x18)?;
    let artist = beatmap_read_type_at_offset!(String, 0x1C).unwrap_or(artist_romanised.clone());
    let title_romanised = beatmap_read_type_at_offset!(String, 0x24)?;
    let title = beatmap_read_type_at_offset!(String, 0x28).unwrap_or(title_romanised.clone());
    let ar = beatmap_read_type_at_offset!(f32, 0x2C)?;
    let cs = beatmap_read_type_at_offset!(f32, 0x30)?;
    let hp = beatmap_read_type_at_offset!(f32, 0x34)?;
    let od = beatmap_read_type_at_offset!(f32, 0x38)?;
    let audio_filename = beatmap_read_type_at_offset!(String, 0x64)?;
    let background_filename = beatmap_read_type_at_offset!(String, 0x68)?;
    let folder = beatmap_read_type_at_offset!(String, 0x78)?;
    let creator = beatmap_read_type_at_offset!(String, 0x7C)?;
    let name = beatmap_read_type_at_offset!(String, 0x80)?;
    let path = beatmap_read_type_at_offset!(String, 0x94)?;
    let difficulty = beatmap_read_type_at_offset!(String, 0xB0)?;
    let map_id = beatmap_read_type_at_offset!(i32, 0xCC)?;
    let set_id = beatmap_read_type_at_offset!(i32, 0xD0)?;
    let ranked_status = beatmap_read_type_at_offset!(i32, 0x130)?;
    let md5 = beatmap_read_type_at_offset!(String, 0x6C)?;
    let object_count = beatmap_read_type_at_offset!(i32, 0xFC)?;
    let osu_file_name = beatmap_read_type_at_offset!(String, 0x94)?;

    Ok(Beatmap {
        artist,
        artist_romanised,
        title_romanised,
        title,
        ar,
        cs,
        hp,
        od,
        audio_filename,
        background_filename,
        folder,
        creator,
        name,
        path,
        difficulty,
        map_id,
        set_id,
        ranked_status,
        md5,
        object_count,
        osu_file_name,
    })
}
