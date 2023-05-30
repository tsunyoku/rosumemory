use crate::memory::read::{read_ptr, read_ptr_at_offset, read_type, read_u32, ReadMemoryError};

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn from_ptr(pid: usize, ptr: *mut u8) -> Result<u32, ReadMemoryError> {
    let play_time_ptr = read_ptr_at_offset!(pid, ptr, 0x9)?;
    read_type!(pid, play_time_ptr, u32)
}
