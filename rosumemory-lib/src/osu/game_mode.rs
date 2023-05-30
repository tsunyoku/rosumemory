use crate::memory::read::{read_i32, read_ptr, read_ptr_at_offset, read_type, ReadMemoryError};

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn from_ptr(pid: usize, ptr: *mut u8) -> Result<i32, ReadMemoryError> {
    let play_time_ptr = read_ptr_at_offset!(pid, ptr, -0x33i8)?;
    read_type!(pid, play_time_ptr, i32)
}
