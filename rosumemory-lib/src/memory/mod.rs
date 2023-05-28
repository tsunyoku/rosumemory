use self::read::ReadMemoryError;

pub mod pattern;
pub mod read;

pub trait MemoryMapping {
    /// # Safety
    ///
    /// This function is unsafe because it dereferences a raw pointer.
    unsafe fn from_memory(pid: usize, memory: *mut u8) -> Result<Self, ReadMemoryError>
    where
        Self: std::marker::Sized;

    fn size() -> usize;
}
