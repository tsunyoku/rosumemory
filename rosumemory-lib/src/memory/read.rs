use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use sysinfo::Pid;
use thiserror::Error;
use vmemory::ProcessMemory;

use crate::process::ProcessError;

use super::MemoryMapping;

pub(crate) fn enumerate_memory(
    pid: Pid,
    size: usize,
    offset: Option<usize>,
) -> Result<Vec<u8>, ProcessError> {
    todo!("cross platform way to query memory pages")
}

#[derive(Error, Debug)]
pub enum ReadMemoryError {
    #[error("failed to decode memory")]
    DecodeFailure,
    #[error("failed to read memory: {0}")]
    Unknown(String),
}

pub fn read_memory(pid: Pid, address: usize, size: usize) -> Result<Vec<u8>, ReadMemoryError> {
    let process_memory = ProcessMemory::attach_process(Into::<usize>::into(pid) as u32)
        .ok_or_else(|| ReadMemoryError::Unknown("failed to attach to process".to_string()))?;

    let memory_region = process_memory
        .read_memory(address, size, false)
        .map_err(|e| ReadMemoryError::Unknown(format!("got error code from os: {}", e)))?;

    Ok(memory_region)
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn structured_read_memory<T: MemoryMapping>(
    pid: Pid,
    address: usize,
) -> Result<T, ReadMemoryError> {
    let process_memory = ProcessMemory::attach_process(Into::<usize>::into(pid) as u32)
        .ok_or_else(|| ReadMemoryError::Unknown("failed to attach to process".to_string()))?;

    let mut memory_region = process_memory
        .read_memory(address, T::size(), false)
        .map_err(|e| ReadMemoryError::Unknown(format!("got error code from os: {}", e)))?;

    T::from_memory(pid.into(), memory_region.as_mut_ptr())
}

const MAX_STRING_LENGTH: u32 = 4096;

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn read_string(pid: Pid, string_ptr: *mut u8) -> Result<String, ReadMemoryError> {
    let length_bytes = read_memory(pid, unsafe { string_ptr.add(4) } as usize, 4)?;

    let length = length_bytes
        .as_slice()
        .read_u32::<LittleEndian>()
        .map_err(|_| ReadMemoryError::DecodeFailure)?;

    if length > MAX_STRING_LENGTH {
        return Err(ReadMemoryError::DecodeFailure);
    }

    let data_bytes = read_memory(pid, unsafe { string_ptr.add(8) } as usize, length as usize)?;

    let mut u16_string: Vec<u16> = Vec::with_capacity(length as usize);
    for (idx, _) in data_bytes.iter().enumerate() {
        let mut char_data = &data_bytes[idx * 2..idx * 2 + 2];
        u16_string.push(
            char_data
                .read_u16::<LittleEndian>()
                .map_err(|_| ReadMemoryError::DecodeFailure)?,
        );
    }

    String::from_utf16(&u16_string).map_err(|_| ReadMemoryError::DecodeFailure)
}
