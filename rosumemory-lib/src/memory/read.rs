use std::str::FromStr;

use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use sysinfo::Pid;
use thiserror::Error;

use super::pattern::Pattern;
use super::pattern::PatternScanError;
use super::MemoryMapping;

#[cfg(windows)]
mod platform {
    use std::os::windows::prelude::RawHandle;

    use sysinfo::Pid;
    use winapi::{
        ctypes::c_void,
        shared::{
            basetsd,
            minwindef::{self, HINSTANCE__},
            ntdef::NULL,
        },
        um::{
            libloaderapi::GetModuleHandleA,
            memoryapi::{self, VirtualQuery, VirtualQueryEx},
            processthreadsapi,
            winnt::{
                self, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
            },
        },
    };

    use crate::memory::pattern::{Pattern, PatternScanError};

    use super::ReadMemoryError;

    pub fn read_os_memory(
        pid: Pid,
        address: usize,
        buffer: &mut [u8],
    ) -> Result<(), ReadMemoryError> {
        let process_handle = unsafe {
            processthreadsapi::OpenProcess(
                winnt::PROCESS_VM_READ,
                0,
                Into::<usize>::into(pid) as minwindef::DWORD,
            )
        };
        if process_handle == (0 as RawHandle) {
            return Err(ReadMemoryError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let result = unsafe {
            memoryapi::ReadProcessMemory(
                process_handle,
                address as minwindef::LPVOID,
                buffer.as_mut_ptr() as minwindef::LPVOID,
                std::mem::size_of_val(buffer) as basetsd::SIZE_T,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(ReadMemoryError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    pub fn find_os_pattern(pid: Pid, pattern: Pattern) -> Result<*mut u8, PatternScanError> {
        let process_handle = unsafe {
            processthreadsapi::OpenProcess(
                winnt::PROCESS_VM_READ,
                0,
                Into::<usize>::into(pid) as minwindef::DWORD,
            )
        };
        if process_handle == (0 as RawHandle) {
            return Err(PatternScanError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let end = 2147483647 as *mut c_void;

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

        let mut page_start = std::ptr::null_mut::<c_void>();

        loop {
            let result = unsafe {
                VirtualQueryEx(
                    process_handle,
                    page_start,
                    &mut mbi as *mut MEMORY_BASIC_INFORMATION,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 || mbi.State != MEM_COMMIT || mbi.Protect != PAGE_EXECUTE_READWRITE {
                continue;
            }

            let mut buffer = vec![0u8; mbi.RegionSize];
            read_os_memory(pid, mbi.BaseAddress as usize, &mut buffer).map_err(|e| {
                PatternScanError::Unknown(format!(
                    "Failed to read memory at {:X}: {}",
                    mbi.BaseAddress as usize, e
                ))
            })?;

            if pattern == buffer {
                return Ok(mbi.BaseAddress as *mut u8);
            }

            if page_start >= end {
                break;
            }

            unsafe {
                page_start = page_start.add(mbi.RegionSize);
            }
        }

        Err(PatternScanError::NotFound)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::ReadMemoryError;
    use libc::{c_void, iovec, pid_t, process_vm_readv};
    use std::io::Read;
    use std::io::Seek;
    use sysinfo::Pid;

    pub fn read_os_memory(
        pid: Pid,
        address: usize,
        buffer: &mut [u8],
    ) -> Result<(), ReadMemoryError> {
        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };

        let remote_iov = iovec {
            iov_base: address as *mut c_void,
            iov_len: buffer.len(),
        };

        let result = unsafe {
            process_vm_readv(
                Into::<usize>::into(pid) as pid_t,
                &local_iov,
                1,
                &remote_iov,
                1,
                0,
            )
        };
        if result == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOSYS) | Some(libc::EPERM) => {
                    let procmem =
                        std::fs::File::open(format!("/proc/{}/mem", Into::<usize>::into(pid)))
                            .map_err(|e| ReadMemoryError::Unknown(e.to_string()))?;

                    procmem
                        .seek(std::io::SeekFrom::Start(address as u64))
                        .map_err(|e| ReadMemoryError::Unknown(e.to_string()))?;

                    procmem.read_exact(buffer);
                }
                _ => {
                    return Err(ReadMemoryError::Unknown(
                        std::io::Error::last_os_error().to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn find_os_pattern(pid: Pid, pattern: Pattern) -> Result<*mut u8, PatternScanError> {
        todo!()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libc::{c_int, pid_t};
    use mach::kern_return::{kern_return_t, KERN_SUCCESS};
    use mach::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
    use mach::vm_types::{mach_vm_address_t, mach_vm_size_t};
    use sysinfo::Pid;

    use super::ReadMemoryError;

    #[allow(non_camel_case_types)]
    type vm_map_t = mach_port_t;
    #[allow(non_camel_case_types)]
    type vm_address_t = mach_vm_address_t;
    #[allow(non_camel_case_types)]
    type vm_size_t = mach_vm_size_t;

    extern "C" {
        fn vm_read_overwrite(
            target_task: vm_map_t,
            address: vm_address_t,
            size: vm_size_t,
            data: vm_address_t,
            out_size: *mut vm_size_t,
        ) -> kern_return_t;
    }

    fn task_for_pid(pid: Pid) -> std::io::Result<mach_port_name_t> {
        if (Into::<usize>::into(pid) as pid_t) == unsafe { libc::getpid() } as pid_t {
            return Ok(unsafe { mach::traps::mach_task_self() });
        }

        let mut task: mach_port_name_t = MACH_PORT_NULL;

        unsafe {
            let result = mach::traps::task_for_pid(
                mach::traps::mach_task_self(),
                Into::<usize>::into(pid) as c_int,
                &mut task,
            );
            if result != KERN_SUCCESS {
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(task)
    }

    pub fn read_os_memory(
        pid: Pid,
        address: usize,
        buffer: &mut [u8],
    ) -> Result<(), ReadMemoryError> {
        let task_pid = task_for_pid(pid).map_err(|e| ReadMemoryError::Unknown(e.to_string()))?;

        let mut read_len = buffer.len() as vm_size_t;
        let result = unsafe {
            vm_read_overwrite(
                task_pid,
                address as vm_address_t,
                buffer.len() as vm_size_t,
                buffer.as_mut_ptr() as vm_address_t,
                &mut read_len,
            )
        };

        if read_len != buffer.len() as vm_size_t {
            return Err(ReadMemoryError::Unknown(
                "failed to read all memory".to_string(),
            ));
        }

        if result != KERN_SUCCESS {
            return Err(ReadMemoryError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    pub fn find_os_pattern(pid: Pid, pattern: Pattern) -> Result<*mut u8, PatternScanError> {
        todo!()
    }
}

use platform::{find_os_pattern, read_os_memory};

// TODO: move this to memory/pattern.rs?
pub fn find_pattern(pid: Pid, pattern_string: &str) -> Result<*mut u8, PatternScanError> {
    let pattern = Pattern::from_str(pattern_string).map_err(PatternScanError::Unknown)?;
    find_os_pattern(pid, pattern)
}

#[derive(Error, Debug)]
pub enum ReadMemoryError {
    #[error("failed to decode memory")]
    DecodeFailure,
    #[error("failed to read memory: {0}")]
    Unknown(String),
}

pub fn read_memory(pid: Pid, address: usize, size: usize) -> Result<Vec<u8>, ReadMemoryError> {
    let mut data = vec![0; size];

    read_os_memory(pid, address, &mut data)?;

    Ok(data)
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn structured_read_memory<T: MemoryMapping>(
    pid: Pid,
    address: usize,
) -> Result<T, ReadMemoryError> {
    let mut memory_region = read_memory(pid, address, T::size())?;
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
