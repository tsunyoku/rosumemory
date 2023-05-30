use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use sysinfo::Pid;
use thiserror::Error;

#[cfg(windows)]
mod platform {
    use std::os::windows::prelude::RawHandle;

    use sysinfo::Pid;
    use winapi::{
        ctypes::c_void,
        shared::{
            basetsd,
            minwindef::{self, DWORD, MAX_PATH},
        },
        um::{
            handleapi::CloseHandle,
            memoryapi::{self, VirtualQueryEx},
            processthreadsapi,
            psapi::{EnumProcessModules, GetModuleFileNameExA},
            winnt::{self, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE},
        },
    };

    use crate::memory::pattern::{Pattern, PatternByte, PatternScanError};

    use super::ReadMemoryError;

    pub fn read_os_memory(
        pid: Pid,
        address: usize,
        buffer: &mut [u8],
        size: usize,
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
                size,
                std::ptr::null_mut(),
            )
        };

        unsafe {
            CloseHandle(process_handle);
        }

        if result == 0 {
            return Err(ReadMemoryError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    fn find_osu_module(process_handle: *mut c_void) -> Result<usize, PatternScanError> {
        let mut base_addr = 0;

        let mut modules = [0 as minwindef::HMODULE; 1024];
        let mut cb_needed: DWORD = 0;

        if (unsafe {
            EnumProcessModules(
                process_handle,
                modules.as_mut_ptr(),
                modules.len() as u32,
                &mut cb_needed,
            )
        } == 0)
            || modules.is_empty()
        {
            return Err(PatternScanError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        for module in modules {
            if module.is_null() {
                continue;
            }

            let mut module_name: [i8; MAX_PATH] = [0; MAX_PATH];

            let result = unsafe {
                GetModuleFileNameExA(
                    process_handle,
                    module,
                    module_name.as_mut_ptr(),
                    std::mem::size_of_val(&module_name) as u32 / std::mem::size_of::<i8>() as u32,
                )
            };
            if result == 0 {
                continue;
            }

            let module_name = unsafe { std::ffi::CStr::from_ptr(module_name.as_ptr()) };
            if module_name.to_str().unwrap().contains("osu!.exe") {
                base_addr = module as usize;
                break;
            }
        }

        Ok(base_addr)
    }

    pub fn find_os_pattern(pid: Pid, pattern: Pattern) -> Result<*mut u8, PatternScanError> {
        let process_handle = unsafe {
            processthreadsapi::OpenProcess(
                winnt::PROCESS_VM_READ | winnt::PROCESS_QUERY_INFORMATION,
                0,
                Into::<usize>::into(pid) as minwindef::DWORD,
            )
        };
        if process_handle == (0 as RawHandle) {
            return Err(PatternScanError::Unknown(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let base_addr = match find_osu_module(process_handle) {
            Ok(addr) => addr,
            Err(err) => {
                unsafe {
                    CloseHandle(process_handle);
                }

                return Err(err);
            }
        };

        if base_addr == 0 {
            unsafe {
                CloseHandle(process_handle);
            }

            return Err(PatternScanError::NotFound);
        }

        let end_addr = 0x7FFFFFFF;

        let mut current_addr = base_addr;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        while current_addr < end_addr {
            let result = unsafe {
                VirtualQueryEx(
                    process_handle,
                    current_addr as minwindef::LPCVOID,
                    &mut mbi,
                    mbi_size as basetsd::SIZE_T,
                )
            };
            if result == 0 || mbi.State != MEM_COMMIT || mbi.Protect != PAGE_EXECUTE_READWRITE {
                current_addr = unsafe { mbi.BaseAddress.add(mbi.RegionSize) } as usize;
                continue;
            }

            let mut buffer = vec![0; mbi.RegionSize];
            let result = unsafe {
                memoryapi::ReadProcessMemory(
                    process_handle,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut c_void,
                    mbi.RegionSize,
                    std::ptr::null_mut(),
                )
            };
            if result == 0 {
                unsafe {
                    CloseHandle(process_handle);
                }

                return Err(PatternScanError::Unknown(
                    std::io::Error::last_os_error().to_string(),
                ));
            }

            let mut i = 0;

            while i < mbi.RegionSize {
                let mut found = true;

                let mut j = 0;
                let pattern_bytes = pattern.bytes();

                while found && j < pattern.len() {
                    match pattern_bytes[j] {
                        PatternByte::Any => {}
                        PatternByte::Byte(byte) => {
                            if buffer[i + j] != byte {
                                found = false;
                                break;
                            }
                        }
                    }

                    j += 1;
                }

                if found {
                    return Ok(unsafe { mbi.BaseAddress.add(i) } as *mut u8);
                }

                i += 1;
            }

            current_addr = unsafe { mbi.BaseAddress.add(mbi.RegionSize) } as usize;
        }

        unsafe {
            CloseHandle(process_handle);
        }

        Err(PatternScanError::NotFound)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::ReadMemoryError;
    use crate::memory::pattern::Pattern;
    use crate::memory::pattern::PatternScanError;

    use libc::{c_void, iovec, pid_t, process_vm_readv};
    use std::io::Read;
    use std::io::Seek;
    use sysinfo::Pid;

    pub fn read_os_memory(
        pid: Pid,
        address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<(), ReadMemoryError> {
        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: size,
        };

        let remote_iov = iovec {
            iov_base: address as *mut c_void,
            iov_len: size,
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
                    let mut procmem =
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

    pub fn find_os_pattern(_pid: Pid, _pattern: Pattern) -> Result<*mut u8, PatternScanError> {
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
    use crate::memory::pattern::Pattern;
    use crate::memory::pattern::PatternScanError;

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
        size: usize,
    ) -> Result<(), ReadMemoryError> {
        let task_pid = task_for_pid(pid).map_err(|e| ReadMemoryError::Unknown(e.to_string()))?;

        let mut read_len = size as vm_size_t;
        let result = unsafe {
            vm_read_overwrite(
                task_pid,
                address as vm_address_t,
                size as vm_size_t,
                buffer.as_mut_ptr() as vm_address_t,
                &mut read_len,
            )
        };

        if read_len != size as vm_size_t {
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

    pub fn find_os_pattern(_pid: Pid, _pattern: Pattern) -> Result<*mut u8, PatternScanError> {
        todo!()
    }
}

pub(crate) use platform::{find_os_pattern, read_os_memory};

#[derive(Error, Debug)]
pub enum ReadMemoryError {
    #[error("failed to decode memory: {0}")]
    DecodeFailure(String),
    #[error("failed to read memory: {0}")]
    Unknown(String),
}

pub fn read_memory(pid: Pid, address: *mut u8, size: usize) -> Result<Vec<u8>, ReadMemoryError> {
    let mut data = vec![0; size];

    read_os_memory(pid, address as usize, &mut data, size)?;

    Ok(data)
}

const PTR_SIZE: usize = 4;

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
unsafe fn get_array_like_header(
    pid: Pid,
    is_list: bool,
    base_address: *mut u8,
) -> Result<(u32, *mut u8), ReadMemoryError> {
    let address = read_ptr(pid, base_address)?;
    if address.is_null() {
        return Err(ReadMemoryError::DecodeFailure(
            "array-like address is null".to_string(),
        ));
    }

    let number_of_elements: u32;
    let first_element_ptr: *mut u8;
    let number_of_elements_addr: *mut u8;

    if is_list {
        number_of_elements_addr = address.add(3 * PTR_SIZE);

        let number_of_elements_bytes = read_memory(pid, number_of_elements_addr, 4)?;
        if number_of_elements_bytes.len() != 4 {
            return Err(ReadMemoryError::DecodeFailure(
                "number of list element bytes is not 4".to_string(),
            ));
        }

        number_of_elements = number_of_elements_bytes
            .as_slice()
            .read_u32::<LittleEndian>()
            .map_err(|_| {
                ReadMemoryError::DecodeFailure(
                    "failed to decode number of list number of elements bytes to u32".to_string(),
                )
            })?;

        let internal_array = read_ptr(pid, address.add(PTR_SIZE))?;
        first_element_ptr = internal_array.add(2 * PTR_SIZE);
    } else {
        number_of_elements_addr = address.add(PTR_SIZE);

        let number_of_elements_bytes = read_memory(pid, number_of_elements_addr, 4)?;
        if number_of_elements_bytes.len() != 4 {
            return Err(ReadMemoryError::DecodeFailure(
                "number of array element bytes is not 4".to_string(),
            ));
        }

        number_of_elements = number_of_elements_bytes
            .as_slice()
            .read_u32::<LittleEndian>()
            .map_err(|_| {
                ReadMemoryError::DecodeFailure(
                    "failed to decode number of array number of elements bytes to u32".to_string(),
                )
            })?;

        first_element_ptr = number_of_elements_addr.add(4);
    }

    Ok((number_of_elements, first_element_ptr))
}

const BYTES_PER_CHARACTER: u32 = 2;

/// # Safety
///
/// This function is unsafe because it calls a function which dereferences a raw pointer.
pub unsafe fn read_string(pid: Pid, string_ptr: *mut u8) -> Result<String, ReadMemoryError> {
    let (number_of_elements, first_element_ptr) = get_array_like_header(pid, false, string_ptr)?;
    if number_of_elements == 0 {
        return Err(ReadMemoryError::DecodeFailure(
            "string has no elements".to_string(),
        ));
    }

    if number_of_elements > 262144 {
        return Err(ReadMemoryError::DecodeFailure(
            "string is too long".to_string(),
        ));
    }

    let total_byte_count = BYTES_PER_CHARACTER * number_of_elements;
    let bytes = read_memory(pid, first_element_ptr, total_byte_count as usize)?;
    if bytes.len() != total_byte_count as usize {
        return Err(ReadMemoryError::DecodeFailure(
            "byte count mismatch on string".to_string(),
        ));
    }

    let bytes_u16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .collect();

    String::from_utf16(bytes_u16.as_slice())
        .map_err(|_| ReadMemoryError::DecodeFailure("failed to decode utf-16 string".to_string()))
}

macro_rules! create_read_primitive {
    ($type:ty) => {
        paste::paste! {
            pub fn [<read_ $type>](pid: Pid, address: *mut u8) -> Result<$type, ReadMemoryError> {
                let memory = read_memory(pid, address, std::mem::size_of::<$type>())?;

                memory
                    .as_slice()
                    .[<read_ $type>]::<LittleEndian>()
                    .map_err(|_| ReadMemoryError::DecodeFailure(concat!("failed to decode ", stringify!($type)).to_string()))
            }
        }
    };
}

create_read_primitive!(u32);
create_read_primitive!(i32);
create_read_primitive!(f32);

pub fn read_ptr(pid: Pid, address: *mut u8) -> Result<*mut u8, ReadMemoryError> {
    let ptr = read_u32(pid, address)?;
    Ok(ptr as *mut u8)
}

macro_rules! read_type_at_offset {
    ($pid:expr, $ptr:expr, $offset:expr, $type:ty) => {
        paste::paste!([<read_ $type:lower>])
        ($pid.into(), $ptr.add($offset))
    };
}
pub(crate) use read_type_at_offset;
