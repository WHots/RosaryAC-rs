//! src/memoryutils.rs

// This module contains memory utility functions based around process memory operations.





use std::{ffi::{c_void}, mem::{self, MaybeUninit}};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use std::slice;





pub mod memory_tools 
{
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, MEM_MAPPED};
    use crate::debug_log;

    use super::*;

    /// Calculates the Relative Virtual Address (RVA).
    ///
    /// # Arguments
    ///
    /// * `$base` - The base address.
    /// * `$abs_addr` - The absolute address.
    ///
    /// # Returns
    ///
    /// The RVA, calculated as `$abs_addr - $base`.
    #[macro_export]
    macro_rules! to_rva {
        ($base:expr, $abs_addr:expr) => {
            $abs_addr - $base
        };
    }

    /// Searches for a sequence (`needle`) within another sequence (`haystack`).
    ///
    /// # Safety
    ///
    /// Both pointers must be valid and `needle` must not exceed `haystack`.
    ///
    /// # Arguments
    ///
    /// * `haystack` - Pointer to the data to search.
    /// * `haystack_len` - Length of `haystack`.
    /// * `needle` - Pointer to the data to find.
    /// * `needle_len` - Length of `needle`.
    ///
    /// # Returns
    ///
    /// The starting position of `needle` within `haystack`, or `None` if not found.
    #[macro_export]
    macro_rules! memmem {
        ($haystack:expr, $haystack_len:expr, $needle:expr, $needle_len:expr) => {{
            if $haystack.is_null() || $haystack_len == 0 || $needle.is_null() || $needle_len == 0 {
                None
            } else {
                let haystack_slice = unsafe { slice::from_raw_parts($haystack, $haystack_len) };
                let needle_slice = unsafe { slice::from_raw_parts($needle, $needle_len) };

                haystack_slice.windows($needle_len).position(|window| window == needle_slice)
                    .map(|pos| unsafe { $haystack.add(pos) })
            }
        }};
    }


    #[derive(Debug)]
    pub enum ScanError
    {
        InvalidAddress,
        EmptyPattern,
        InvalidSize,
        ReadFailed(String),
    }

    impl std::fmt::Display for ScanError
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
        {
            match self
            {
                ScanError::InvalidAddress => write!(f, "Start address cannot be null"),
                ScanError::EmptyPattern => write!(f, "Search pattern cannot be empty"),
                ScanError::InvalidSize => write!(f, "Chunk size cannot be 0"),
                ScanError::ReadFailed(e) => write!(f, "Failed to read process memory: {}", e),
            }
        }
    }


    /// Reads memory from a target process.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - A handle to the process to read memory from.
    /// * `address` - The address in the target process to read memory from.
    /// * `size` - The number of bytes to read from the target process.
    ///
    /// # Returns
    ///
    /// A `Result` containing the value read from memory if successful, or an error string otherwise.
    pub fn read_memory<T: Sized>(process_handle: HANDLE, address: *const u8) -> Result<T, String>
    {

        let mut buffer = MaybeUninit::<T>::uninit();
        let mut bytes_read = 0;

        let success: BOOL = unsafe {
            ReadProcessMemory(
                process_handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                mem::size_of::<T>(),
                &mut bytes_read,
            )
        };

        if success == 0 || bytes_read != mem::size_of::<T>() {
            return Err(format!("Failed to read memory at address {:?}", address));
        }

        Ok(unsafe { buffer.assume_init() })
    }



    /// Reads memory from a target process into a buffer.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - A handle to the process to read memory from.
    /// * `address` - The address in the target process to read memory from.
    /// * `buffer` - A mutable pointer to the buffer where the read data will be stored.
    /// * `size` - The number of bytes to read from the target process.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if successful, or an error string otherwise.
    pub fn read_mem_into_buf(process_handle: HANDLE, address: *const u8, buffer: *mut u16, size: usize) -> Result<(), String>
    {
        let mut bytes_read = 0;

        let success: BOOL = unsafe { ReadProcessMemory(process_handle, address as *const c_void, buffer as *mut c_void, size, &mut bytes_read, ) };

        if success == 0 || bytes_read != size {
            debug_log!(format!("Error: size was 0: {}", unsafe {GetLastError()}));
            return Err(format!("Failed to read memory at address {:?}. Error code: {}", address, unsafe { GetLastError() }));
        }

        Ok(())
    }


    /// Checks if the memory at a given address in a target process contains a JMP instruction.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - A handle to the process to read memory from.
    /// * `address` - The address in the target process to check for a JMP instruction.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean value:
    /// - `Ok(true)` if a JMP instruction is detected at the address.
    /// - `Ok(false)` if no JMP instruction is detected at the address.
    /// - `Err(String)` if reading the memory fails, with the error string providing details.
    pub fn check_for_jmp(process_handle: HANDLE, address: *const u8) -> Result<bool, String> 
    {
        let buffer = read_memory::<[u8; 2]>(process_handle, address)?;

        match buffer.get(0) {
            Some(&0xEB) | Some(&0xE9) | Some(&0xEA) => Ok(true),
            Some(&0xFF) if buffer.len() > 1 => {
                let modrm_byte = buffer[1];
                match modrm_byte & 0x38 {
                    0x20 | 0x28 => Ok(true),
                    _ => Ok(false),
                }
            }
            Some(&byte) if (0x70..=0x7F).contains(&byte) => Ok(true),
        _ => Ok(false),
        }
    }


    /// Scans a chunk of memory in a target process for a specific pattern.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - Handle to the process to read memory from
    /// * `start_address` - Starting address to begin scanning
    /// * `chunk_size` - Total size of memory region to scan
    /// * `pattern` - Byte pattern to search for
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if pattern is found
    /// * `Ok(false)` if pattern is not found
    /// * `Err(ScanError)` if memory read fails
    pub fn scan_memory(process_handle: HANDLE, start_address: *const u8, chunk_size: usize, pattern: &[u8]) -> Result<bool, ScanError>
    {

        if start_address.is_null() {
            return Err(ScanError::InvalidAddress);
        }

        if pattern.is_empty() {
            return Err(ScanError::EmptyPattern);
        }

        if chunk_size == 0 {
            return Err(ScanError::InvalidSize);
        }

        const PAGE_SIZE: usize = 4096;
        let mut current_offset = 0;

        while current_offset < chunk_size
        {
            let remaining = chunk_size - current_offset;
            let chunk_size = remaining.min(PAGE_SIZE);

            let current_address = unsafe { start_address.add(current_offset) };

            match read_memory::<[u8; PAGE_SIZE]>(process_handle, current_address) {
                Ok(chunk) => {
                    if let Some(_) = memmem!(chunk.as_ptr(),chunk_size,pattern.as_ptr(),pattern.len()) {
                        return Ok(true);
                    }
                },
                Err(e) => {
                    debug_log!(format!("Memory read failed at {:?}: {}", current_address, e));
                    return Err(ScanError::ReadFailed(e));
                }
            }

            current_offset += PAGE_SIZE;
        }

        Ok(false)
    }


    /// Checks for mapped executable regions in a target process.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - A handle to the process to check.
    ///
    /// # Returns
    ///
    /// `true` if a mapped executable region is found, `false` otherwise.
    pub fn is_memory_mapped_exe(process_handle: HANDLE) -> bool 
    {

        let mut address = 0;
        let mut mem_info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
        let mem_info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

        while unsafe { VirtualQueryEx(process_handle, address as *const c_void, mem_info.as_mut_ptr(), mem_info_size) } != 0 
        {
            let mem_info = unsafe { mem_info.assume_init() };

            if mem_info.Type == MEM_MAPPED && mem_info.Protect == PAGE_EXECUTE_READWRITE 
            {
                return true;
            }

            address += mem_info.RegionSize;
        }

        false
    }
}