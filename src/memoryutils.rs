//! src/memoryutils.rs

// This module contains memory utility functions based around process memory operations.





pub mod memory_tools
{
    use std::ffi::c_void;
    use std::{mem, mem::MaybeUninit, slice};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, MEM_MAPPED};

    use crate::{debug_log, processutils::ProcessError};




    /// Macro for finding a byte pattern within a larger sequence.
    ///
    /// # Arguments
    /// * `haystack` - Pointer to the data to search in
    /// * `haystack_len` - Length of haystack data
    /// * `needle` - Pointer to pattern to find
    /// * `needle_len` - Length of pattern
    ///
    /// # Returns
    /// Optional pointer to first match position, or None if not found
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


    /// Represents possible errors during memory scanning operations
    #[derive(Debug)]
    pub enum ScanError
    {
        /// Invalid memory address
        InvalidAddress,
        /// Pattern was empty
        EmptyPattern,
        /// Invalid size
        InvalidSize,
        /// Read operation failed
        ReadFailed
    }


    impl std::fmt::Display for ScanError
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
        {
            let msg = match self {
                ScanError::InvalidAddress => "Start address cannot be null",
                ScanError::EmptyPattern => "Search pattern cannot be empty",
                ScanError::InvalidSize => "Chunk size cannot be 0",
                ScanError::ReadFailed => "Failed reading memory operation"
            };
            write!(f, "{}", msg)
        }
    }



    /// Reads a sized type T from process memory at specified address
    ///
    /// # Arguments
    /// * `process_handle` - Handle to the target process
    /// * `address` - Memory address to read from
    ///
    /// # Returns
    /// * `Ok(T)` - Successfully read value
    /// * `Err(ProcessError)` - Read operation failed
    #[inline]
    pub fn read_memory<T: Sized>(process_handle: HANDLE, address: *const u8) -> Result<T, ProcessError>
    {

        let mut buffer = MaybeUninit::<T>::uninit();
        let mut bytes_read = 0;

        (!unsafe {
            ReadProcessMemory(
                process_handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                mem::size_of::<T>(),
                &mut bytes_read,
            )
        }.eq(&0) && bytes_read == mem::size_of::<T>())
            .then(|| unsafe { buffer.assume_init() })
            .ok_or_else(|| {
                let e = ProcessError::ProcessInfoQueryFailed;
                debug_log!(e);
                e
            })
    }


    /// Reads process memory into provided buffer
    ///
    /// # Arguments
    /// * `process_handle` - Handle to target process
    /// * `address` - Source memory address
    /// * `buffer` - Destination buffer
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    /// * `Ok(())` - Read succeeded
    /// * `Err(ProcessError)` - Read failed
    pub fn read_mem_into_buf(process_handle: HANDLE, address: *const u8, buffer: *mut u16, size: usize) -> Result<(), ProcessError>
    {
        let mut bytes_read = 0;
        (!unsafe { ReadProcessMemory(process_handle, address as *const c_void, buffer as *mut c_void, size, &mut bytes_read) }.eq(&0) && bytes_read == size)
            .then_some(())
            .ok_or_else(|| {
                let e = ProcessError::ProcessInfoQueryFailed;
                debug_log!(e);
                e
            })
    }


    /// Detects JMP instruction at memory address
    ///
    /// # Arguments
    /// * `process_handle` - Handle to target process
    /// * `address` - Memory address to check
    ///
    /// # Returns
    /// * `Ok(true)` - JMP instruction found
    /// * `Ok(false)` - No JMP instruction
    /// * `Err(ProcessError)` - Read failed
    pub fn check_for_jmp(process_handle: HANDLE, address: *const u8) -> Result<bool, ProcessError>
    {
        let buffer = read_memory::<[u8; 2]>(process_handle, address)?;
        Ok(match buffer.get(0) {
            Some(&0xEB) | Some(&0xE9) | Some(&0xEA) => true,
            Some(&0xFF) if buffer.len() > 1 => matches!(buffer[1] & 0x38, 0x20 | 0x28),
            Some(&byte) if (0x70..=0x7F).contains(&byte) => true,
            _ => false,
        })
    }


    /// Scans memory region for byte pattern
    ///
    /// # Arguments
    /// * `process_handle` - Handle to target process
    /// * `start_address` - Starting address of region
    /// * `chunk_size` - Size of region to scan
    /// * `pattern` - Byte pattern to find
    ///
    /// # Returns
    /// * `Ok(true)` - Pattern found
    /// * `Ok(false)` - Pattern not found
    /// * `Err(ScanError)` - Scan operation failed
    pub fn scan_memory(process_handle: HANDLE, start_address: *const u8, chunk_size: usize, pattern: &[u8]) -> Result<bool, ScanError>
    {

        if start_address.is_null() { return Err(ScanError::InvalidAddress); }
        if pattern.is_empty() { return Err(ScanError::EmptyPattern); }
        if chunk_size == 0 { return Err(ScanError::InvalidSize); }

        const PAGE_SIZE: usize = 4096;
        let mut current_offset = 0;

        while current_offset < chunk_size {
            let chunk_size = (chunk_size - current_offset).min(PAGE_SIZE);
            let current_address = unsafe { start_address.add(current_offset) };

            match read_memory::<[u8; PAGE_SIZE]>(process_handle, current_address) {
                Ok(chunk) => {
                    if memmem!(chunk.as_ptr(), chunk_size, pattern.as_ptr(), pattern.len()).is_some() {
                        return Ok(true);
                    }
                },
                Err(e) => {
                    debug_log!(e);
                    return Err(ScanError::ReadFailed);
                }
            }
            current_offset += PAGE_SIZE;
        }
        Ok(false)
    }


    /// Checks if process has mapped executable memory regions
    ///
    /// # Arguments
    /// * `process_handle` - Handle to target process
    ///
    /// # Returns
    /// `true` if executable mapped regions found, `false` otherwise
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