use std::{ffi::{c_void, CStr}, io, mem::{self, MaybeUninit}, ptr, slice};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;










pub mod memory_tools 
{
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, MEM_MAPPED};

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



    /// Enum for breakpoint opcodes.
    #[repr(u8)]
    pub enum BreakpointOpcode 
    {
        Int3 = 0xCC, // Int3
        Int1 = 0xF1, // ICE
    }




    /// Checks if an address is canonical on x64 systems.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check.
    ///
    /// # Returns
    ///
    /// `true` if the address is canonical, otherwise `false`.
    #[inline]
    fn is_canonical(address: u64) -> bool
    {
        let upper_bits = address >> 47;
        upper_bits == 0 || upper_bits == (1 << 17) - 1
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

        if success == 0 || bytes_read != mem::size_of::<T>() 
        {
            return Err(format!("Failed to read memory at address {:?}. Error code: {}", address, unsafe { GetLastError() } ));
        }

        Ok(unsafe { buffer.assume_init() })
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
    /// * `process_handle` - A handle to the process to read memory from.
    /// * `start_address` - The starting address in the target process to begin scanning.
    /// * `chunk_size` - The size of the memory chunk to scan.
    /// * `pattern` - The pattern to search for within the memory chunk.
    ///
    /// # Returns
    ///
    /// A `Result` containing `true` if the pattern is found, or `false` if not.
    /// Returns `Err(())` if there is a failure reading the memory.
    pub fn scan_memory(process_handle: HANDLE, start_address: *const u8, chunk_size: usize, pattern: &[u8], ) -> Result<bool, ()> 
    {
        for offset in (0..chunk_size).step_by(4096) 
        {
            let current_address = unsafe { start_address.add(offset) };

            match read_memory::<[u8; 4096]>(process_handle, current_address) 
            {
                Ok(chunk) => 
                {
                    let result = memmem!(chunk.as_ptr(), chunk.len(), pattern.as_ptr(), pattern.len());

                    if result.is_some() 
                    {
                        return Ok(true);
                    }
                }
                Err(_) => return Err(()),
            }
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