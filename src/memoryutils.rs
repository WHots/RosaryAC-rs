use std::{ffi::{c_void, CStr}, io, mem, ptr, slice};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory};





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
enum BreakpointOpcode
{
    Int3 = 0xCC, // Int3
    Int1 = 0xF1, // ICE
}




/// Reads memory from a target process.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process to read memory from.
/// * `address` - The address in the target process to read memory from.
///
/// # Returns
///
/// A `Result` containing the value read from memory if successful, or an error string otherwise.
pub fn read_memory<T: Sized>(process_handle: HANDLE, address: *const u8) -> Result<T, String>
{

    let mut buffer: T = unsafe { mem::zeroed() };
    let mut bytes_read = 0;

    let success: BOOL = unsafe {
        ReadProcessMemory(
            process_handle,
            address as *const c_void,
            &mut buffer as *mut _ as *mut c_void,
            mem::size_of::<T>(),
            &mut bytes_read,
        )
    };

    if success == 0 || bytes_read != mem::size_of::<T>()
    {
        return Err(format!("Failed to read memory at address {:?}. Error code: {}", address, unsafe { GetLastError() }));
    }

    Ok(buffer)
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
