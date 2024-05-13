use windows_sys::Win32::System::Diagnostics::Debug::{ImageNtHeader, ReadProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::Foundation::{GetLastError, BOOL, HANDLE, HMODULE};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use std::{mem, slice};
use std::ffi::{c_void, CStr};








macro_rules! to_rva {
    ($base:expr, $abs_addr:expr) => {
        $abs_addr - $base
    };
}


macro_rules! get_dos_header {
    ($module_base:expr) => {
        &*($module_base as *const IMAGE_DOS_HEADER)
    };
}


macro_rules! get_nt_headers {
    ($module_base:expr, $dos_header:expr) => {
        &*($module_base.offset($dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64)
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
macro_rules! memmem
{
    ($haystack:expr, $haystack_len:expr, $needle:expr, $needle_len:expr) => {{

        if $haystack.is_null() || $haystack_len == 0 || $needle.is_null() || $needle_len == 0
        {
            None
        }
        else
        {
            let haystack_slice = unsafe { std::slice::from_raw_parts($haystack, $haystack_len) };
            let needle_slice = unsafe { std::slice::from_raw_parts($needle, $needle_len) };

            haystack_slice.windows($needle_len).position(|window| window == needle_slice)
                .map(|pos| unsafe { $haystack.add(pos) })
        }
    }};
}


#[repr(u8)]
enum BreakpointOpcode
{
    Int3 = 0xCC,    //  Int3
    Int1 = 0xF1,    //  ICE
}


#[repr(C)]
pub struct SectionInfo
{
    pub name: String,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
}



/// Retrieves information about sections in a PE file with the specified name.
///
/// # Safety
///
/// This function is unsafe due to raw pointer dereferencing. womp womp :(
///
/// # Arguments
///
/// * `h_process` - A handle to the process containing the PE file.
/// * `section_name` - The name of the section to retrieve information for.
///
/// # Returns
///
/// A vector of `SectionInfo` structs containing information about each section found.
pub unsafe fn get_section_info(h_process: HANDLE, section_name: &str) -> Vec<SectionInfo>
{

    let mut sections = Vec::new();
    let mut h_module: HMODULE = 0;
    let mut cb_needed = 0;
    let hmodule_size = mem::size_of::<HMODULE>() as u32;
    let moduleinfo_size = mem::size_of::<MODULEINFO>() as u32;

    if EnumProcessModules(h_process, &mut h_module as *mut _ as *mut HMODULE, hmodule_size, &mut cb_needed) == 0
    {
        return sections;
    }

    let mut module_info: MODULEINFO = mem::zeroed();

    if GetModuleInformation(h_process, h_module, &mut module_info, moduleinfo_size) == 0 {
        return sections;
    }

    let dos_header = get_dos_header!(module_info.lpBaseOfDll);
    let nt_headers = get_nt_headers!(module_info.lpBaseOfDll, dos_header);

    let num_sections = nt_headers.FileHeader.NumberOfSections;

    let first_section = (nt_headers as *const _ as usize + nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;

    for i in 0..num_sections
    {
        let section = first_section.offset(i as isize);
        let section_ref = &*section;

        let name = CStr::from_ptr(section_ref.Name.as_ptr() as *const i8).to_string_lossy().into_owned();

        if name.starts_with(section_name)
        {
            let info = SectionInfo {
                name,
                virtual_address: to_rva!(module_info.lpBaseOfDll as u32, section_ref.VirtualAddress),
                size_of_raw_data: section_ref.SizeOfRawData,
            };
            sections.push(info);
        }
    }

    sections
}


/// Checks for the presence of a specified sequence of byte codes in a process's memory.
///
/// # Arguments
///
/// * `h_process` - A handle to the process whose memory is being checked.
/// * `base_address` - The starting address from where to read the memory.
/// * `size` - The number of bytes to read from the memory.
/// * `byte_codes` - A slice of byte codes to search for in the memory.
///
/// # Returns
///
/// A `Result` containing `true` if the specified sequence of byte codes is found,
/// or `false` otherwise. Returns an error string if the read fails, including the base address and size attempted.
pub fn compare_bytes(h_process: HANDLE, base_address: *const c_void, size: usize, byte_codes: &[u8]) -> Result<bool, String>
{

    if base_address.is_null() || h_process == 0
    {
        return Err(format!("Issue with process handle. Error code: {}", unsafe { GetLastError() }));
    }


    let mut buffer = vec![0u8; size];
    let mut bytes_read: usize = 0;

    let success: BOOL = unsafe {
        ReadProcessMemory(
            h_process,
            base_address as *mut _,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read as *mut _ as *mut _,
        )
    };

    if success == 0
    {
        return Err(format!("Failed to read process memory. Error code: {}", unsafe { GetLastError() }));
    }

    let found = memmem!(buffer.as_ptr(), buffer.len(), byte_codes.as_ptr(), byte_codes.len()).is_some();

    Ok(found)
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
