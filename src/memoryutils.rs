use windows_sys::Win32::System::Diagnostics::Debug::{ImageNtHeader, ReadProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::Foundation::{GetLastError, BOOL, HANDLE, HMODULE};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use std::{mem, slice};
use std::ffi::c_void;







/// Converts an absolute address to a relative virtual address (RVA).
macro_rules! to_rva {
    ($base:expr, $abs_addr:expr) => {
        $abs_addr - $base
    };
}



#[repr(C)]
pub struct SectionInfo
{
    pub name: String,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
}


pub struct PeValidation
{
    pub is_valid_pe: bool,
    pub nt_headers: Option<IMAGE_NT_HEADERS64>,
}



/// Retrieves information about sections in a PE file with the specified name.
///
/// # Safety
///
/// This function is unsafe because it performs raw pointer dereferencing.
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

    if EnumProcessModules(h_process, &mut h_module as *mut _ as *mut HMODULE, mem::size_of::<HMODULE>() as u32, &mut cb_needed) == 0
    {
        return sections;
    }

    let mut module_info: MODULEINFO = mem::zeroed();

    if GetModuleInformation(h_process, h_module, &mut module_info, mem::size_of::<MODULEINFO>() as u32) == 0
    {
        return sections;
    }

    let module_base = module_info.lpBaseOfDll as *const u8;
    let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
    let nt_headers = &*(module_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);

    let section_headers = slice::from_raw_parts(
        (nt_headers as *const _ as *const u8).offset(mem::size_of::<IMAGE_NT_HEADERS64>() as isize) as *const IMAGE_SECTION_HEADER,
        nt_headers.FileHeader.NumberOfSections as usize,
    );

    for i in 0..nt_headers.FileHeader.NumberOfSections as usize
    {
        let section = &section_headers[i];
        let name_buffer = slice::from_raw_parts(section.Name.as_ptr(), 8);
        let section_name_str = String::from_utf8_lossy(name_buffer);

        if section_name_str.trim_end_matches('\0') == section_name
        {
            sections.push(SectionInfo {
                name: section_name_str.to_string(),
                virtual_address: section.VirtualAddress,
                size_of_raw_data: section.SizeOfRawData,
            });
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
pub fn check_byte_codes(h_process: HANDLE, base_address: *const c_void, size: usize, byte_codes: &[u8]) -> Result<bool, String>
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

    let found = memmem(
        buffer.as_ptr(),
        buffer.len(),
        byte_codes.as_ptr(),
        byte_codes.len(),
    ).is_some();

    Ok(found)
}


/// Validates the PE file format of a process.
///
/// # Safety
///
/// This function is unsafe because it performs raw pointer dereferencing.
///
/// # Arguments
///
/// * `h_process` - A handle to the process to validate.
///
/// # Returns
///
/// A `PeValidation` struct containing the validation results.
pub unsafe fn validate_pe(h_process: HANDLE) -> PeValidation
{

    let nt_headers_addr = ImageNtHeader(h_process as _);

    if nt_headers_addr.is_null() {
        return PeValidation { is_valid_pe: false, nt_headers: None, };
    }

    let nt_headers = &*(nt_headers_addr as *const IMAGE_NT_HEADERS64);

    if nt_headers.Signature != 0x00004550
    {
        return PeValidation { is_valid_pe: false, nt_headers: None, };
    }

    PeValidation { is_valid_pe: true, nt_headers: Some(*nt_headers), }
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
#[inline]
fn memmem(haystack: *const u8, haystack_len: usize, needle: *const u8, needle_len: usize) -> Option<*const u8>
{

    if haystack.is_null() || haystack_len == 0 || needle.is_null() || needle_len == 0
    {
        return None;
    }

    let haystack_slice = unsafe { slice::from_raw_parts(haystack, haystack_len) };
    let needle_slice = unsafe { slice::from_raw_parts(needle, needle_len) };

    haystack_slice.windows(needle_len).position(|window| window == needle_slice).map(|pos| unsafe { haystack.add(pos) })
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
