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



/// Represents information about a section within a PE file.
#[repr(C)]
pub struct SectionInfo
{
    /// The name of the section.
    pub name: String,
    /// The virtual address where the section begins.
    pub virtual_address: u32,
    /// The size of the section's raw data.
    pub size_of_raw_data: u32,
}


/// Contains validation results for a PE file.
pub struct PeValidation
{
    /// Indicates whether the PE file is valid.
    pub is_valid_pe: bool,
    /// The NT headers of the PE file, if valid.
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


/// Prints memory contents from a specified address in a process.
///
/// # Arguments
///
/// * `h_process` - A handle to the process.
/// * `base_address` - The starting address from where to read the memory.
/// * `size` - The number of bytes to read.
///
/// # Returns
///
/// A `Result` containing a vector of the read bytes or an error string.
pub fn print_memory(h_process: HANDLE, base_address: *const c_void, size: usize) -> Result<Vec<u8>, String>
{

    if size == 0
    {
        return Err("Size must be greater than zero.".into());
    }

    let mut buffer = vec![0u8; size];
    let mut bytes_read: usize = 0;

    let success: BOOL = unsafe {
        ReadProcessMemory(
            h_process,
            base_address,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            &mut bytes_read,
        )
    };

    if success == 0
    {
        return Err(format!("Failed to read process memory. Error code: {}", unsafe { GetLastError() },));
    }

    // TODO:
    // Not sure what exactly I'm going to use this for at the moment, thee idea was to have it print
    // a read memory address with the data at that address appended to it in this format [Address] - [Data].
    //
    // Ultimately it may just be something generic like string or used to detect certain opcodes.. idk.

    Ok(buffer)
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

    if nt_headers.Signature != 0x00004550 { // "PE\0\0" in little-endian
        return PeValidation { is_valid_pe: false, nt_headers: None, };
    }

    PeValidation { is_valid_pe: true, nt_headers: Some(*nt_headers), }
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
