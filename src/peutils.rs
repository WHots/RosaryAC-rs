//! src/peutils.rs

// This module contains utility functions based around interaction with a Process Environment.





use std::mem;
use std::slice;
use std::fmt;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use windows_sys::Win32::Foundation::{BOOL, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, ReadProcessMemory};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE};
use crate::debug_log;
use crate::memorymanage::CleanBuffer;

use crate::memoryutils::memory_tools::{read_mem_into_buf, read_memory};
use crate::stringutils::{read_c_string, strings_match};




const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;



#[repr(C)]
#[derive(Debug)]
pub struct SectionInfo
{
    pub name: String,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
}


/// Result of iterating through the Import Address Table (IAT).
pub enum IATResult
{
    /// The function was found in the IAT.
    Found,
    /// The function was not found in the IAT.
    NotFound,
    /// The execution failed while iterating through the IAT.
    FailedExecution,
}


/// Various errors that can occur while processing PE (Portable Executable) files.
#[derive(Debug)]
pub enum PEError
{
    /// Failed to read memory from the process.
    ReadMemoryFailed,
    /// The DOS signature is invalid.
    InvalidDosSignature,
    /// The NT signature is invalid.
    InvalidNtSignature,
    /// No import directory was found in the PE file.
    NoImportDirectory,
    /// Failed execution while processing the PE file.
    FailedExecution,
    /// The section name is invalid.
    InvalidSectionName,
    /// The size of section is 0.
    PESectionsZero,
    /// Process or operation not initialized.
    Uninitialized,
}


impl Display for PEError
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
    {
        let msg = match self {
            PEError::ReadMemoryFailed => "Failed to read memory",
            PEError::InvalidDosSignature => "Invalid DOS signature",
            PEError::InvalidNtSignature => "Invalid NT signature",
            PEError::NoImportDirectory => "No import directory found",
            PEError::FailedExecution => "Failed execution",
            PEError::InvalidSectionName => "Invalid section name",
            PEError::PESectionsZero => "No valid PE sections found",
            PEError::Uninitialized => "Not initialized",
        };
        f.write_str(msg)
    }
}




/// Retrieves the NT headers from the process's memory given the base address.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process.
/// * `base` - The base address in the process's memory.
///
/// # Returns
///
/// A `Result` containing the `IMAGE_NT_HEADERS64` if successful, or a `PEError` otherwise.
#[inline]
fn get_nt_headers(process_handle: HANDLE, base: *const u8) -> Result<IMAGE_NT_HEADERS64, PEError> 
{

    let dos_header: IMAGE_DOS_HEADER = read_memory(process_handle, base).map_err(|_| PEError::ReadMemoryFailed)?;

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE 
    {
        debug_log!(format!("Error invalid dos signature: {}", unsafe {GetLastError()}));
        return Err(PEError::InvalidDosSignature);
    }

    let nt_headers_address = unsafe { base.add(dos_header.e_lfanew as usize) };
    let nt_headers: IMAGE_NT_HEADERS64 = read_memory(process_handle, nt_headers_address).map_err(|_| PEError::ReadMemoryFailed)?;

    if nt_headers.Signature != IMAGE_NT_SIGNATURE 
    {
        debug_log!(format!("Error invalid Nt signature: {}", unsafe {GetLastError()}));
        return Err(PEError::InvalidNtSignature);
    }

    Ok(nt_headers)
}


/// Retrieves the import descriptors from the NT headers.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process.
/// * `nt_headers` - A reference to the NT headers.
/// * `base` - The base address in the process's memory.
///
/// # Returns
///
/// A `Result` containing a vector of `IMAGE_IMPORT_DESCRIPTOR` if successful, or a `PEError` otherwise.
#[inline]
fn get_import_descriptors(process_handle: HANDLE, nt_headers: &IMAGE_NT_HEADERS64, base: *const u8, ) -> Result<Vec<IMAGE_IMPORT_DESCRIPTOR>, PEError> 
{

    let import_directory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if import_directory.VirtualAddress == 0 
    {
        debug_log!(format!("Error no import directory: {}", unsafe {GetLastError()}));
        return Err(PEError::NoImportDirectory);
    }

    let import_descriptor_address = unsafe { base.add(import_directory.VirtualAddress as usize) };
    let num_descriptors = import_directory.Size / mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u32;
    let mut import_descriptors = Vec::with_capacity(num_descriptors as usize);

    unsafe {

        for i in 0..num_descriptors 
        {
            let descriptor: IMAGE_IMPORT_DESCRIPTOR = read_memory(
                process_handle,
                import_descriptor_address.add(i as usize * mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as *const u8,
            )
            .map_err(|_| PEError::ReadMemoryFailed)?;

            if descriptor.Name == 0 {
                break;
            }

            import_descriptors.push(descriptor);
        }
    }

    Ok(import_descriptors)
}


/// Iterates through the Import Address Table (IAT) to find a specific function name.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process.
/// * `base` - The base address in the process's memory.
/// * `search_name` - The function name to search for.
///
/// # Returns
///
/// A `Result` containing `IATResult::Found` if the function is found, `IATResult::NotFound` if not found, or a `PEError` otherwise.
pub fn search_iat(process_handle: HANDLE, base: *const u8, search_name: &str) -> Result<IATResult, PEError>
{

    let nt_headers = get_nt_headers(process_handle, base)?;
    let import_descriptors = get_import_descriptors(process_handle, &nt_headers, base)?;

    for descriptor in import_descriptors.iter() 
    {
        if descriptor.Name == 0 
        {
            return Ok(IATResult::FailedExecution);
        }

        let name_address = unsafe { base.add(descriptor.Name as usize) };

        let _module_name = match read_c_string(process_handle, name_address) {
            Ok(module_name) => module_name,
            Err(_) => {
                debug_log!(format!("Error reading memory failed: {}", unsafe {GetLastError()}));
                return Err(PEError::ReadMemoryFailed);
            }
        };

        let original_thunk_address = unsafe { base.add(descriptor.Anonymous.OriginalFirstThunk as usize) };
        let mut i = 0;

        loop {

            let original_thunk_data: IMAGE_THUNK_DATA64 = read_memory(process_handle, unsafe { original_thunk_address.add(i * std::mem::size_of::<IMAGE_THUNK_DATA64>()) } as *const u8, ).map_err(|_| PEError::ReadMemoryFailed)?;

            if unsafe { original_thunk_data.u1.AddressOfData } == 0 
            {
                break;
            }

            let func_name_address = unsafe { base.add(original_thunk_data.u1.AddressOfData as usize) };

            match read_c_string(process_handle, func_name_address) 
            {
                Ok(function_name) => {
                    if strings_match(&function_name, search_name)
                    {
                        return Ok(IATResult::Found);
                    }
                },
                Err(_) => {
                    debug_log!(format!("Error Reading C string: {}", unsafe {GetLastError()}));
                    return Err(PEError::ReadMemoryFailed);
                }
            }

            i += 1;
        }
    }

    Ok(IATResult::NotFound)
}


/// Displays information about a specific section in the process's memory.
///
/// # Arguments
///
/// * `section_name` - The name of the section to display information about.
/// * `process_handle` - A handle to the process.
/// * `base` - The base address in the process's memory.
///
/// # Returns
///
/// A `Result` containing an `Option` with `SectionInfo` if the section is found, or a `PEError` otherwise.
pub unsafe fn display_section_info(section_name: &str, process_handle: HANDLE, base: *const c_void,) -> Result<Option<SectionInfo>, PEError> 
{

    let mut memory_info: MEMORY_BASIC_INFORMATION = mem::zeroed();
    let mut base_address = base as usize;

    while VirtualQueryEx(process_handle,base_address as _, &mut memory_info, mem::size_of::<MEMORY_BASIC_INFORMATION>(), ) != 0
    {

        let headers = (memory_info.BaseAddress as *const IMAGE_NT_HEADERS64).read_unaligned();
        let sections_start = headers.OptionalHeader.DataDirectory[2].VirtualAddress as usize;
        let section_headers = (memory_info.BaseAddress as usize + sections_start) as *const IMAGE_SECTION_HEADER;

        for i in 0..headers.FileHeader.NumberOfSections 
        {
            let section = read_memory::<IMAGE_SECTION_HEADER>(process_handle, section_headers.add(i as usize) as *const u8).map_err(|_| PEError::ReadMemoryFailed)?;

            let name_bytes = slice::from_raw_parts(section.Name.as_ptr(), 8);
            let name_end = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);
            let name = std::str::from_utf8(&name_bytes[..name_end]).map_err(|_| PEError::InvalidSectionName)?;

            if name.starts_with(section_name) 
            {
                return Ok(Some(SectionInfo {name: name.to_string(), virtual_address: section.VirtualAddress, size_of_raw_data: section.SizeOfRawData, }));
            }
        }

        if memory_info.RegionSize == 0 
        {
            break;
        }

        base_address += memory_info.RegionSize;
    }

    Ok(None)
}


/// Checks if the PE in the process's memory is zeroed out.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process.
/// * `base` - The base address in the process's memory.
///
/// # Returns
///
/// A `Result` containing a boolean indicating whether the PE is zeroed out, or a `PEError` otherwise.
pub fn is_pe_zeroed(process_handle: HANDLE, base: *const u8) -> Result<bool, PEError>
{

    const MAX_PE_SIZE: usize = 2 * 1024 * 1024;
    const MIN_PE_SIZE: usize = 0x1000;
    const PE_ZEROED_PERCENTAGE: f64 = 0.85;
    const PE_TOTAL_ZEROED: f64 = 0.45;


    let dos_header: IMAGE_DOS_HEADER = read_memory(process_handle, base).map_err(|_| PEError::ReadMemoryFailed)?;

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew <= 0 || (dos_header.e_lfanew as usize) > MAX_PE_SIZE
    {
        return Err(PEError::InvalidDosSignature);
    }

    let nt_headers: IMAGE_NT_HEADERS64 = read_memory(process_handle, unsafe { base.add(dos_header.e_lfanew as usize) }).map_err(|_| PEError::ReadMemoryFailed)?;

    if nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.FileHeader.NumberOfSections == 0 || nt_headers.FileHeader.NumberOfSections > 96
    {
        return Err(PEError::InvalidNtSignature);
    }

    let section_headers_address = unsafe { base.add(dos_header.e_lfanew as usize).add(mem::size_of::<IMAGE_NT_HEADERS64>()) };

    let mut total_sections = 0;
    let mut zeroed_sections = 0;

    for i in 0..nt_headers.FileHeader.NumberOfSections
    {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process_handle,
            unsafe {
                section_headers_address.add(i as usize * mem::size_of::<IMAGE_SECTION_HEADER>())
            } as *const u8
        ).map_err(|_| PEError::ReadMemoryFailed)?;

        if section_header.SizeOfRawData == 0 || (section_header.SizeOfRawData as usize) > MAX_PE_SIZE || (section_header.VirtualAddress as usize) > MAX_PE_SIZE || (section_header.SizeOfRawData as usize) < MIN_PE_SIZE
        {
            continue;
        }

        let section_data_size = section_header.SizeOfRawData as usize;
        let mut section_data = CleanBuffer::new(section_data_size);

        if let Ok(_) = read_mem_into_buf(process_handle, unsafe { base.add(section_header.VirtualAddress as usize) }, section_data.as_mut_ptr(), section_data_size)
        {

            total_sections += 1;

            let zero_count = section_data.as_slice().iter().filter(|&&byte| byte == 0).count();

            if (zero_count as f64 / section_data_size as f64) > PE_ZEROED_PERCENTAGE
            {
                zeroed_sections += 1;
            }
        }
    }

    if total_sections > 0
    {
        Ok(zeroed_sections as f64 / total_sections as f64 > PE_TOTAL_ZEROED)
    }
    else
    {
        let e = PEError::PESectionsZero;
        debug_log!(e);
        Err(e)
    }
}


/// Gets all section names from a PE file in memory.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process.
/// * `base` - The base address in the process's memory.
///
/// # Returns
///
/// A `Result` containing a vector of section names as String if successful, or a `PEError` otherwise.
pub fn get_pe_sections(process_handle: HANDLE, base: *const u8) -> Result<Vec<String>, PEError>
{

    const MAX_PE_SIZE: usize = 2 * 1024 * 1024; // 2MB

    let dos_header: IMAGE_DOS_HEADER = read_memory(process_handle, base).map_err(|_| PEError::ReadMemoryFailed)?;

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew <= 0 || (dos_header.e_lfanew as usize) > MAX_PE_SIZE
    {
        debug_log!(PEError::InvalidDosSignature);
        return Err(PEError::InvalidDosSignature);
    }

    let nt_headers: IMAGE_NT_HEADERS64 = read_memory(process_handle, unsafe { base.add(dos_header.e_lfanew as usize) }).map_err(|_| PEError::ReadMemoryFailed)?;

    if nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.FileHeader.NumberOfSections == 0 || nt_headers.FileHeader.NumberOfSections > 96
    {
        debug_log!(PEError::InvalidNtSignature);
        return Err(PEError::InvalidNtSignature);
    }

    let section_headers_address = unsafe { base.add(dos_header.e_lfanew as usize).add(mem::size_of::<IMAGE_NT_HEADERS64>()) };

    let mut section_names = Vec::with_capacity(nt_headers.FileHeader.NumberOfSections as usize);

    for i in 0..nt_headers.FileHeader.NumberOfSections
    {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process_handle,
            unsafe {
                section_headers_address.add(i as usize * mem::size_of::<IMAGE_SECTION_HEADER>())
            }
        ).map_err(|_| PEError::ReadMemoryFailed)?;

        let name_bytes = unsafe { slice::from_raw_parts(section_header.Name.as_ptr(), 8) };
        let name_end = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);

        let section_name = match std::str::from_utf8(&name_bytes[..name_end]) {
            Ok(name) => {

                let name = name.trim();

                if name.is_empty()
                {
                    "null".to_string()
                }
                else
                {
                    name.to_string()
                }
            },
            Err(_) => "null".to_string()
        };

        section_names.push(section_name);
    }

    Ok(section_names)
}