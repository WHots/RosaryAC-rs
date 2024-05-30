use std::ffi::{c_void};
use std::{mem, slice};
use windows_sys::Win32::Foundation::{HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
use crate::memoryutils;
use crate::stringutils::read_c_string;







#[repr(C)]
pub struct SectionInfo
{
    pub name: String,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
}



const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;





/// Iterates over the Import Address Table (IAT) of a PE file in the specified process, printing the names of imported functions and their addresses.
///
/// # Safety
///
/// This function is unsafe due to raw pointer dereferencing and handling of external process memory.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process containing the PE file.
/// * `base` - The base address of the PE file in the process's memory.
///
/// # Returns
///
/// A `Result` indicating success or an error string if any error occurs.
pub fn iterate_iat(process_handle: HANDLE, base: *const u8) -> Result<(), String>
{

    let nt_headers = get_nt_headers(process_handle, base)?;
    let import_descriptors = get_import_descriptors(process_handle, &nt_headers, base)?;

    unsafe {

        for descriptor in import_descriptors.iter()
        {
            if descriptor.Name == 0
            {
                break;
            }

            let name_address = base.add(descriptor.Name as usize);

            match read_c_string(process_handle, name_address)
            {
                Ok(module_name) => println!("Importing from: {}", module_name),
                Err(e) => {
                    eprintln!("Error reading module name: {}", e);
                    continue;
                }
            }

            let original_thunk_address = base.add(descriptor.Anonymous.OriginalFirstThunk as usize);
            let thunk_address = base.add(descriptor.FirstThunk as usize);
            let mut i = 0;

            loop {

                let original_thunk_data: IMAGE_THUNK_DATA64 = match memoryutils::read_memory(process_handle, original_thunk_address.add(i * mem::size_of::<IMAGE_THUNK_DATA64>()) as *const u8) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error reading original thunk data: {}", e);
                        break;
                    }
                };

                let thunk_data: IMAGE_THUNK_DATA64 = match memoryutils::read_memory(process_handle, thunk_address.add(i * mem::size_of::<IMAGE_THUNK_DATA64>()) as *const u8) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error reading thunk data: {}", e);
                        break;
                    }
                };

                if original_thunk_data.u1.AddressOfData == 0
                {
                    break;
                }

                let func_name_address = base.add(original_thunk_data.u1.AddressOfData as usize) as *const u8;

                match read_c_string(process_handle, func_name_address)
                {
                    Ok(function_name) => println!("Imported function name: {}, address: {:?}", function_name, thunk_data.u1.Function as *const c_void),
                    Err(e) => eprintln!("Error reading function name: {}", e),
                }

                i += 1;
            }
        }
    }

    Ok(())
}


/// Retrieves information about sections in a PE file with the specified name.
///
/// # Safety
///
/// This function is unsafe due to raw pointer dereferencing.
///
/// # Arguments
///
/// * `section_name` - The name of the section to retrieve information for.
/// * `process_handle` - A handle to the process containing the PE file.
/// * `base` - The base address of the PE file in the process's memory.
///
/// # Returns
///
/// A `Result` containing an optional `SectionInfo` struct with information about the section, or an error string if any error occurs.
pub unsafe fn display_section_info(section_name: &str, process_handle: HANDLE, base: *const c_void) -> Result<Option<SectionInfo>, String>
{

    let mut memory_info: MEMORY_BASIC_INFORMATION = mem::zeroed();
    let mut base_address = base as usize;

    while VirtualQueryEx(process_handle, base_address as _, &mut memory_info, mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0
    {
        let headers = (memory_info.BaseAddress as *const IMAGE_NT_HEADERS64).read_unaligned();
        let sections_start = headers.OptionalHeader.DataDirectory[2].VirtualAddress as usize;
        let section_headers = (memory_info.BaseAddress as usize + sections_start) as *const IMAGE_SECTION_HEADER;

        for i in 0..headers.FileHeader.NumberOfSections
        {
            let section = memoryutils::read_memory::<IMAGE_SECTION_HEADER>(
                process_handle,
                section_headers.add(i as usize) as *const u8
            )?;

            let name_bytes = slice::from_raw_parts(section.Name.as_ptr(), 8);
            let name_end = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);
            let name = std::str::from_utf8(&name_bytes[..name_end]).map_err(|_| "Invalid section name".to_string())?;

            if name.starts_with(section_name)
            {
                return Ok(Some(SectionInfo { name: name.to_string(), virtual_address: section.VirtualAddress, size_of_raw_data: section.SizeOfRawData, }));
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


/// Retrieves the NT headers of a PE file loaded in the target process.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process containing the PE file.
/// * `base` - The base address of the PE file in the process's memory.
///
/// # Returns
///
/// A `Result` containing the `IMAGE_NT_HEADERS64` if successful, or an error string otherwise.
#[inline]
fn get_nt_headers(process_handle: HANDLE, base: *const u8) -> Result<IMAGE_NT_HEADERS64, String>
{

    let dos_header: IMAGE_DOS_HEADER = memoryutils::read_memory(process_handle, base)?;

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE
    {
        return Err("Invalid DOS signature".into());
    }

    let nt_headers_address = unsafe { base.add(dos_header.e_lfanew as usize) };
    let nt_headers: IMAGE_NT_HEADERS64 = memoryutils::read_memory(process_handle, nt_headers_address)?;

    if nt_headers.Signature != IMAGE_NT_SIGNATURE
    {
        return Err("Invalid NT signature".into());
    }

    Ok(nt_headers)
}


/// Retrieves the import descriptors of a PE file loaded in the target process.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process containing the PE file.
/// * `nt_headers` - A reference to the NT headers of the PE file.
/// * `base` - The base address of the PE file in the process's memory.
///
/// # Returns
///
/// A `Result` containing a vector of `IMAGE_IMPORT_DESCRIPTOR` if successful, or an error string otherwise.
#[inline]
fn get_import_descriptors(process_handle: HANDLE, nt_headers: &IMAGE_NT_HEADERS64, base: *const u8) -> Result<Vec<IMAGE_IMPORT_DESCRIPTOR>, String>
{

    let import_directory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if import_directory.VirtualAddress == 0
    {
        return Err("No import directory found".into());
    }

    let import_descriptor_address = unsafe { base.add(import_directory.VirtualAddress as usize) };
    let num_descriptors = import_directory.Size / mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u32;
    let mut import_descriptors = Vec::with_capacity(num_descriptors as usize);

    unsafe {
        for i in 0..num_descriptors
        {
            let descriptor: IMAGE_IMPORT_DESCRIPTOR = memoryutils::read_memory(
                process_handle,
                import_descriptor_address.add(i as usize * mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as *const u8
            )?;

            if descriptor.Name == 0
            {
                break;
            }

            import_descriptors.push(descriptor);
        }
    }

    Ok(import_descriptors)
}