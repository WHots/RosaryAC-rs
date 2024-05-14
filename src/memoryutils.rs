use windows_sys::Win32::System::Diagnostics::Debug::{ImageNtHeader, ReadProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::Foundation::{GetLastError, BOOL, HANDLE};
use std::{mem, slice};
use std::ffi::{c_void, CStr};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;






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



const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;





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
fn get_nt_headers(process_handle: HANDLE, base: *const u8) -> Result<IMAGE_NT_HEADERS64, String>
{

    let dos_header: IMAGE_DOS_HEADER = read_memory(process_handle, base)?;

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE
    {
        return Err("Invalid DOS signature".into());
    }

    let nt_headers_address = unsafe { base.add(dos_header.e_lfanew as usize) };
    let nt_headers: IMAGE_NT_HEADERS64 = read_memory(process_handle, nt_headers_address)?;

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
            let descriptor: IMAGE_IMPORT_DESCRIPTOR = read_memory(
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


/// Iterates over the Import Address Table (IAT) of a PE file loaded in the target process.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process containing the PE file.
/// * `base` - The base address of the PE file in the process's memory.
///
/// # Returns
///
/// A `Result` indicating success or an error string if any error occurs.
fn iterate_iat(process_handle: HANDLE, base: *const u8) -> Result<(), String>
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
            let name = read_memory::<[u8; 128]>(process_handle, name_address)?;
            let cstr_name = CStr::from_ptr(name.as_ptr() as *const i8);

            println!("Importing from: {:?}", cstr_name);

            let thunk_address = base.add(descriptor.FirstThunk as usize);
            let mut i = 0;

            loop {
                let thunk_data: IMAGE_THUNK_DATA64 = read_memory(process_handle, thunk_address.add(i * mem::size_of::<IMAGE_THUNK_DATA64>()) as *const u8)?;

                if thunk_data.u1.Function == 0
                {
                    break;
                }
                println!("Imported function address: {:?}", thunk_data.u1.Function as *const c_void);

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
            let section = read_memory::<IMAGE_SECTION_HEADER>(
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
#[inline]
fn read_memory<T: Sized>(process_handle: HANDLE, address: *const u8) -> Result<T, String>
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
        unsafe {
            return Err(format!(
                "Failed to read memory at address {:?}. Error code: {}",
                address, GetLastError()
            ));
        }
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