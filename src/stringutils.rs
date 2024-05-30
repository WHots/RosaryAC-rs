use std::ffi::CString;
use windows_sys::Win32::Foundation::HANDLE;
use crate::memoryutils;










/// Reads a null-terminated C string from the specified process's memory and converts it to a sanitized Rust `String`.
///
/// # Safety
///
/// This function is unsafe due to raw pointer dereferencing and handling of external process memory.
///
/// # Arguments
///
/// * `process_handle` - A handle to the process from which the C string is read.
/// * `address` - The address in the process's memory where the C string is located.
///
/// # Returns
///
/// A `Result` containing the sanitized Rust `String` or an error string if any error occurs.
///
/// The returned string will have non-UTF-8 sequences replaced with the Unicode replacement character (�)
/// and control characters or non-printable characters replaced with '?'.
pub fn read_c_string(process_handle: HANDLE, address: *const u8) -> Result<String, String>
{

    let mut bytes = Vec::new();
    let mut offset = 0;

    loop {

        let byte: u8 = match memoryutils::read_memory(process_handle, unsafe { address.add(offset) }) {
            Ok(b) => b,
            Err(e) => return Err(e),
        };

        if byte == 0
        {
            break;
        }

        bytes.push(byte);
        offset += 1;
    }

    bytes.push(0);

    let c_string = unsafe { CString::from_vec_unchecked(bytes) };
    let lossy_string = c_string.to_string_lossy().into_owned();

    let sanitized_string: String = lossy_string.chars().map(|c| {
        if c.is_control() || !c.is_ascii_graphic() {
            '?'
        } else {
            c
        }
    }).collect();

    Ok(sanitized_string)
}