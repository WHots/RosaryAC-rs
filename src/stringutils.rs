use std::ffi::CString;
use windows_sys::Win32::Foundation::HANDLE;
use crate::memoryutils::memory_tools::read_memory;










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

        let byte: u8 = match read_memory(process_handle, unsafe { address.add(offset) }) {
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


/// Compares two strings for similarity based on consecutive matching characters.
///
/// This function compares two strings, `s1` and `s2`, to determine if they contain a 
/// sequence of at least `threshold` consecutive matching characters. If the length 
/// of the longest sequence of matching characters is greater than or equal to 
/// the `threshold`, the function returns `true`; otherwise, it returns `false`.
///
/// # Arguments
///
/// * `s1` - The first string to compare.
/// * `s2` - The second string to compare.
///
/// # Returns
///
/// A boolean value indicating whether the two strings have a sequence of at least 
/// `threshold` consecutive matching characters.
pub fn strings_match(s1: &str, s2: &str) -> bool 
{

    let threshold = 4;
    let min_length = s1.len().min(s2.len());

    let mut max_common_length = 0;
    let mut current_common_length = 0;

    for i in 0..min_length 
    {
        if s1.as_bytes()[i] == s2.as_bytes()[i] 
        {
            current_common_length += 1;
            if current_common_length > max_common_length 
            {
                max_common_length = current_common_length;
            }
        } 
        else 
        {
            current_common_length = 0;
        }
    }

    max_common_length >= threshold
}


/// Converts a string slice to a null-terminated UTF-16 vector.
///
/// This function takes a string slice, encodes it in UTF-16, and appends a null
/// terminator to the end of the encoded string. This is typically required when
/// interfacing with Windows API functions that expect a wide string pointer.
///
/// # Arguments
///
/// * `s` - A string slice to be converted.
///
/// # Returns
///
/// A `Vec<u16>` that contains the UTF-16 encoded form of the input string, followed
/// by a null terminator (0).
pub fn to_wide_chars(s: &str) -> Vec<u16>
{
    s.encode_utf16().chain(std::iter::once(0)).collect()
}