//! src/fileutils.rs

// This module contains utility functions based around file operations.





use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use digest::Digest;
use sha2::Sha256;


#[derive(Debug)]
pub enum FileVersionError
{
    GetSizeFailed(u32),
    GetInfoFailed(u32),
    QueryTranslationFailed(u32),
    NoTranslationAvailable,
    QueryInternalNameFailed(u32),
}



pub fn get_file_internal_name(file_path: &OsStr) -> Result<OsString, FileVersionError>
{

    let wide_file_path: Vec<u16> = file_path.encode_wide().chain(Some(0)).collect();

    let size = unsafe { GetFileVersionInfoSizeW(wide_file_path.as_ptr(), null_mut()) };

    if size == 0
    {
        return Err(FileVersionError::GetSizeFailed(unsafe { GetLastError() }));
    }

    let mut data = vec![0u8; size as usize];

    if unsafe { GetFileVersionInfoW(wide_file_path.as_ptr(), 0, size, data.as_mut_ptr() as *mut _) } == 0
    {
        return Err(FileVersionError::GetInfoFailed(unsafe { GetLastError() }));
    }

    let mut translation_buffer: *mut u8 = null_mut();
    let mut translation_length: u32 = 0;
    let translation_key: Vec<u16> = OsStr::new("\\VarFileInfo\\Translation").encode_wide().chain(Some(0)).collect();

    if unsafe { VerQueryValueW(data.as_ptr() as *const _, translation_key.as_ptr(), &mut translation_buffer as *mut _ as *mut *mut _, &mut translation_length) } == 0
    {
        return Err(FileVersionError::QueryTranslationFailed(unsafe { GetLastError() }));
    }

    let translation_table = unsafe { std::slice::from_raw_parts(translation_buffer as *const u32, translation_length as usize / 4) };
    let language_and_codepage = *translation_table.get(0).ok_or(FileVersionError::NoTranslationAvailable)?;

    let internal_name_key = format!("\\StringFileInfo\\{:04x}{:04x}\\InternalName", language_and_codepage & 0xFFFF, language_and_codepage >> 16);
    let internal_name_key_wide: Vec<u16> = OsStr::new(&internal_name_key).encode_wide().chain(Some(0)).collect();

    let mut buffer: *mut u8 = null_mut();
    let mut length: u32 = 0;

    if unsafe { VerQueryValueW(data.as_ptr() as *const _, internal_name_key_wide.as_ptr(), &mut buffer as *mut _ as *mut *mut _, &mut length) } == 0
    {
        return Err(FileVersionError::QueryInternalNameFailed(unsafe { GetLastError() }));
    }

    let internal_name_wide = unsafe { std::slice::from_raw_parts(buffer as *const u16, length as usize / 2) };

    Ok(OsString::from_wide(internal_name_wide))
}


/// Calculates the MD5 signature of a file.
///
/// # Arguments
///
/// * `file_path` - A reference to an `OsStr` that represents the path to the file.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be opened or read.
///
/// # Returns
///
/// A `Result` containing either the calculated MD5 signature as a hexadecimal string or an `io::Error`.
pub fn get_file_sha256(file_path: &OsStr) -> io::Result<String>
{

    let path = Path::new(file_path);
    let mut file = File::open(path)?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}


/// Calculates the Shannon entropy of a file, which is a measure of the randomness
/// or information density in the file's contents.
///
/// # Arguments
///
/// * `file_path` - A reference to an `OsStr` that represents the path to the file.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be opened or read.
///
/// # Returns
///
/// A `Result` containing either the calculated entropy as `f64` or an `io::Error`.
pub fn get_file_entropy(file_path: &OsStr) -> io::Result<f64>
{

    let path = Path::new(file_path);
    let mut file = File::open(path)?;

    let mut frequency: HashMap<u8, i64> = HashMap::new();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)?;

    if buffer.is_empty()
    {
        return Ok(0.0);
    }

    for &byte in &buffer
    {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let total_bytes = buffer.len() as f64;
    let entropy = frequency.values().fold(0.0, |acc, &freq| {
        if freq > 0
        {
            let probability = freq as f64 / total_bytes;
            acc - (probability * probability.log2())
        }
        else
        {
            acc
        }
    });

    Ok(entropy)
}