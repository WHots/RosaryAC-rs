use std::ffi::{c_void, OsString};
use peutils::{display_section_info, IATResult};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, MAX_PATH, NO_ERROR};
use windows_sys::Win32::Security::SE_DEBUG_NAME;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows_sys::Win32::System::Services::{OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, SERVICE_STATUS};
use crate::processcore::ProcessData;

mod processutils;
mod memoryutils;
mod fileutils;
mod peutils;
mod ntpsapi_h;
mod memorymanage;
mod winnt_h;
mod stringutils;
mod playerone;
mod processfilters;
mod ntexapi_h;
mod ntobapi_h;
mod processcore;
mod debugutils;

use crate::processutils::ProcessInfo;

use crate::processfilters::ProcessEnumerator;


const PROCESS_FLAGS: u32 = PROCESS_ALL_ACCESS;





//  Testing stuff in here, so it will probably be very random.


fn main()
{

    let pid: u32 = unsafe {GetCurrentProcessId()};
    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };

    let process_info = ProcessInfo::new(pid, process_handle);

    let mut process_data = ProcessData::new(pid);

    process_data.fill_process_data(&process_info);

    println!("Process ID: {}", process_data.pid);

    match &process_data.image_path {
        Ok(path) => println!("Image Path: {}", path),
        Err(e) => println!("Error getting image path: {}", e),
    }

    match process_data.is_debugged {
        Ok(is_debugged) => println!("Is Debugged: {}", is_debugged),
        Err(e) => println!("Error checking if debugged: {}", e),
    }

    match process_data.is_elevated {
        Ok(is_elevated) => println!("Is Elevated: {}", is_elevated),
        Err(e) => println!("Error checking if elevated: {}", e),
    }

    println!("Thread Count: {:?}", process_data.thread_count);

    match process_data.handle_count {
        Ok(count) => println!("Handle Count: {}", count),
        Err(e) => println!("Error getting handle count: {}", e),
    }

    println!("Token Privileges: {}", process_data.token_privileges);

    unsafe { CloseHandle(process_handle) };
}