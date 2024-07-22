use std::ffi::{c_void, OsString};
use peutils::{display_section_info, IATResult};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, MAX_PATH, NO_ERROR};
use windows_sys::Win32::Security::SE_DEBUG_NAME;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows_sys::Win32::System::Services::{OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, SERVICE_STATUS};
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

use crate::processutils::ProcessInfo;

use crate::processfilters::ProcessEnumerator;


const PROCESS_FLAGS: u32 = PROCESS_ALL_ACCESS;





//  Testing stuff in here, so it will probably be very random.


fn main()
{

    let mut enumerator = ProcessEnumerator::new();
    enumerator.enumerate_processes();


    enumerator.process_matching_pids(|pid| {
        println!("Processing PID: {}", pid);
    });

    let pid: u32 = 15612; //    unsafe { GetCurrentProcessId() };
    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };

    let process_info = ProcessInfo::new(pid, process_handle);

    let pid = unsafe { GetCurrentProcess() } as u32;
    let object_type = 7;
    let handle_count = process_info.get_current_handle_count(10888, 1);
    println!("Handle count: {:?}", handle_count);

    let mut process_enumerator = ProcessEnumerator::new();

    match process_enumerator.check_process_handles()
    {
        Ok(processes) => {
            println!("Processes with handles to the current process:");
            for pid in processes {
                println!("Process ID: {}", pid);

            }
        }
        Err(e) => {
            eprintln!("Error checking process handles: {}", e);
        }
    }
}