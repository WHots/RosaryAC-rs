use std::ffi::{c_void, OsString};
use peutils::{display_section_info, IATResult};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, MAX_PATH, NO_ERROR};
use windows_sys::Win32::Security::SE_DEBUG_NAME;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
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

use crate::processutils::ProcessInfo;
use crate::fileutils::get_file_internal_name;
use crate::fileutils::get_file_entropy;

use crate::peutils::{iterate_iat};
use crate::processfilters::ProcessEnumerator;
//use crate::processfilters::process_enum;


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

    let violent_threads = process_info.query_thread_information();
    println!("Violent Threads: {:?}", violent_threads);
}