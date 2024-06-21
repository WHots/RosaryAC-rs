use std::ffi::{c_void, OsString};
use peutils::{display_section_info, IATResult};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, MAX_PATH, NO_ERROR};
use windows_sys::Win32::Security::SE_DEBUG_NAME;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows_sys::Win32::System::Services::{OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, SERVICE_STATUS};
mod processprofiler;
mod memoryutils;
mod fileutils;
mod peutils;
mod ntpsapi_h;
mod memorymanage;
mod winnt_h;
mod stringutils;
mod playerone;
mod processfilters;

use crate::processprofiler::ProcessInfo;
use crate::fileutils::get_file_internal_name;
use crate::fileutils::get_file_entropy;

use crate::peutils::{iterate_iat};
use crate::processfilters::process_enum;


const PROCESS_FLAGS: u32 = PROCESS_ALL_ACCESS;




//  Testing stuff in here, so it will probably be very random.












fn main()
{

    let mut enumerator = process_enum::ProcessEnumerator::new();
    enumerator.enumerate_processes();
    let process_ids = enumerator.get_matching_pids();
    for pid in process_ids {
        println!("Process ID: {}", pid);
    }

    let pid: u32 = unsafe { GetCurrentProcessId() };
    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };

    let process_info = ProcessInfo::new(pid, process_handle);

    let violent_threads = process_info.query_thread_information();
    println!("Violent Threads: {:?}", violent_threads);

    match process_info.get_process_image_path_ex() 
    {

        Ok(path) => {
            println!("{:?}", path);

            match get_file_internal_name(&path) {
                Ok(internal_name) => println!("Internal Name: {:?}", internal_name),
                Err(e) => eprintln!("Error: {:?}", e),
            }
            match get_file_entropy(&path) {
                Ok(entropy) => println!("The entropy of the file is: {}", entropy),
                Err(e) => println!("{}", e),
            }
            match process_info.get_main_module_ex() {
                Ok((base_address, size_of_image)) => {
                    println!("Base Address: {:?}", base_address);
                    println!("Size of Image: {}", size_of_image);

                    let search_name = "OpenProcess";

                    match iterate_iat(process_handle, base_address, search_name) {
                        Ok(IATResult::Found) => {
                            println!("Function '{}' found in IAT.", search_name);
                        },
                        Ok(IATResult::NotFound) => {
                            println!("Function '{}' not found in IAT.", search_name);
                        },
                        Ok(IATResult::FailedExecution) => {
                            println!("Failed to execute IAT iteration: ");
                        },
                        Err(e) => {
                            println!("Error iterating IAT: {}", e);
                        },
                    }

                    match unsafe { display_section_info(".text", process_handle, base_address as *const c_void) } {
                        Ok(Some(section_info)) => println!("Section Info: {:?}", section_info),
                        Ok(None) => println!("Section not found"),
                        Err(e) => println!("Error: {}", e),
                    }
                }
                Err(err) => {
                    eprintln!("Error: {}", err);
                }
            }

            match process_info.get_peb_base_address() {
                Ok(peb_address) => println!("PEB Base Address: {:?}", peb_address),
                Err(e) => eprintln!("Error: {}", e),
            }

            match process_info.is_wow64() {
                Ok(is_wow64) => println!("WoW64 Emulation: {}", is_wow64),
                Err(e) => eprintln!("Error: {}", e),
            }

            match process_info.is_protected_process() {
                Ok(is_protected) => println!("Is Protected Process: {}", is_protected),
                Err(e) => eprintln!("Error: {}", e),
            }

            match process_info.is_secure_process() {
                Ok(is_secure) => println!("Is Secure Process: {}", is_secure),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
