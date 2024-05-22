use std::ffi::OsString;
use windows_sys::Win32::Foundation::{HANDLE, MAX_PATH};
use windows_sys::Win32::Security::SE_DEBUG_NAME;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

mod processutils;
mod memoryutils;
mod fileutils;
mod peutils;
mod ntpsapi_h;
mod memorymanage;
mod winnt_h;

use crate::processutils::ProcessInfo;
use crate::fileutils::get_file_internal_name;
use crate::fileutils::get_file_entropy;

use crate::peutils::display_section_info;


const PROCESS_FLAGS: u32 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;



//  Testing stuff in here, so it will probably be very random.

fn main() {
    let pid: u32 = 1996;//unsafe { GetCurrentProcessId() };
    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };

    let process_info = ProcessInfo::new(pid, process_handle);

    let mut buffer = Vec::new();
    let mut output = OsString::new();

    let violent_threads = process_info.query_thread_information();
    println!("Violent Threads: {:?}", violent_threads);

    match unsafe { process_info.get_process_image_path_ex(&mut buffer, &mut output) } {
        Ok(path) => unsafe {
            println!("{:?}", path);



            match get_file_internal_name(path) {
                Ok(internal_name) => println!("Internal Name: {:?}", internal_name),
                Err(e) => eprintln!("Error: {}", e),
            }
            match get_file_entropy(path) {
                Ok(entropy) => println!("The entropy of the file is: {}", entropy),
                Err(e) => println!("{}", e),
            }
            match process_info.get_main_module_ex() {
                Ok((base_address, size_of_image)) => {
                    println!("Base Address: {:?}", base_address);
                    println!("Size of Image: {}", size_of_image);


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

            match process_info.is_secure_process()
            {
                Ok(is_secure) => println!("Is Secure Process: {}", is_secure),
                Err(e) => eprintln!("Error: {}", e),
            }
        },

        Err(e) => println!("Error: {}", e),
    }
}