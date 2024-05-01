use std::ffi::OsString;
use windows_sys::Win32::Foundation::{HANDLE, MAX_PATH};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

mod processutils;
mod memoryutils;
mod fileutils;

use crate::processutils::ProcessInfo;
use crate::fileutils::get_file_internal_name;
use crate::fileutils::get_file_entropy;

const PROCESS_FLAGS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;



//  Testing stuff in here, so it will probably be very random.

fn main()
{

    let pid: u32 = unsafe { GetCurrentProcessId() };

    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };
    
    let process_info = ProcessInfo::new(pid, process_handle);

    let mut buffer = Vec::new();
    let mut output = OsString::new();

    match unsafe { process_info.get_process_image_path_ex(&mut buffer, &mut output) }
    {
        Ok(path) => {
            println!("{:?}", path);
            match get_file_internal_name(path)
            {
                Ok(internal_name) => println!("Internal Name: {:?}", internal_name),
                Err(e) => eprintln!("Error: {}", e),
            }
            match get_file_entropy(path) {
                Ok(entropy) => println!("The entropy of the file is: {}", entropy),
                Err(e) => println!("{}", e),
            }
        },
        Err(e) => println!("Error: {}", e),
    }



}