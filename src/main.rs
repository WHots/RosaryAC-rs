use windows_sys::Win32::Foundation::{HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

mod processutils;
mod memoryutils;
mod fileutils;

use crate::processutils::ProcessInfo;
use crate::memoryutils::print_memory;


const PROCESS_FLAGS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;



//  Testing stuff in here, so it will probably be very random.

fn main()
{

    let pid: u32 = unsafe { GetCurrentProcessId() };

    let process_handle: HANDLE = unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) };
    
    let process_info = ProcessInfo::new(pid, process_handle);


}