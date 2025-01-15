use std::io::{self, Write};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use crate::processfilters::ProcessEnumerator;
use crate::processthreatprocessor::ProcessThreatInfo;


mod processutils;
mod memoryutils;
mod fileutils;
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
mod peutils;
mod mathutils;
mod monitor;
mod processthreatprocessor;

//  Flags for opening every process.
const PROCESS_FLAGS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

fn main() {
    let enumerator = ProcessEnumerator::new();

    match enumerator.enumerate_processes() {
        Ok(pids) => {
            if pids.is_empty() {
                return;
            }

            for pid in pids {
                let process_handle = match unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) } {
                    0 => continue,
                    handle => handle,
                };

                let process_threat_info = ProcessThreatInfo::new(pid, process_handle);
                process_threat_info.display();

                unsafe { CloseHandle(process_handle) };
            }
        },
        Err(e) => eprintln!("Failed to enumerate processes: {}", e)
    }

    pause_console();
}

fn pause_console() {
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}