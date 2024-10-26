use std::ffi::OsStr;
use std::{env, io};
use std::io::Write;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use crate::fileutils::{get_file_entropy, get_file_sha256};
use crate::processcore::ProcessData;

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

use crate::processutils::ProcessInfo;



const PROCESS_FLAGS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
const BASE_CRIT_THREAT_SCORE: f64 = 2.0;
const HIGH_ENTROPY: f64 = 6.7;



struct ProcessThreatInfo
{
    pid: u32,
    image_path: Option<String>,
    is_debugged: Option<bool>,
    is_elevated: Option<bool>,
    thread_count: Option<usize>,
    threat_score: f64,
    file_entropy: Option<f64>,
    file_sha256: Option<String>,
    is_32_bit: Option<bool>,
    is_suspect: bool,
    write_count: Result<f64,i32>
}


impl ProcessThreatInfo
{
    fn new(pid: u32, process_handle: HANDLE) -> Self
    {
        let process_info = ProcessInfo::new(pid, process_handle);
        let mut process_data = ProcessData::new(pid);

        process_data.fill_process_data(&process_info);

        let image_path = match &process_data.image_path {
            Ok(path) => Some(path.clone()),
            Err(_) => None,
        };

        let is_debugged = match &process_data.is_debugged {
            Ok(status) => Some(*status),
            Err(_) => None,
        };

        let is_elevated = match &process_data.is_elevated {
            Ok(status) => Some(*status),
            Err(_) => None,
        };

        let thread_count = process_data.thread_count.values().next().cloned();
        let (threat_score, malicious_threads) = process_data.base_score_process();
        let threat_score = threat_score.into();

        let (file_entropy, file_sha256) = match &image_path {
            Some(path) => {
                let image_path_osstr = OsStr::new(path);
                let entropy = get_file_entropy(image_path_osstr).ok();
                let sha256 = get_file_sha256(image_path_osstr).ok();
                (entropy, sha256)
            }
            None => (None, None),
        };

        let is_32_bit = match &process_data.is_32_bit {
            Ok(status) => Some(*status),
            Err(_) => None,
        };

        let is_suspect = {
            let high_threat = threat_score > BASE_CRIT_THREAT_SCORE;
            let high_entropy = file_entropy.map_or(false, |entropy| entropy > HIGH_ENTROPY);
            high_threat && high_entropy
        };

        let write_count = match process_info.get_process_write_amount() {
            Ok(amount) => Ok(amount),
            Err(e) => Err(e)
        };

        Self {
            pid,
            image_path,
            is_debugged,
            is_elevated,
            thread_count,
            threat_score,
            file_entropy,
            file_sha256,
            is_32_bit,
            is_suspect,
            write_count
        }
    }


    fn display(&self)
    {

        println!("Process ID: {}", self.pid);

        match &self.image_path {
            Some(path) => println!("Image Path: {}", path),
            None => println!("Image Path: Not available"),
        }

        match self.is_debugged {
            Some(is_debugged) => println!("Is Debugged: {}", is_debugged),
            None => println!("Is Debugged: Not available"),
        }

        match self.is_elevated {
            Some(is_elevated) => println!("Is Elevated: {}", is_elevated),
            None => println!("Is Elevated: Not available"),
        }

        match self.thread_count {
            Some(count) => println!("Thread Count: {}", count),
            None => println!("Thread Count: Not available"),
        }

        match self.is_32_bit {
            Some(is_32_bit) => println!("Is 32-bit Process: {}", is_32_bit),
            None => println!("Is 32-bit Process: Not available"),
        }

        match self.file_entropy {
            Some(entropy) => println!("File Entropy: {:.6}", entropy),
            None => println!("File Entropy: Not available"),
        }

        match &self.file_sha256 {
            Some(hash) => println!("SHA256: {}", hash),
            None => println!("SHA256: Not available"),
        }

        match self.write_count {
            Ok(write_count) => println!("Write Amount: {}", write_count),
            Err(_) => println!("Write Amount: Not available"), // Use _ or specify an error variable like Err(error)
        }

        println!("Threat Score: {:.2}", self.threat_score);
        println!("Suspect Override: {}", self.is_suspect)
    }
}

fn main()
{

    let args: Vec<String> = env::args().collect();

    let pid: u32 = if args.len() > 1 {
        match args[1].parse() {
            Ok(pid) => pid,
            Err(_) => {
                eprintln!("\nInvalid process ID provided. Using the current process ID instead.\n");
                unsafe { GetCurrentProcessId() }
            }
        }
    }
    else
    {
        unsafe { GetCurrentProcessId() }
    };

    let process_handle: HANDLE = match unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) } {
        0 => {
            let error_code = unsafe { GetLastError() };
            debug_log!(format!("Process handle was empty: {}", error_code));
            return;
        },
        handle => handle,
    };

    let process_threat_info = ProcessThreatInfo::new(pid, process_handle);

    process_threat_info.display();

    let process_info = ProcessInfo::new(pid, process_handle);

    match process_info.get_process_privileges()
    {
        Ok(privileges) => {
            println!("Process Privileges:");
            for privilege in privileges {
                println!("  - {}", privilege);
            }
        }
        Err(e) => println!("Error retrieving privileges: {}", e),
    }

    unsafe { CloseHandle(process_handle) };

    pause_console();
}

fn pause_console() {
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}
