use std::ffi::OsStr;
use std::{env, io};
use std::io::Write;
use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use crate::fileutils::{get_file_entropy, get_file_sha256};
use crate::peutils::IATResult;
use crate::processcore::ProcessData;
use crate::processfilters::ProcessEnumerator;

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


use crate::processutils::ProcessInfo;


//  Flags for opening every process.
const PROCESS_FLAGS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
//  The lowest score of a process to be considered for 'suspect_override'.
const BASE_CRIT_THREAT_SCORE: f64 = 5.6;
//  Hard coded value for arguably high file entropy.
const HIGH_ENTROPY: f64 = 6.58;
//  Score of all found sus APIs, the max score is 9 meaning every API from the list was found.
const SUSPICIOUS_API_SCORE: f32 = 0.75;


#[derive(Serialize)]
struct ProcessThreatInfo
{
    pid: u32,
    image_path: Option<String>,
    is_debugged: Option<bool>,
    is_elevated: Option<bool>,
    thread_count: Option<usize>,
    file_entropy: Option<f64>,
    file_sha256: Option<String>,
    is_32_bit: Option<bool>,
    write_count: f64,
    suspicious_imports: Vec<String>,
    privileges: Vec<String>,
    threat_score: f64,
    suspect_override: bool
}

impl ProcessThreatInfo
{
    pub fn process_bad_imports(pid: u32, process_handle: HANDLE) -> Vec<(String, bool)>
    {

        let suspicious_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            //"NtMapViewOfSection",
            "LoadLibraryA",
            "LoadLibraryW",
            //"GetProcAddress",
            "SetWindowsHookEx",
            "ReadProcessMemory",
            "CreateProcess",
            "VirtualProtect",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            //"QueueUserAPC",
            "SetThreadContext",
            //"ResumeThread"
        ];

        let process_info = ProcessInfo::new(pid, process_handle);
        let mut results = Vec::new();

        if let Ok((base_address, _)) = process_info.get_main_module_ex()
        {
            for api in suspicious_apis.iter()
            {
                match peutils::search_iat(process_handle, base_address, api)
                {
                    Ok(IATResult::Found) => {
                        results.push((api.to_string(), true));
                    }
                    Ok(IATResult::NotFound) => {
                        results.push((api.to_string(), false));
                    }
                    Ok(IATResult::FailedExecution) => {
                        debug_log!(format!("Failed to check for API: {}", api));
                    }
                    Err(e) => {
                        debug_log!(format!("Error checking API {}: {}", api, e));
                    }
                }
            }
        } else {
            debug_log!("Failed to get main module address");
        }

        results
    }


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
        let (mut threat_score, malicious_threads) = process_data.base_score_process();

        let suspicious_imports = Self::process_bad_imports(pid, process_handle)
            .into_iter()
            .filter(|(_, found)| *found)
            .map(|(api, _)| api)
            .collect::<Vec<String>>();

        threat_score = threat_score + (suspicious_imports.len() as f32 * SUSPICIOUS_API_SCORE);

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

        let suspect_override = {

            let high_threat = threat_score > BASE_CRIT_THREAT_SCORE as f32;
            let high_entropy = file_entropy.map_or(false, |entropy| entropy > HIGH_ENTROPY);
            let is_elevated = is_elevated.unwrap_or(false);
            let is_32_bit = is_32_bit.unwrap_or(false);

            (high_threat && high_entropy) || (is_32_bit && (high_entropy || is_elevated))
        };

        let write_count = match process_info.get_process_write_amount() {
            Ok(amount) => amount,
            Err(_) => 0.0
        };

        let privileges = match process_info.get_process_privileges() {
            Ok(privs) => privs,
            Err(_) => Vec::new(),
        };

        Self {
            pid,
            image_path,
            is_debugged,
            is_elevated,
            thread_count,
            threat_score: threat_score.into(),
            file_entropy,
            file_sha256,
            is_32_bit,
            suspect_override: suspect_override,
            write_count,
            suspicious_imports,
            privileges
        }
    }

    fn display(&self)
    {
        match serde_json::to_string_pretty(self)
        {
            Ok(json_output) => println!("{}", json_output),
            Err(e) => println!("Error serializing to JSON: {}", e),
        }
    }
}


fn main()
{

    let enumerator = ProcessEnumerator::new();

    match enumerator.enumerate_processes()
    {
        Ok(pids) => {

            if pids.is_empty() {
                return;
            }

            println!("Found {} matching processes", pids.len());

            for pid in pids
            {

                let process_handle = match unsafe { OpenProcess(PROCESS_FLAGS, 0, pid) } {
                    0 => {
                        continue;
                    },
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


fn pause_console()
{
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}