//! src/processthreatprocessor.rs

// This module contains logic in snapshotting processes, and another layer of scoring a bad process.





use std::ffi::OsStr;
use serde::Serialize;
use windows_sys::Win32::Foundation::HANDLE;
use crate::fileutils::{get_file_entropy, get_file_sha256};
use crate::peutils::IATResult;
use crate::processcore::ProcessData;
use crate::processutils::ProcessInfo;
use crate::{debug_log, peutils};

//  The lowest score of a process to be considered for 'suspect_override'.
const BASE_CRIT_THREAT_SCORE: f64 = 5.6;
//  Hard coded value for arguably high file entropy.
const HIGH_ENTROPY: f64 = 6.58;
//  Score of all found sus APIs, the max score is 9 meaning every API from the list was found.
const SUSPICIOUS_API_SCORE: f32 = 0.75;

#[derive(Serialize)]
pub struct ProcessThreatInfo {
    pid: u32,
    image_path: Option<String>,
    is_debugged: Option<bool>,
    is_elevated: Option<bool>,
    thread_count: Option<usize>,
    window_title: Option<String>,
    visible_windows: Option<u32>,
    invisible_windows: Option<u32>,
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
        }
        else
        {
            debug_log!("Failed to get main module address");
        }

        results
    }


    pub fn new(pid: u32, process_handle: HANDLE) -> Self
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
            let has_hidden_windows = process_data.window_stats.as_ref().map_or(false, |stats| stats.invisible_count > 0 && stats.visible_count == 0);

            (high_threat && high_entropy) || (is_32_bit && (high_entropy || is_elevated)) || (has_hidden_windows && high_threat)
        };

        let write_count = match process_info.get_process_write_amount() {
            Ok(amount) => amount,
            Err(_) => -0.0
        };

        let privileges = match process_info.get_process_privileges() {
            Ok(privs) => privs,
            Err(_) => Vec::new(),
        };

        let (visible_windows, invisible_windows) = process_data.window_stats.map_or(
            (None, None),
            |stats| (Some(stats.visible_count), Some(stats.invisible_count))
        );

        Self {
            pid,
            image_path,
            is_debugged,
            is_elevated,
            thread_count,
            window_title: process_data.window_title,
            visible_windows,
            invisible_windows,
            threat_score: threat_score.into(),
            file_entropy,
            file_sha256,
            is_32_bit,
            suspect_override,
            write_count,
            suspicious_imports,
            privileges
        }
    }

    pub fn display(&self)
    {
        match serde_json::to_string_pretty(self) {
            Ok(json_output) => println!("{}", json_output),
            Err(e) => println!("Error serializing to JSON: {}", e),
        }
    }
}