//! src/processthreatprocessor.rs

// This module contains logic in snapshotting processes, and another layer of scoring a bad process.





use std::ffi::OsStr;
use serde::Serialize;
use windows_sys::Win32::Foundation::HANDLE;
use crate::fileutils::{get_file_entropy, get_file_sha256};
use crate::peutils::{IATResult, self};
use crate::processcore::{ProcessData, ProcessDataError, ProcessThreatData};
use crate::processutils::ProcessInfo;
use crate::debug_log;



/// Lowest threat score to be considered override in some scenarios.
pub const BASE_CRIT_THREAT_SCORE: f64 = 4.6;
/// Base value indicating what is considered high file entropy.
const HIGH_ENTROPY: f64 = 6.78;
/// 0.75 is added to the threat score per suspicious API found in scan.
const SUSPICIOUS_API_SCORE: f32 = 0.75;



#[derive(Serialize)]
pub struct ProcessThreatInfo
{
    pid: u32,
    image_path: Option<String>,
    is_debugged: Option<bool>,
    hidden_threads: u32,
    is_elevated: Option<bool>,
    window_title: Option<String>,
    visible_windows: Option<u32>,
    invisible_windows: Option<u32>,
    file_entropy: Option<f64>,
    file_sha256: Option<String>,
    is_32_bit: Option<bool>,
    write_count: f64,
    suspicious_imports: Vec<String>,
    privileges: Vec<String>,
    is_pe_zero: Option<bool>,
    pe_sections: Vec<String>,
    pub(crate) threat_score: f64,
    pub(crate) suspect_override: bool
}

impl ProcessThreatInfo
{
    pub fn new(pid: u32, process_handle: HANDLE) -> Self
    {
        let process_info = ProcessInfo::new(pid, process_handle);
        let mut process_data = ProcessData::new(pid);

        process_data.fill_process_data(&process_info);

        let suspicious_imports = Self::process_bad_imports(pid, process_handle);
        let threat_data = Self::assess_threat_level(&process_data, &process_info, &suspicious_imports);

        let pe_sections = process_info.get_main_module_ex()
            .ok()
            .and_then(|(base_address, _)| peutils::get_pe_sections(process_handle, base_address).ok())
            .unwrap_or_default();

        let privileges = process_info.get_process_privileges()
            .map(|privs| privs.into_iter()
                .filter(|(_, enabled)| *enabled)
                .map(|(name, _)| name)
                .collect())
            .unwrap_or_default();

        let (visible_windows, invisible_windows) = process_data.window_stats.as_ref().map_or((None, None), |stats| (Some(stats.visible_count), Some(stats.invisible_count)));

        Self {
            pid,
            image_path: process_data.image_path.as_ref().ok().cloned(),
            is_debugged: process_data.is_debugged.as_ref().ok().copied(),
            hidden_threads: process_data.hidden_threads,
            is_elevated: process_data.is_elevated.as_ref().ok().copied(),
            window_title: process_data.window_title,
            visible_windows,
            invisible_windows,
            threat_score: threat_data.threat_score.into(),
            file_entropy: threat_data.file_entropy,
            file_sha256: threat_data.file_sha256,
            is_32_bit: process_data.is_32_bit.as_ref().ok().copied(),
            suspect_override: threat_data.is_suspect,
            write_count: threat_data.write_count,
            suspicious_imports: threat_data.suspicious_imports,
            privileges,
            is_pe_zero: process_data.is_pe_zero,
            pe_sections,
        }
    }


    #[inline]
    fn process_bad_imports(pid: u32, process_handle: HANDLE) -> Vec<(String, bool)>
    {
        const SUSPICIOUS_APIS: [&str; 12] = [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "LoadLibraryA", "LoadLibraryW", "SetWindowsHookEx",
            "ReadProcessMemory", "CreateProcess", "VirtualProtect",
            "NtCreateThreadEx", "RtlCreateUserThread", "SetThreadContext",
        ];

        let process_info = ProcessInfo::new(pid, process_handle);
        let mut results = Vec::with_capacity(SUSPICIOUS_APIS.len());

        if let Ok((base_address, _)) = process_info.get_main_module_ex()
        {
            for api in &SUSPICIOUS_APIS
            {
                match peutils::search_iat(process_handle, base_address, api) {

                    Ok(IATResult::Found) => results.push((api.to_string(), true)),
                    Ok(IATResult::NotFound) => results.push((api.to_string(), false)),
                    Ok(IATResult::FailedExecution) => {
                        let e = ProcessDataError::ImagePathError;
                        debug_log!(e);
                    },
                    Err(e) => {
                        let e = ProcessDataError::ImagePathError;
                        debug_log!(e);
                    }
                }
            }
        }

        results
    }


    #[inline]
    fn assess_threat_level(process_data: &ProcessData, process_info: &ProcessInfo, imports: &[(String, bool)]) -> ProcessThreatData
    {

        let mut threat_score = 0.0;

        if process_data.is_debugged.as_ref().map_or(false, |&x| x) { threat_score += 2.0; }
        if process_data.hidden_threads > 0 { threat_score += process_data.hidden_threads as f32 * 5.0; }
        if process_data.is_elevated.as_ref().map_or(false, |&x| x) { threat_score += 6.5; }
        if process_data.is_wow64.as_ref().map_or(false, |&x| x) { threat_score += 0.5; }
        if process_data.is_protected.as_ref().map_or(false, |&x| x) { threat_score -= 1.0; }


        /// TODO:
        /// -  Thread based scoring needs reworked -
        /// * Only score if the tread has the hide from debugger.
        /// * If an anomaly thread (a thread that isn't owend by the process), capture that process as a complete threat.

        if let Some(&count) = process_data.thread_count.get("Hidden Flag")
        {
            threat_score += count as f32 * 2.5;
        }
        if let Some(&count) = process_data.thread_count.get("NOT Owned")
        {
            threat_score += count as f32;
        }

        /// --------------

        if process_data.is_32_bit.as_ref().map_or(false, |&x| x)
        {
            threat_score += 3.25;
        }

        if let Some(stats) = &process_data.window_stats
        {
            if stats.invisible_count > 1 { threat_score += 3.0; }
            if stats.invisible_count > stats.visible_count { threat_score += 2.5; }
        }

        if process_data.window_title.is_none() && process_data.window_stats.as_ref().map_or(false, |s| s.visible_count + s.invisible_count > 0)
        {
            threat_score += 2.0;
        }

        if let Some(enabled_count) = process_data.privileged_token_count
        {
            threat_score += enabled_count as f32 * 1.25;
        }

        if let Some(zeroed) = process_data.is_pe_zero
        {
            threat_score += if zeroed { 4.5 } else { -2.0 };
        }

        let suspicious_imports: Vec<String> = imports.iter().filter(|(_, found)| *found).map(|(api, _)| api.clone()).collect();

        threat_score += suspicious_imports.len() as f32 * SUSPICIOUS_API_SCORE;
        threat_score = threat_score.min(14.0).max(1.0);

        let (file_entropy, file_sha256) = process_data.image_path.as_ref().map_or((None, None), |path| {
            let path_osstr = OsStr::new(path);
            (get_file_entropy(path_osstr).ok(), get_file_sha256(path_osstr).ok())
        });

        let write_count = process_data.image_path.as_ref().map_or(-0.0, |_| {
            process_info.get_process_write_amount().unwrap_or(-0.0)
        });

        let is_suspect = {
            let high_threat = threat_score > BASE_CRIT_THREAT_SCORE as f32;
            let high_entropy = file_entropy.map_or(false, |entropy| entropy > HIGH_ENTROPY);
            let is_elevated = process_data.is_elevated.as_ref().map_or(false, |&x| x);
            let is_32_bit = process_data.is_32_bit.as_ref().map_or(false, |&x| x);
            let has_hidden_windows = process_data.window_stats.as_ref()
                .map_or(false, |stats| stats.invisible_count > 0 && stats.visible_count == 0);
            let has_zeroed_pe = process_data.is_pe_zero.unwrap_or(false);
            let high_write_count = write_count > 5.0;
            let many_suspicious_imports = suspicious_imports.len() >= 3;

            (high_threat && high_entropy) ||
                (is_32_bit && (high_entropy || is_elevated)) ||
                (has_hidden_windows && high_threat) ||
                (has_zeroed_pe && (high_threat || high_entropy)) ||
                (high_write_count && (many_suspicious_imports || high_entropy)) ||
                (many_suspicious_imports && high_entropy && is_elevated)
        };

        ProcessThreatData
        {
            threat_score,
            suspicious_imports,
            is_suspect,
            file_entropy,
            file_sha256,
            write_count
        }
    }


    pub fn display(&self)
    {
        if let Ok(json_output) = serde_json::to_string_pretty(self)
        {
            println!("{}", json_output);
        }
    }
}