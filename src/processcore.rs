//! src/processcore.rs

// This module contains logic in scoring the threat of an active running process.





use std::collections::HashMap;
use std::{fmt::{Display, Formatter}, fmt};
use serde::{Serialize, Deserialize};
use crate::processutils::{ProcessInfo};
use crate::windowutils::{WindowStats, };




/// Enum representing various errors that can occur when gathering process data.
#[derive(Serialize, Deserialize, Debug)]
pub enum ProcessDataError
{
    ImagePathError(String),
    DebuggerError(String),
    IsElevatedError(String),
    PebBaseAddressError(String),
    Wow64Error(String),
    ProtectionError(String),
    SecurityError(String),
    ElevationError(String),
    HandleCountError(String),
    Uninitialized(&'static str)
}


impl Display for ProcessDataError
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
    {
        match self {

            ProcessDataError::ImagePathError(msg) => write!(f, "Failed fetching image path: {}", msg),
            ProcessDataError::DebuggerError(msg) => write!(f, "Debugger check failed: {}", msg),
            ProcessDataError::IsElevatedError(msg) => write!(f, "Elevation check failed: {}", msg),
            ProcessDataError::PebBaseAddressError(msg) => write!(f, "PEB base address error: {}", msg),
            ProcessDataError::Wow64Error(msg) => write!(f, "WOW64 check failed: {}", msg),
            ProcessDataError::ProtectionError(msg) => write!(f, "Protection check failed: {}", msg),
            ProcessDataError::SecurityError(msg) => write!(f, "Security check failed: {}", msg),
            ProcessDataError::ElevationError(msg) => write!(f, "Handle count error: {}", msg),
            ProcessDataError::HandleCountError(msg) => write!(f, "Not initialized: {}", msg),
            ProcessDataError::Uninitialized(msg) => write!(f, "Not initialized: {}", msg)
        }
    }
}



#[derive(Debug)]
pub struct ProcessData
{
    pub(crate) pid: u32,
    pub(crate) image_path: Result<String, ProcessDataError>,
    pub(crate) is_debugged: Result<bool, ProcessDataError>,
    pub(crate) hidden_threads: u32,
    pub (crate) is_elevated: Result<bool, ProcessDataError>,
    peb_base_address: Result<u64, ProcessDataError>,
    is_wow64: Result<bool, ProcessDataError>,
    is_protected: Result<bool, ProcessDataError>,
    is_secure: Result<bool, ProcessDataError>,
    pub(crate) thread_count: HashMap<String, usize>,
    pub(crate) is_32_bit: Result<bool, ProcessDataError>,
    pub(crate) window_title: Option<String>,
    pub(crate) window_stats: Option<WindowStats>,
    pub(crate) privileged_token_count: Option<u32>,
    pub(crate) is_pe_zero: Option<bool>
}



impl ProcessData
{
    pub fn new(pid: u32) -> Self
    {
        Self {
            pid,
            image_path: Err(ProcessDataError::Uninitialized("Process image path")),
            is_debugged: Err(ProcessDataError::Uninitialized("Debug status")),
            hidden_threads: 0,
            peb_base_address: Err(ProcessDataError::Uninitialized("PEB address")),
            is_wow64: Err(ProcessDataError::Uninitialized("WOW64 status")),
            is_protected: Err(ProcessDataError::Uninitialized("Protection status")),
            is_secure: Err(ProcessDataError::Uninitialized("Security status")),
            is_elevated: Err(ProcessDataError::Uninitialized("Elevation status")),
            is_32_bit: Err(ProcessDataError::Uninitialized("Architecture Error")),
            thread_count: HashMap::new(),
            window_title: None,
            window_stats: None,
            privileged_token_count: None,
            is_pe_zero: None
        }
    }


    /// Fills the `ProcessData` instance with data gathered from `ProcessInfo`.
    ///
    /// This method populates various fields of the `ProcessData` struct by querying
    /// the provided `ProcessInfo` object. It gathers information such as image path,
    /// debugging status, elevation status, PEB base address, WoW64 status, protection status,
    /// security status, thread information, token privileges, and checks for injected threads.
    ///
    /// # Parameters
    ///
    /// - `process_info`: A reference to a `ProcessInfo` object containing the raw process data.
    ///
    /// # Errors
    ///
    /// While this method doesn't return a Result, it populates various fields with
    /// `Result<T, ProcessDataError>` types. Errors during data gathering are converted
    /// to appropriate `ProcessDataError` variants.
    ///
    /// # Side Effects
    ///
    /// - Updates all fields of the `ProcessData` instance.
    /// - Prints an error message to stdout if scanning for injected threads fails.
    ///
    /// # Safety
    ///
    /// This method relies on `ProcessInfo` methods which may use unsafe Windows API calls.
    pub fn fill_process_data(&mut self, process_info: &ProcessInfo)
    {
        self.image_path = process_info.get_process_image_path_ex()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|e| ProcessDataError::ImagePathError(e.to_string()));

        self.is_debugged = process_info.is_debugger()
            .map_err(|e| ProcessDataError::DebuggerError(e.to_string()));

        self.hidden_threads = process_info.get_hidden_thread_count();

        self.is_elevated = process_info.is_process_elevated()
            .map_err(|e| ProcessDataError::IsElevatedError(e.to_string()));

        self.peb_base_address = process_info.get_peb_base_address()
            .map(|addr| addr as u64)
            .map_err(|e| ProcessDataError::PebBaseAddressError(e.to_string()));

        self.is_wow64 = process_info.is_wow64()
            .map_err(|e| ProcessDataError::Wow64Error(e.to_string()));

        self.is_protected = process_info.is_protected_process()
            .map_err(|e| ProcessDataError::ProtectionError(e.to_string()));

        self.is_secure = process_info.is_secure_process()
            .map_err(|e| ProcessDataError::SecurityError(e.to_string()));


        self.is_32_bit = process_info.is_32_bit_process()
            .map_err(|e| ProcessDataError::Wow64Error(e.to_string()));

        self.window_title = match process_info.get_window_title() {
            Ok(title) => title,
            Err(e) => {
                None
            }
        };

        self.window_stats = match process_info.get_window_stats() {
            Ok(stats) => Some(stats),
            Err(e) => {
                None
            }
        };

        self.privileged_token_count = match process_info.get_process_privileges() {
            Ok(privs) => Some(privs.iter().filter(|(_, enabled)| *enabled).count() as u32),
            Err(_) => None,
        };

        self.is_pe_zero = match &self.image_path {
            Ok(_) => {
                if let Ok((base_address, _)) = process_info.get_main_module_ex() {
                    match crate::peutils::is_pe_zeroed(process_info.process_handle, base_address) {
                        Ok(zeroed) => Some(zeroed),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            },
            Err(_) => None,
        };
    }


    /// Calculates a base threat score for the process based on its characteristics.
    ///
    /// This method analyzes various attributes of the process, such as debugging status,
    /// elevation, WoW64 status, protection status, presence of malicious threads,
    /// token privileges, and thread characteristics, window stats, & PE stats to compute a threat score.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `f32`: The calculated threat score, ranging from 0.0 to 14.0.
    /// - `Vec<u32>`: A list of process IDs of detected malicious threads.
    pub fn base_score_process(&self) -> (f32, Vec<u32>)
    {
        let mut threat_score: f32 = 0.0;
        let mut malicious_thread_pids = Vec::new();

        if let Ok(is_debugged) = self.is_debugged {
            if is_debugged {
                threat_score += 2.0;
            }
        }

        if self.hidden_threads > 0 {
            threat_score += self.hidden_threads as f32 * 5.0;
        }

        if let Ok(is_elevated) = self.is_elevated {
            if is_elevated {
                threat_score += 6.5;
            }
        }

        if let Ok(is_wow64) = self.is_wow64 {
            if is_wow64 {
                threat_score += 0.5;
            }
        }

        if let Ok(is_protected) = self.is_protected {
            if is_protected {
                threat_score -= 1.0;
            }
        }

        if let Some(hidden_thread_count) = self.thread_count.get("Hidden Flag") {
            for _ in 0..*hidden_thread_count {
                threat_score += 2.5;
            }
        }

        if let Some(not_owned_count) = self.thread_count.get("NOT Owned") {
            for _ in 0..*not_owned_count {
                threat_score += 1.0;
            }
        }

        if let Ok(is_32_bit) = self.is_32_bit
        {
            if is_32_bit
            {
                threat_score += 3.25;
            }
        }

        if let Some(stats) = &self.window_stats
        {
            if stats.invisible_count > 1
            {
                threat_score += 3.0;
            }

            if stats.invisible_count > stats.visible_count {
                threat_score += 2.5;
            }
        }

        if self.window_title.is_none() &&
            self.window_stats.as_ref().map_or(false, |s| s.visible_count + s.invisible_count > 0) {
            threat_score += 2.0;
        }

        if let Some(enabled_count) = self.privileged_token_count {
            threat_score += enabled_count as f32 * 1.25;
        }

        if let Ok(is_32_bit) = self.is_32_bit
        {
            if is_32_bit
            {
                threat_score += 3.25;
            }
        }

        if let Some(zeroed) = self.is_pe_zero
        {
            if zeroed
            {
                threat_score += 4.5; // High score due to severity of zeroed PE
            }
            else {
                threat_score -= 3.0;
            }
        }

        threat_score = threat_score.min(14.0).max(1.0);

        (threat_score, malicious_thread_pids)
    }
}