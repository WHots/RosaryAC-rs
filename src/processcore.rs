//! src/processcore.rs

// This module contains logic in scoring the threat of an active running process.





use std::collections::HashMap;
use std::{fmt};
use serde::{Serialize, Deserialize};
use crate::processutils::{ ProcessInfo};




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
}


impl fmt::Display for ProcessDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessDataError::ImagePathError(msg) => write!(f, "Failed Fetching Image Path: {}", msg),
            ProcessDataError::DebuggerError(msg) => write!(f, "Debugger Check Error: {}", msg),
            ProcessDataError::IsElevatedError(msg) => write!(f, "Elevation Check Error: {}", msg),
            ProcessDataError::PebBaseAddressError(msg) => write!(f, "PEB Base Address Error: {}", msg),
            ProcessDataError::Wow64Error(msg) => write!(f, "WOW64 Check Error: {}", msg),
            ProcessDataError::ProtectionError(msg) => write!(f, "Protection Check Error: {}", msg),
            ProcessDataError::SecurityError(msg) => write!(f, "Security Check Error: {}", msg),
            ProcessDataError::ElevationError(msg) => write!(f, "Elevation check error: {}", msg),
            ProcessDataError::HandleCountError(msg) => write!(f, "Handle Count Error: {}", msg),
        }
    }
}

impl std::error::Error for ProcessDataError {}


/// `ProcessData` struct holds information about a process.
#[derive(Serialize, Deserialize, Debug)]
pub struct ProcessData
{
    pub(crate) pid: u32,
    pub(crate) image_path: Result<String, ProcessDataError>,
    pub(crate) is_debugged: Result<bool, ProcessDataError>,
    pub (crate) is_elevated: Result<bool, ProcessDataError>,
    peb_base_address: Result<u64, ProcessDataError>,
    is_wow64: Result<bool, ProcessDataError>,
    is_protected: Result<bool, ProcessDataError>,
    is_secure: Result<bool, ProcessDataError>,
    pub(crate) thread_count: HashMap<String, usize>,
    pub(crate) malicious_threads: Option<Vec<u32>>,
    pub(crate) has_malicious_threads: bool,
    pub(crate) is_32_bit: Result<bool, ProcessDataError>,
}



impl ProcessData {
    /// Creates a new `ProcessData` instance with the given process ID.
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            image_path: Err(ProcessDataError::ImagePathError("Not initialized".to_string())),
            is_debugged: Err(ProcessDataError::DebuggerError("Not initialized".to_string())),
            peb_base_address: Err(ProcessDataError::PebBaseAddressError("Not initialized".to_string())),
            is_wow64: Err(ProcessDataError::Wow64Error("Not initialized".to_string())),
            is_protected: Err(ProcessDataError::ProtectionError("Not initialized".to_string())),
            is_secure: Err(ProcessDataError::SecurityError("Not initialized".to_string())),
            is_elevated: Err(ProcessDataError::ElevationError("Not initialized".to_string())),
            thread_count: HashMap::new(),
            malicious_threads: None,
            has_malicious_threads: false,
            is_32_bit: Err(ProcessDataError::SecurityError("Not initialized".to_string())),
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

        self.thread_count = process_info.query_thread_information();


        match process_info.injected_thread() {
            Ok((malicious_threads, has_malicious_threads)) => {
                self.malicious_threads = Some(malicious_threads);
                self.has_malicious_threads = has_malicious_threads;
            }
            Err(_) => {
                println!("Error occurred while scanning for injected threads.");
            }
        }

        self.is_32_bit = process_info.is_32_bit_process()
            .map_err(|e| ProcessDataError::Wow64Error(e.to_string()));
    }


    /// Calculates a base threat score for the process based on its characteristics.
    ///
    /// This method analyzes various attributes of the process, such as debugging status,
    /// elevation, WoW64 status, protection status, presence of malicious threads,
    /// token privileges, and thread characteristics to compute a threat score.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `f32`: The calculated threat score, ranging from 0.0 to 14.0.
    /// - `Vec<u32>`: A list of process IDs of detected malicious threads.
    ///
    /// # Scoring Factors
    ///
    /// - Debugged process: +2.0
    /// - Elevated process: +6.5
    /// - WoW64 process: +0.5
    /// - Protected process: -1.0
    /// - Each malicious thread: +0.5
    /// - Each token privilege: +1.25
    /// - Each hidden thread: +2.5
    /// - Each thread not owned by the process: +1.0
    /// - Is process 32-bit: 3.25
    ///
    /// The final score is clamped between 0.0 and 14.0.
    ///
    /// # Note
    ///
    /// This method does not modify the `ProcessData` instance and can be called multiple times
    /// to recalculate the score based on the current state of the process data.
    pub fn base_score_process(&self) -> (f32, Vec<u32>)
    {
        let mut threat_score: f32 = 0.0;
        let mut malicious_thread_pids = Vec::new();

        if let Ok(is_debugged) = self.is_debugged {
            if is_debugged {
                threat_score += 2.0;
            }
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

        if let Some(malicious_threads) = &self.malicious_threads {
            for _ in malicious_threads {
                threat_score += 0.5;
            }
            malicious_thread_pids.extend(malicious_threads.iter().cloned());
        }

        /*
        for _ in 0..self.token_privileges {
            threat_score += 1.25;
        }
        */

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

        threat_score = threat_score.min(14.0).max(1.0);

        (threat_score, malicious_thread_pids)
    }
}