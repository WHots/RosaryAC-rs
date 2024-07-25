//! src/processcore.rs

// This module contains logic in scoring the threat of an active running process.





use std::collections::HashMap;
use std::fmt;
use serde::{Serialize, Deserialize};
use crate::processutils::ProcessInfo;



/// Enum representing various errors that can occur when gathering process data.
#[derive(Serialize, Deserialize, Debug)]
pub enum ProcessDataError
{
    ImagePathError(String),
    DebuggerError(String),
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
    pid: u32,
    image_path: Result<String, ProcessDataError>,
    is_debugged: Result<bool, ProcessDataError>,
    peb_base_address: Result<u64, ProcessDataError>,
    is_wow64: Result<bool, ProcessDataError>,
    is_protected: Result<bool, ProcessDataError>,
    is_secure: Result<bool, ProcessDataError>,
    is_elevated: Result<bool, ProcessDataError>,
    thread_count: HashMap<String, usize>,
    handle_count: Result<i32, ProcessDataError>,
    token_privileges: i32,
}

const FILE_HANDLE_TYPE: u8 = 28;

const PRIVILEGE_TOKENS: &[&str] = &[
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeShutdownPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeRemoteShutdownPrivilege",
    "SeSecurityPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeUndockPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
];


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
            handle_count: Err(ProcessDataError::HandleCountError("Not initialized".to_string())),
            token_privileges: 0,
        }
    }

    /// Fills the `ProcessData` instance with data gathered from `ProcessInfo`.
    pub fn fill_process_data(&mut self, process_info: &ProcessInfo)
    {
        self.image_path = process_info.get_process_image_path_ex()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|e| ProcessDataError::ImagePathError(e.to_string()));

        self.is_debugged = process_info.is_debugger()
            .map_err(|e| ProcessDataError::DebuggerError(e.to_string()));

        self.peb_base_address = process_info.get_peb_base_address()
            .map(|addr| addr as u64)
            .map_err(|e| ProcessDataError::PebBaseAddressError(e.to_string()));

        self.is_wow64 = process_info.is_wow64()
            .map_err(|e| ProcessDataError::Wow64Error(e.to_string()));

        self.is_protected = process_info.is_protected_process()
            .map_err(|e| ProcessDataError::ProtectionError(e.to_string()));

        self.is_secure = process_info.is_secure_process()
            .map_err(|e| ProcessDataError::SecurityError(e.to_string()));

        self.is_elevated = process_info.is_process_elevated()
            .map_err(|e| ProcessDataError::ElevationError(e.to_string()));

        self.thread_count = process_info.query_thread_information();

        self.handle_count = process_info.get_current_handle_count(self.pid, FILE_HANDLE_TYPE)
            .map_err(|e| ProcessDataError::HandleCountError(e.to_string()));

        self.token_privileges = PRIVILEGE_TOKENS.iter().filter(|&&privilege| process_info.is_token_present(privilege) == 1).count() as i32;
    }
}
