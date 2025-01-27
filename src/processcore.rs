//! src/processcore.rs

// This module contains logic in scoring the threat of an active running process.





use std::collections::HashMap;
use std::{fmt::{Display, Formatter}, fmt};
use crate::processutils::ProcessInfo;
use crate::windowutils::WindowStats;




#[derive(Debug)]
/// Various errors that can happen when filling process data.
pub enum ProcessDataError
{
    /// Failed to fetch image path
    ImagePathError,
    /// Failed to check debugger status
    DebuggerError,
    /// Failed to check elevation status
    IsElevatedError,
    /// Failed to get PEB base address
    PebBaseAddressError,
    /// Failed to check WOW64 status
    Wow64Error,
    /// Failed to check protection status
    ProtectionError,
    /// Failed to check security status
    SecurityError,
    /// Failed to check elevation
    ElevationError,
    /// Failed to get handle count
    HandleCountError,
    /// Operation not initialized
    Uninitialized
}

impl Display for ProcessDataError
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
    {
        let msg = match self {
            ProcessDataError::ImagePathError => "Failed fetching image path",
            ProcessDataError::DebuggerError => "Debugger check failed",
            ProcessDataError::IsElevatedError => "Elevation check failed",
            ProcessDataError::PebBaseAddressError => "PEB base address error",
            ProcessDataError::Wow64Error => "WOW64 check failed",
            ProcessDataError::ProtectionError => "Protection check failed",
            ProcessDataError::SecurityError => "Security check failed",
            ProcessDataError::ElevationError => "Handle count error",
            ProcessDataError::HandleCountError => "Not initialized",
            ProcessDataError::Uninitialized => "Not initialized",
        };
        f.write_str(msg)
    }
}


#[derive(Debug)]
pub struct ProcessThreatData
{
    pub threat_score: f32,
    pub suspicious_imports: Vec<String>,
    pub is_suspect: bool,
    pub file_entropy: Option<f64>,
    pub file_sha256: Option<String>,
    pub write_count: f64,
}


#[derive(Debug)]
pub struct ProcessData
{
    pub(crate) pid: u32,
    pub(crate) image_path: Result<String, ProcessDataError>,
    pub(crate) is_debugged: Result<bool, ProcessDataError>,
    pub(crate) hidden_threads: u32,
    pub(crate) is_elevated: Result<bool, ProcessDataError>,
    pub(crate) peb_base_address: Result<u64, ProcessDataError>,
    pub(crate) is_wow64: Result<bool, ProcessDataError>,
    pub(crate) is_protected: Result<bool, ProcessDataError>,
    pub(crate) is_secure: Result<bool, ProcessDataError>,
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
            image_path: Err(ProcessDataError::Uninitialized),
            is_debugged: Err(ProcessDataError::Uninitialized),
            hidden_threads: 0,
            peb_base_address: Err(ProcessDataError::Uninitialized),
            is_wow64: Err(ProcessDataError::Uninitialized),
            is_protected: Err(ProcessDataError::Uninitialized),
            is_secure: Err(ProcessDataError::Uninitialized),
            is_elevated: Err(ProcessDataError::Uninitialized),
            is_32_bit: Err(ProcessDataError::Uninitialized),
            thread_count: HashMap::new(),
            window_title: None,
            window_stats: None,
            privileged_token_count: None,
            is_pe_zero: None
        }
    }

    pub fn fill_process_data(&mut self, process_info: &ProcessInfo)
    {
        self.image_path = process_info.get_process_image_path_ex()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|_| ProcessDataError::ImagePathError);

        self.is_debugged = process_info.is_debugger()
            .map_err(|_| ProcessDataError::DebuggerError);

        self.hidden_threads = process_info.get_hidden_thread_count();

        self.is_elevated = process_info.is_process_elevated()
            .map_err(|_| ProcessDataError::IsElevatedError);

        self.peb_base_address = process_info.get_peb_base_address()
            .map(|addr| addr as u64)
            .map_err(|_| ProcessDataError::PebBaseAddressError);

        self.is_wow64 = process_info.is_wow64()
            .map_err(|_| ProcessDataError::Wow64Error);

        self.is_protected = process_info.is_protected_process()
            .map_err(|_| ProcessDataError::ProtectionError);

        self.is_secure = process_info.is_secure_process()
            .map_err(|_| ProcessDataError::SecurityError);

        self.is_32_bit = process_info.is_32_bit_process()
            .map_err(|_| ProcessDataError::Wow64Error);

        self.window_title = process_info.get_window_title().ok().flatten();

        self.window_stats = match process_info.get_window_stats() {
            Ok(stats) => Some(stats),
            Err(_) => None,
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
}