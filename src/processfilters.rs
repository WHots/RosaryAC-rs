//! src/processfilters.rs

// This module contains process filter logic.





use std::collections::HashSet;
use std::ffi::c_void;
use std::fmt::Debug;
use std::mem::size_of;
use std::ptr::null_mut;
use std::{fmt, mem, slice};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, LocalFree, PSID, STATUS_INFO_LENGTH_MISMATCH};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows_sys::Win32::System::Threading::{OpenProcess, GetCurrentProcessId, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER, TOKEN_QUERY, EqualSid, TOKEN_ACCESS_MASK};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use crate::debug_log;

use crate::memorymanage::{CleanBuffer, CleanHandle};
use crate::ntexapi_h::{SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use crate::ntexapi_h::SystemInformationClass::{SystemExtendedHandleInformation};
use crate::ntpsapi_h::NtQuerySystemInformation;
use crate::processutils::ProcessError;

const TOKEN_ACCESS_TYPE: TOKEN_ACCESS_MASK = TOKEN_QUERY;
const PROCESS_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;





/// Custom error output for process enumeration operations.
#[derive(Debug)]
pub enum ProcessEnumError
{
    SnapshotCreationFailed,
    ProcessEnumerationFailed,
    SidRetrievalFailed,
    TokenInformation,
    OpenProcessToken,
    Other(i32)
}


impl fmt::Display for ProcessEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessEnumError::SnapshotCreationFailed => write!(f, "Failed to create snapshot of running processes."),
            ProcessEnumError::ProcessEnumerationFailed => write!(f, "Failed to enumerate process list."),
            ProcessEnumError::SidRetrievalFailed => write!(f, "Failed to get process SID."),
            ProcessEnumError::TokenInformation => write!(f, "Failed to query token information."),
            ProcessEnumError::OpenProcessToken => write!(f, "Failed to open process token."),
            ProcessEnumError::Other(error_code) => write!(f, "Unknown error: {}", error_code),
        }
    }
}

impl From<i32> for ProcessEnumError {
    fn from(error_code: i32) -> Self {
        ProcessEnumError::Other(error_code)
    }
}


/// Struct to hold various types regarding the process filter process.
pub struct ProcessEnumerator
{
    matching_pids: Vec<u32>,
    current_process_sid: Option<*mut u16>,
    current_process_id: u32,
    snapshot_handle: Option<CleanHandle>,
    open_process_handles: Vec<CleanHandle>,
}

impl ProcessEnumerator
{

    /// Creates a new `ProcessEnumerator`.
    ///
    /// # Returns
    ///
    /// A new instance of `ProcessEnumerator`.
    pub fn new() -> Self {
        let current_process_handle = unsafe { GetCurrentProcess() };
        let current_process_id = unsafe { GetCurrentProcessId() };
        let current_process_sid = Self::get_process_sid(current_process_handle).ok();

        Self {
            matching_pids: Vec::new(),
            current_process_sid,
            current_process_id,
            snapshot_handle: None,
            open_process_handles: Vec::new(),
        }
    }


    /// Retrieves the SID of the specified process.
    ///
    /// # Arguments
    ///
    /// * `process_handle` - The handle to the process.
    ///
    /// # Returns
    ///
    /// `Some(*mut u16)` if the SID was successfully retrieved, `None` otherwise.
    #[inline]
    fn get_process_sid(process_handle: HANDLE) -> Result<*mut u16, ProcessEnumError>
    {

        let mut token_handle: HANDLE = 0;

        if unsafe { OpenProcessToken(process_handle, TOKEN_ACCESS_TYPE, &mut token_handle) } == 0 {
            debug_log!(format!("Error opening process token: {}", unsafe { GetLastError() }));
            return Err(ProcessEnumError::OpenProcessToken);
        }

        let clean_token_handle = CleanHandle::new(token_handle).ok_or(ProcessEnumError::OpenProcessToken)?;

        let mut clean_buffer = CleanBuffer::new(256);
        let mut return_length: u32 = 0;

        if unsafe {
            GetTokenInformation(
                clean_token_handle.as_raw(),
                TokenUser,
                clean_buffer.as_mut_ptr() as *mut _,
                clean_buffer.as_slice().len() as u32,
                &mut return_length,
            )
        } == 0 {
            debug_log!(format!("Error getting token information: {}", unsafe { GetLastError() }));
            return Err(ProcessEnumError::TokenInformation);
        }

        let token_user: TOKEN_USER = unsafe {
            std::ptr::read(clean_buffer.as_slice().as_ptr() as *const TOKEN_USER)
        };

        let mut sid_string: *mut u16 = null_mut();

        if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) } == 0
        {
            debug_log!(format!("Error converting sid: {}", unsafe { GetLastError() }));
            return Err(ProcessEnumError::SidRetrievalFailed);
        }

        Ok(sid_string)
    }


    /// Compares two SIDs.
    ///
    /// # Arguments
    ///
    /// * `sid1` - The first SID to compare.
    /// * `sid2` - The second SID to compare.
    ///
    /// # Returns
    ///
    /// `true` if the SIDs are equal, `false` otherwise.
    #[inline]
    fn compare_sids(sid1: PSID, sid2: PSID) -> bool {
        unsafe { EqualSid(sid1 as *mut _, sid2 as *mut _) != 0 }
    }



    pub fn enumerate_processes(&mut self) -> Result<(), ProcessEnumError>
    {

        let current_process_sid = self.current_process_sid
            .ok_or_else(|| { debug_log!("Failed to get current process SID");ProcessEnumError::SidRetrievalFailed })?;

        let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        if snapshot_handle == -1 {
            debug_log!(format!("Error creating snapshot of process list: {}", unsafe { GetLastError() }));
            return Err(ProcessEnumError::SnapshotCreationFailed);
        }

        self.snapshot_handle = Some(CleanHandle::new(snapshot_handle)
            .ok_or_else(|| { debug_log!("Failed to create clean handle for snapshot");ProcessEnumError::SnapshotCreationFailed })?);

        let snapshot_handle = self.snapshot_handle.as_ref()
            .ok_or_else(|| { debug_log!("Snapshot handle was None after creation");ProcessEnumError::SnapshotCreationFailed })?;

        let mut process_entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { mem::zeroed() }
        };

        if unsafe { Process32FirstW(snapshot_handle.as_raw(), &mut process_entry) } == 0 {
            debug_log!(format!("Error with process enumeration: {}", unsafe { GetLastError() }));
            return Err(ProcessEnumError::ProcessEnumerationFailed);
        }

        let mut processes_checked = 0;
        let mut processes_matched = 0;

        loop {
            processes_checked += 1;

            if process_entry.th32ProcessID != self.current_process_id {
                let process_handle = unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_entry.th32ProcessID)
                };

                if process_handle == 0 { debug_log!(format!("Failed to open process {} with error: {}",process_entry.th32ProcessID,unsafe { GetLastError() }));
                    continue;
                }

                let clean_handle = match CleanHandle::new(process_handle) {
                    Some(handle) => handle,
                    None => { debug_log!(format!("Failed to create clean handle for process {}",process_entry.th32ProcessID));
                        continue;
                    }
                };

                match Self::get_process_sid(clean_handle.as_raw()) {
                    Ok(process_sid) => {
                        if Self::compare_sids(process_sid as PSID, current_process_sid as PSID) {
                            self.matching_pids.push(process_entry.th32ProcessID);
                            self.open_process_handles.push(clean_handle);
                            processes_matched += 1;
                        }
                        unsafe { LocalFree(process_sid as *mut _) };
                    }
                    Err(e) => {
                        debug_log!(format!("Failed to get SID for process {} with error: {}",process_entry.th32ProcessID,unsafe { GetLastError() }));
                    }
                }
            }

            if unsafe { Process32NextW(snapshot_handle.as_raw(), &mut process_entry) } == 0 {
                if unsafe { GetLastError() } != 18 {
                    debug_log!(format!("Process32NextW failed with unexpected error: {}", unsafe { GetLastError() }));
                }
                break;
            }
        }

        Ok(())
    }


    /// Process the list of matching process IDs with a generic function.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure or function that processes each process ID.
    ///
    /// # How it works
    ///
    /// Iterates through the list of matching PIDs, applying the provided function to each.
    pub fn process_matching_pids<F>(&self, f: F)
        where
            F: Fn(u32),
    {
        for &pid in &self.matching_pids {
            f(pid);
        }
    }
}


impl Drop for ProcessEnumerator
{
    fn drop(&mut self)
    {
        if let Some(sid) = self.current_process_sid.take() {
            unsafe { LocalFree(sid as *mut _) };
        }

        if let Some(handle) = self.snapshot_handle.take() {
            drop(handle);
        }

        self.open_process_handles.clear();
    }
}