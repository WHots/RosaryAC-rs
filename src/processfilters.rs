//! Module for enumerating processes with the same owner SID as the current process.

use std::fmt::Debug;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, PSID};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows_sys::Win32::System::Threading::{OpenProcess, GetCurrentProcessId, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER, TOKEN_QUERY, EqualSid, TOKEN_ACCESS_MASK};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::System::Threading::OpenProcessToken;

use crate::memorymanage::CleanHandle;

const TOKEN_ACCESS_TYPE: TOKEN_ACCESS_MASK = TOKEN_QUERY;
const PROCESS_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;





/// Custom error type for process enumeration operations.
#[derive(Debug)]
pub enum ProcessEnumError
{
    SnapshotCreationFailed,
    ProcessEnumerationFailed,
    SidRetrievalFailed,
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
        let current_process_sid = Self::get_process_sid(current_process_handle);

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
    ///
    /// # How it works
    ///
    /// 1. Opens the process token.
    /// 2. Retrieves token information.
    /// 3. Converts the SID to a string format.
    /// 4. Returns the string SID or None if any step fails.
    fn get_process_sid(process_handle: HANDLE) -> Option<*mut u16>
    {

        let mut token_handle: HANDLE = 0;

        if unsafe { OpenProcessToken(process_handle, TOKEN_ACCESS_TYPE, &mut token_handle) } == 0
        {
            return None;
        }

        let clean_token_handle = CleanHandle::new(token_handle);

        let mut token_info: Vec<u8> = vec![0; 256];
        let mut return_length: u32 = 0;

        if unsafe {
            GetTokenInformation(
                clean_token_handle?.as_raw(),
                TokenUser,
                token_info.as_mut_ptr() as *mut _,
                token_info.len() as u32,
                &mut return_length,
            )
        } == 0 {
            return None;
        }

        let token_user: TOKEN_USER = unsafe { std::ptr::read(token_info.as_ptr() as *const TOKEN_USER) };
        let mut sid_string: *mut u16 = null_mut();

        if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) } == 0
        {
            return None;
        }

        Some(sid_string)
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

    /// Enumerates processes and fills the list of process IDs owned by the same user as the current process.
    ///
    /// # Returns
    ///
    /// `Result<(), ProcessEnumError>` indicating success or the specific error encountered.
    pub fn enumerate_processes(&mut self) -> Result<(), ProcessEnumError>
    {

        let current_process_sid = self.current_process_sid.ok_or(ProcessEnumError::SidRetrievalFailed)?;

        let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        self.snapshot_handle = Some(CleanHandle::new(snapshot_handle).ok_or(ProcessEnumError::SnapshotCreationFailed)?);

        let snapshot_handle = self.snapshot_handle.as_ref().ok_or(ProcessEnumError::SnapshotCreationFailed)?;

        let mut process_entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { std::mem::zeroed() }
        };

        if unsafe { Process32FirstW(snapshot_handle.as_raw(), &mut process_entry) } == 0
        {
            return Err(ProcessEnumError::ProcessEnumerationFailed);
        }

        loop {

            if process_entry.th32ProcessID != self.current_process_id
            {
                let process_handle = CleanHandle::new(unsafe {
                    OpenProcess(PROCESS_ACCESS, 0, process_entry.th32ProcessID)
                });

                if let Some(process_handle) = process_handle
                {
                    if let Some(process_sid) = Self::get_process_sid(process_handle.as_raw())
                    {
                        if Self::compare_sids(process_sid as PSID, current_process_sid as PSID)
                        {
                            self.matching_pids.push(process_entry.th32ProcessID);
                            self.open_process_handles.push(process_handle);
                        }

                        unsafe { LocalFree(process_sid as *mut _) };
                    }
                }
            }

            if unsafe { Process32NextW(snapshot_handle.as_raw(), &mut process_entry) } == 0
            {
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
    /// Cleans up resources when the ProcessEnumerator is dropped.

    fn drop(&mut self)
    {
        if let Some(sid) = self.current_process_sid.take()
        {
            unsafe { LocalFree(sid as *mut _) };
        }

        if let Some(handle) = self.snapshot_handle.take()
        {
            drop(handle);
        }

        self.open_process_handles.clear();
    }
}