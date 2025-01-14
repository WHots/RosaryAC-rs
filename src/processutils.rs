//! src/processutils.rs

// This module contains process utility function based around process interactions.





use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, OsStr, OsString};
use std::path::Path;
use std::{fmt, mem, ptr};
use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use windows_sys::Win32::Foundation::{BOOL, BOOLEAN, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, LUID, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetProcessIdOfThread, GetProcessIoCounters, IO_COUNTERS, IsWow64Process, OpenProcessToken, OpenThread, PEB, PROCESS_BASIC_INFORMATION, THREAD_ACCESS_RIGHTS, THREAD_QUERY_INFORMATION};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;

use windows_sys::Win32::Security::{AllocateLocallyUniqueId, GetTokenInformation, LookupPrivilegeNameW, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::SystemServices::PRIVILEGE_SET_ALL_NECESSARY;
use crate::debug_log;

use crate::memorymanage::{CleanBuffer, CleanHandle};
use crate::ntexapi_h::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, SystemInformationClass};
use crate::ntexapi_h::SystemInformationClass::SystemHandleInformation;
use crate::ntpsapi_h::{NtPrivilegeCheck, NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken, NtQuerySystemInformation, PROCESS_EXTENDED_BASIC_INFORMATION, ProcessInformationClass, THREAD_BASIC_INFORMATION, THREADINFOCLASS};
use crate::winnt_h::{TOKEN_PRIVILEGES, TokenInformationClass};
use crate::winnt_h::TokenInformationClass::TokenPrivileges;





pub enum ProcessError
{
    /// Failed to open a handle to the process.
    OpenProcessFailed,
    /// Failed to enumerate or get information about process modules.
    ModuleOperationFailed,
    /// The module's base address was null.
    NullModuleAddress,
    /// Failed to get the process image path.
    ImagePathFailed,
    /// Failed to open or query the process token.
    TokenOperationFailed,
    /// Failed to query the debug port.
    DebugPortQueryFailed,
    /// Failed to query process information.
    ProcessInfoQueryFailed,
    /// Failed to check process elevation status.
    ElevationCheckFailed,
    /// Failed to get the PEB base address.
    PebAddressFailed,
    /// Failed to determine process architecture.
    ArchitectureCheckFailed,
    /// Failed to get IO counters.
    IoCountersFailed,
    /// Failed to enumerate or get information about threads.
    ThreadOperationFailed,
    /// Failed to get handle count information.
    HandleCountFailed,
    /// Creating a clean / safe handle to the process failed.
    CleanHandleFailed,
    /// Other errors represented by an integer code.
    Other(i32),
}

impl Display for ProcessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ProcessError::OpenProcessFailed => write!(f, "Failed to open process"),
            ProcessError::ModuleOperationFailed => write!(f, "Failed to perform module operation"),
            ProcessError::NullModuleAddress => write!(f, "Module base address is null"),
            ProcessError::ImagePathFailed => write!(f, "Failed to get process image path"),
            ProcessError::TokenOperationFailed => write!(f, "Failed to perform token operation"),
            ProcessError::DebugPortQueryFailed => write!(f, "Failed to query debug port"),
            ProcessError::ProcessInfoQueryFailed => write!(f, "Failed to query process information"),
            ProcessError::ElevationCheckFailed => write!(f, "Failed to check process elevation"),
            ProcessError::PebAddressFailed => write!(f, "Failed to get PEB address"),
            ProcessError::ArchitectureCheckFailed => write!(f, "Failed to check process architecture"),
            ProcessError::IoCountersFailed => write!(f, "Failed to get IO counters"),
            ProcessError::ThreadOperationFailed => write!(f, "Failed to perform thread operation"),
            ProcessError::HandleCountFailed => write!(f, "Failed to get handle count"),
            ProcessError::CleanHandleFailed => write!(f, "Failed to create a clean / safe handle to process."),
            ProcessError::Other(code) => write!(f, "Unknown error: {}", code),
        }
    }
}


pub const PRIVILEGE_TOKENS: &[&str] = &[
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

const TOKEN_ACCESS_TYPE: TOKEN_ACCESS_MASK = TOKEN_QUERY;
const THREAD_ACCESS_TYPE: THREAD_ACCESS_RIGHTS = THREAD_QUERY_INFORMATION;




impl PROCESS_EXTENDED_BASIC_INFORMATION
{
    /// Creates a new instance of `PROCESS_EXTENDED_BASIC_INFORMATION` with zero-initialized fields.
    ///
    /// # Returns
    ///
    /// * `Self` - A new instance of `PROCESS_EXTENDED_BASIC_INFORMATION`.
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }
}



pub struct ProcessInfo
{
    pub(crate) pid: u32,
    process_handle: HANDLE,
}

impl ProcessInfo
{
    /// Constructs a new `ProcessInfo` with the given process ID and handle.
    ///
    /// # Arguments
    ///
    /// * `pid` - A u32 representing the process ID.
    /// * `process_handle` - A HANDLE to the process.
    ///
    /// # Returns
    ///
    /// * `Self` - The newly created `ProcessInfo`.
    pub fn new(pid: u32, process_handle: HANDLE) -> Self
    {
        Self {
            pid,
            process_handle,
        }
    }


    /// Returns the `CLIENT_ID` for a thread given its handle.
    ///
    /// # Safety
    ///
    /// The caller must ensure `h_thread` is a valid handle to a thread that has not exited.
    /// The function is unsafe due to raw pointer operations and system call usage.
    ///
    /// # Returns
    ///
    /// An `Option<CLIENT_ID>` which is `Some` if successful, or `None` otherwise.
    #[inline]
    fn get_thread_client_id(h_thread: HANDLE) -> Option<CLIENT_ID>
    {
        let mut thread_info: THREAD_BASIC_INFORMATION = unsafe { mem::zeroed() };

        let status = unsafe {
            NtQueryInformationThread(
                h_thread,
                THREADINFOCLASS::ThreadBasicInformation,
                &mut thread_info as *mut _ as *mut c_void,
                mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };

        if status == 0
        {
            Some(thread_info.client_id)
        } else {
            None
        }
    }


    /// This function checks if a given privilege matches the specified token identifier.
    ///
    /// # Arguments
    /// * `privilege` - A reference to an `LUID_AND_ATTRIBUTES` structure representing the privilege to check.
    /// * `token_identifier` - A string representing the token identifier. It can be in the format "LowPart,HighPart" or the name of the privilege.
    ///
    /// # Returns
    /// * `true` if the privilege matches the specified token identifier, otherwise `false`.
    ///
    /// # Safety
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    #[inline]
    fn is_matching_privilege(&self, privilege: &LUID_AND_ATTRIBUTES, token_identifier: &str) -> bool
    {

        if let Some((low, high)) = token_identifier.split_once(',') {
            if let (Ok(low_part), Ok(high_part)) = (low.trim().parse::<u32>(), high.trim().parse::<i32>()) {
                return privilege.Luid.LowPart == low_part && privilege.Luid.HighPart == high_part;
            }
        }

        let mut name_buffer = [0u16; 256];
        let mut name_size = name_buffer.len() as u32;

        unsafe {
            if LookupPrivilegeNameW(ptr::null(), &privilege.Luid as *const LUID, name_buffer.as_mut_ptr(), &mut name_size, ) != 0 {
                let privilege_name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
                return privilege_name.trim_end_matches('\0') == token_identifier;
            }
        }

        false
    }


    /// This function checks if a thread has the "hide from debugger" flag enabled.
    ///
    /// # Arguments
    /// * `h_thread` - Handle to the thread to check.
    ///
    /// # Returns
    /// * `true` if the thread has the "hide from debugger" flag set, otherwise `false`.
    ///
    /// # Safety
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    #[inline]
    fn is_thread_hidden_from_debugger(h_thread: HANDLE) -> bool
    {
        let mut thread_hidden: u32 = 0;

        let status = unsafe {
            NtQueryInformationThread(
                h_thread,
                THREADINFOCLASS::ThreadHideFromDebugger,
                &mut thread_hidden as *mut _ as *mut c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
            )
        };

        status == 0 && thread_hidden != 0
    }


    /// Checks if a specific process module exists.
    ///
    /// # Arguments
    ///
    /// * `module_name` - The name of the module to look for as an `OsStr`.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the module exists, otherwise `false`.
    pub fn module_exists(&self, module_name: &OsStr) -> bool
    {

        const MAX_MODULES: usize = 1024;
        let mut h_modules = CleanBuffer::new(MAX_MODULES);
        let mut cb_needed: u32 = 0;

        if unsafe { EnumProcessModulesEx( self.process_handle, h_modules.as_mut_ptr() as *mut HMODULE, (MAX_MODULES * std::mem::size_of::<HMODULE>()) as u32, &mut cb_needed, LIST_MODULES_ALL, ) } == 0
        {
            return false;
        }

        let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();
        let mut buffer = CleanBuffer::new(260);

        (0..module_count).any(|i| {
            let result = unsafe { GetModuleFileNameExW(self.process_handle, *(h_modules.as_slice().as_ptr().add(i) as *const HMODULE), buffer.as_mut_ptr(), buffer.buffer.len() as u32, ) };

            if result == 0 {
                return false;
            }

            buffer.truncate_at_null();
            let module_path = OsString::from_wide(buffer.as_slice());
            let module_name_in_path = Path::new(&module_path).file_name().unwrap_or(OsStr::new(""));

            module_name_in_path == module_name
        })
    }


    /// Determines if the process is a 32-bit process.
    ///
    /// This method checks if the process is running under the WOW64 subsystem, which indicates
    /// that the process is a 32-bit process running on a 64-bit Windows system.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is a 32-bit process, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid or if the operation fails.
    ///
    /// # Safety
    ///
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    pub fn is_32_bit_process(&self) -> Result<bool, ProcessError>
    {

        let mut is_wow64: i32 = 0;
        let result = unsafe { IsWow64Process(self.process_handle, &mut is_wow64) };

        if result == 0
        {
            debug_log!(format!("Error checking if process is 32-bit: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ArchitectureCheckFailed)
        }

        Ok(is_wow64 != 0)
    }


    /// Retrieves a list of all privileges of the process.
    ///
    /// This method queries the process token for its privileges and returns them as a list of
    /// human-readable privilege names.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<String>, String>` - A list of privilege names if successful, or an error message.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid, the process token cannot be opened,
    /// or the token information cannot be retrieved.
    ///
    /// # Safety
    ///
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    pub fn get_process_privileges(&self) -> Result<Vec<String>, ProcessError>
    {

        let mut token_handle: HANDLE = INVALID_HANDLE_VALUE;

        if unsafe { OpenProcessToken(self.process_handle, TOKEN_QUERY, &mut token_handle) } == 0
        {
            debug_log!(format!("Error opening process token: {}", unsafe { GetLastError() }));
            return Err(ProcessError::TokenOperationFailed)
        }

        let safe_handle = match CleanHandle::new(token_handle) {
            Some(handle) => handle,
            None => return Err(ProcessError::CleanHandleFailed),
        };

        let mut return_length = 0;
        unsafe { GetTokenInformation(safe_handle.as_raw(), TokenPrivileges as u32 as TOKEN_INFORMATION_CLASS, ptr::null_mut(), 0, &mut return_length, ) };

        if return_length == 0
        {
            let error_code = unsafe { GetLastError() };
            debug_log!(format!("Error getting token information: {}", unsafe { GetLastError() }));
            return Err(ProcessError::TokenOperationFailed);
        }

        let mut buffer = vec![0u8; return_length as usize];
        let token_privileges = buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES;

        if unsafe { GetTokenInformation(safe_handle.as_raw(), TokenPrivileges as u32 as TOKEN_INFORMATION_CLASS, token_privileges as *mut _, return_length, &mut return_length, ) } == 0
        {
            debug_log!(format!("Error getting token information: {}", unsafe { GetLastError() }));
            return Err(ProcessError::TokenOperationFailed);
        }

        let privileges = unsafe { std::slice::from_raw_parts((*token_privileges).Privileges.as_ptr(), (*token_privileges).PrivilegeCount as usize, ) };

        let mut privilege_names = Vec::new();

        for privilege in privileges
        {
            let mut name_buffer = [0u16; 256];
            let mut name_size = name_buffer.len() as u32;

            if unsafe { LookupPrivilegeNameW(ptr::null(), &privilege.Luid as *const LUID, name_buffer.as_mut_ptr(), &mut name_size, ) } != 0
            {
                let privilege_name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
                privilege_names.push(privilege_name.trim_end_matches('\0').to_string());
            }
        }

        Ok(privilege_names)
    }


    /// Retrieves the handle and size of the main module of the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<(HMODULE, usize), String>` - The handle and size of the main module or an error.
    pub fn get_main_module_ex(&self) -> Result<(*const u8, usize), ProcessError>
    {

        let mut h_module: HMODULE = unsafe { std::mem::zeroed() };
        let mut cb_needed: u32 = 0;

        if unsafe { EnumProcessModulesEx(self.process_handle, &mut h_module, std::mem::size_of_val(&h_module) as u32, &mut cb_needed, LIST_MODULES_ALL) == 0 } {
            debug_log!(format!("Error enum process modules: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ModuleOperationFailed);
        }

        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        if unsafe { GetModuleInformation(self.process_handle, h_module, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32) == 0 } {
            debug_log!(format!("Error getting module information: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ModuleOperationFailed);
        }

        let base_address: *const u8 = module_info.lpBaseOfDll as *const u8;

        if base_address.is_null() {
            debug_log!(format!("The module base address was null: {}", unsafe { GetLastError() }));
            return Err(ProcessError::NullModuleAddress);
        }

        Ok((base_address, module_info.SizeOfImage as usize))
    }


    /// Retrieves the file path of the main module of the process as an `OsStr`.
    ///
    /// This method fills a provided buffer with the file path and stores the result in an `OsString`.
    /// It then returns a reference to the `OsStr` slice of the `OsString`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `Vec<u16>` that will be used to store the file path.
    /// * `output` - A mutable reference to an `OsString` that will be used to store the file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails, specifically if the Windows API call to retrieve the module file name fails.
    ///
    /// # Returns
    ///
    /// * `Result<&'a OsStr, &'static str>` - A reference to the `OsStr` slice containing the file path of the main module, or an error if the operation fails.
    pub fn get_process_image_path_ex(&self) -> Result<OsString, ProcessError>
    {

        const MAX_PATH: usize = 260;
        let mut buffer = CleanBuffer::new(MAX_PATH);

        let result = unsafe { GetModuleFileNameExW(self.process_handle, 0, buffer.as_mut_ptr(), buffer.buffer.len() as u32, ) };

        if result == 0 {
            debug_log!(format!("Error getting process image name: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ImagePathFailed);
        }

        buffer.truncate_at_null();

        let output = OsString::from_wide(buffer.as_slice());
        Ok(output)
    }


    // Checks if the process is being debugged by querying the debug port.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is being debugged, otherwise `false`.
    pub fn is_debugger(&self) -> Result<bool, ProcessError>
    {

        let mut debug_port: isize = 0;
        let mut return_length: u32 = 0;

        let status = unsafe { NtQueryInformationProcess(self.process_handle, ProcessInformationClass::ProcessDebugPort as u32, &mut debug_port as *mut _ as *mut c_void, size_of::<isize>() as u32, &mut return_length, ) };

        if status != 0
        {
            debug_log!(format!("Error checking for debug flag in process info query: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ProcessInfoQueryFailed);
        }

        Ok(debug_port != 0)
    }


    /// Retrieves the base address of the Process Environment Block (PEB).
    ///
    /// # Errors
    ///
    /// Returns an error if no process is associated or if the query fails.
    ///
    /// # Returns
    ///
    /// * `Result<*mut PEB, String>` - The base address of the PEB or an error.
    pub fn get_peb_base_address(&self) -> Result<*mut PEB, ProcessError>
    {

        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = unsafe { NtQueryInformationProcess(self.process_handle, ProcessInformationClass::ProcessBasicInformation as u32, &mut pbi as *mut _ as *mut _, std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut return_length, ) };

        if status != 0
        {
            debug_log!(format!("Error getting PEB address: {}", unsafe { GetLastError() }));
            return Err(ProcessError::PebAddressFailed);
        }

        Ok(pbi.PebBaseAddress)
    }


    /// Determines if the process is running under WOW64.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid or if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is running under WOW64, `false` otherwise, or an error.
    pub fn is_wow64(&self) -> Result<bool, ProcessError>
    {

        let mut pebi: PROCESS_EXTENDED_BASIC_INFORMATION = PROCESS_EXTENDED_BASIC_INFORMATION::new();
        pebi.Size = size_of::<PROCESS_EXTENDED_BASIC_INFORMATION>();

        let mut return_length: u32 = 0;

        let status = unsafe { NtQueryInformationProcess(self.process_handle, ProcessInformationClass::ProcessBasicInformation as u32, &mut pebi as *mut _ as *mut _, std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut return_length, ) };

        if status != 0
        {
            debug_log!(format!("Error checking if WoW64 Emulation: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ProcessInfoQueryFailed);
        }

        const FLAG_IS_WOW64_PROCESS: u32 = 0x00000002;
        Ok(pebi.Flags & FLAG_IS_WOW64_PROCESS != 0)
    }


    /// Determines if the process is protected.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid or if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is protected, `false` otherwise, or an error.
    pub fn is_protected_process(&self) -> Result<bool, ProcessError>
    {

        let mut pebi: PROCESS_EXTENDED_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        pebi.Size = std::mem::size_of::<PROCESS_EXTENDED_BASIC_INFORMATION>();

        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle,
                ProcessInformationClass::ProcessBasicInformation as u32,
                &mut pebi as *mut _ as *mut _,
                pebi.Size as u32,
                &mut return_length,
            )
        };

        if status != 0
        {
            debug_log!(format!("Error checking if process is protected: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ProcessInfoQueryFailed);
        }

        const FLAG_IS_PROTECTED_PROCESS: u32 = 0x00000001;
        Ok(pebi.Flags & FLAG_IS_PROTECTED_PROCESS != 0)
    }


    /// Determines if the process is a secure process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid or if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is a secure process, `false` otherwise, or an error.
    pub fn is_secure_process(&self) -> Result<bool, ProcessError>
    {

        let mut pebi: PROCESS_EXTENDED_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        pebi.Size = std::mem::size_of::<PROCESS_EXTENDED_BASIC_INFORMATION>();

        let mut return_length: u32 = 0;

        let status = unsafe { NtQueryInformationProcess(self.process_handle, ProcessInformationClass::ProcessBasicInformation as u32, &mut pebi as *mut _ as *mut _, pebi.Size as u32, &mut return_length, ) };

        if status != 0
        {
            debug_log!(format!("Error checking if process is secured: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ProcessInfoQueryFailed);
        }

        const FLAG_IS_SECURE_PROCESS: u32 = 0x00000080;
        Ok(pebi.Flags & FLAG_IS_SECURE_PROCESS != 0)
    }


    /// Checks if the process associated with the provided handle is running with elevated privileges.
    ///
    /// # Errors
    ///
    /// Returns an error if the function fails to open the process token or retrieve the token information.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the process is elevated, or `Ok(false)` otherwise.
    pub fn is_process_elevated(&self) -> Result<bool, ProcessError>
    {

        let mut token_handle: HANDLE = INVALID_HANDLE_VALUE;

        let token_opened: BOOL = unsafe { OpenProcessToken(self.process_handle, TOKEN_ACCESS_TYPE, &mut token_handle, ) };

        if token_opened == 0 {
            debug_log!(format!("Error checking if process is elevated: {}", unsafe { GetLastError() }));
            return Err(ProcessError::TokenOperationFailed);
        }

        let safe_handle = match CleanHandle::new(token_handle) {
            Some(handle) => handle,
            None => return Ok(false)
        };

        let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: u32 = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let token_info: BOOL = unsafe { GetTokenInformation(safe_handle.as_raw(), TokenElevation, &mut elevation as *mut _ as *mut _, size, &mut size, ) };

        if token_info == 0
        {
            debug_log!(format!("Error checking if process is elevated: {}", unsafe { GetLastError() }));
            return Err(ProcessError::TokenOperationFailed);
        }

        Ok(elevation.TokenIsElevated != 0)
    }


    /// Enumerates the threads associated with the process and counts them.
    ///
    /// This method creates a snapshot of the threads for the process identified by `self.pid`
    /// and counts the number of threads owned by the process as well as any anomaly threads.
    ///
    /// It also counts the number of threads with the "hide from debugger" flag enabled.
    ///
    /// # Returns
    ///
    /// A `HashMap<String, usize>` where the keys are "Owned threads", "Anomaly threads" (if any),
    /// and "Hidden threads" (if any), and the values are the respective counts of those threads.
    ///
    /// # Safety
    ///
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    pub fn query_thread_information(&self) -> HashMap<String, usize>
    {
        let mut counts = HashMap::new();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid) };
        let snapshot = match CleanHandle::new(snapshot) {
            Some(handle) => handle,
            None => return counts,
        };

        let mut thread_entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut not_owned = 0;
        let mut hidden_thread_count = 0;
        let mut total_count = 0;


        unsafe {
            if Thread32First(snapshot.as_raw(), &mut thread_entry) != 0
            {
                loop {
                    if thread_entry.th32OwnerProcessID == self.pid
                    {
                        total_count += 1;

                        let h_thread = OpenThread(THREAD_ACCESS_TYPE, 0, thread_entry.th32ThreadID);

                        if let Some(thread_handle) = CleanHandle::new(h_thread)
                        {
                            if Self::is_thread_hidden_from_debugger(thread_handle.as_raw())
                            {
                                hidden_thread_count += 1;
                            }

                            let thread_owner_id: u32 = GetProcessIdOfThread(thread_handle.as_raw());

                            if thread_owner_id != thread_entry.th32OwnerProcessID
                            {
                                not_owned += 1;
                            }
                        }
                    }

                    if Thread32Next(snapshot.as_raw(), &mut thread_entry) == 0 {
                        break;
                    }
                }
            }
        }


        counts.insert("Total".to_string(), total_count);
        counts.insert("NOT Owned".to_string(), not_owned);
        counts.insert("Hidden Flag".to_string(), hidden_thread_count);

        counts
    }


    /// Detects potential thread injection in the current process.
    ///
    /// Identifies threads associated with the current process but owned by different processes.
    ///
    /// # Returns
    ///
    /// - `Ok((Vec<u32>, bool))`: Process IDs of potential injected thread owners and whether any were found.
    /// - `Err(bool)`: `true` if an error occurred during detection.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows API calls for system thread enumeration and analysis.
    pub fn injected_thread(&self) -> Result<(Vec<u32>, bool), bool>
    {

        let mut injected_thread_owners = HashSet::new();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        let snapshot = CleanHandle::new(snapshot).ok_or(true)?;

        let mut thread_entry_buffer = CleanBuffer::new(std::mem::size_of::<THREADENTRY32>() / std::mem::size_of::<u16>());
        let thread_entry = unsafe { &mut *(thread_entry_buffer.as_mut_ptr() as *mut THREADENTRY32) };
        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        unsafe {
            if Thread32First(snapshot.as_raw(), thread_entry) != 0 {
                loop {
                    if thread_entry.th32OwnerProcessID == self.pid {
                        let thread_handle = OpenThread(0x0040, 0, thread_entry.th32ThreadID);

                        if let Some(thread_handle) = CleanHandle::new(thread_handle) {
                            let thread_owner_id = GetProcessIdOfThread(thread_handle.as_raw());

                            if thread_owner_id != 0 && thread_owner_id != self.pid {
                                injected_thread_owners.insert(thread_owner_id);
                            }
                        }
                    }

                    if Thread32Next(snapshot.as_raw(), thread_entry) == 0 {
                        break;
                    }
                }
            } else {
                return Err(true);
            }
        }

        let malicious_threads: Vec<u32> = injected_thread_owners.into_iter().collect();
        let has_malicious_threads = !malicious_threads.is_empty();

        Ok((malicious_threads, has_malicious_threads))
    }


    /// Retrieves the count of handles for a specific process and object type.
    ///
    /// This method queries the system for handle information and counts the number of handles
    /// that match the given process ID and object type.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID for which to count handles.
    /// * `object_type` - The type of object to count handles for.
    ///
    /// # Returns
    ///
    /// Returns the count of handles matching the specified criteria, or -1 if an error occurred.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it uses raw pointers and calls the Windows API function
    /// `NtQuerySystemInformation`, which is not guaranteed to be safe.
    pub fn get_current_handle_count(&self, pid: u32, object_type: u8) -> Result<i32, NTSTATUS>
    {
        let mut buffer_size = 0;
        let mut buffer: Vec<u8>;
        let mut status: NTSTATUS;

        unsafe { status = NtQuerySystemInformation(SystemInformationClass::SystemHandleInformation, std::ptr::null_mut(), 0, &mut buffer_size); }

        if status != STATUS_INFO_LENGTH_MISMATCH
        {
            debug_log!(format!("Error getting system handle count: {}", unsafe { GetLastError() }));
            return Err(status);
        }

        loop {
            buffer = vec![0; buffer_size as usize];
            unsafe { status = NtQuerySystemInformation(SystemInformationClass::SystemHandleInformation, buffer.as_mut_ptr() as *mut _, buffer.len() as u32, &mut buffer_size); }

            if status != STATUS_INFO_LENGTH_MISMATCH {
                break;
            }
        }

        let handle_count = u64::from_ne_bytes(buffer[0..8].try_into().unwrap()) as usize;
        let handles_offset = 8;
        let handle_size = 24;
        let mut count = 0;

        for i in 0..handle_count
        {
            let base = handles_offset + i * handle_size;
            let handle_pid = u32::from_ne_bytes(buffer[base..base + 4].try_into().unwrap());
            let handle_type = buffer[base + 4];

            if handle_pid == pid && handle_type == object_type {
                count += 1;
            }
        }

        Ok(count as i32)
    }


    //// Checks if the current process has a specified privilege enabled.
    ///
    /// # Arguments
    /// * `token_identifier` - The name of the privilege to check, as a string slice.
    ///
    /// # Returns
    /// An `i32` value:
    /// - `1` if the process has the specified privilege enabled.
    /// - `-1` if the process does not have the privilege or if an error occurs.
    ///
    /// # Safety
    /// This function contains unsafe code that interacts with the Windows API for Foreign Function Interface (FFI) operations. It calls several Windows API functions that require careful handling to maintain safety guarantees. The caller must ensure that the provided `privilege_type` is valid and that the function is used in a context where the necessary privileges are held by the process.
    pub fn get_enabled_token_count(&self, token_identifier: &str) -> i32
    {

        let fail = -1;
        let mut token_handle: HANDLE = INVALID_HANDLE_VALUE;

        if unsafe { OpenProcessToken(self.process_handle, TOKEN_ACCESS_TYPE, &mut token_handle) } == 0 {
            let error_code = unsafe { GetLastError() };
            debug_log!(format!("Error opening process token: {}", error_code));
            return fail;
        }

        let safe_handle = match CleanHandle::new(token_handle) {
            Some(handle) => handle,
            None => return fail,
        };

        let mut return_length = 0;
        unsafe { GetTokenInformation( safe_handle.as_raw(), TokenPrivileges as u32 as TOKEN_INFORMATION_CLASS, ptr::null_mut(), 0, &mut return_length, ); }

        if return_length == 0 {
            let error_code = unsafe { GetLastError() };
            debug_log!(format!("Error querying token information size: {}", error_code));
            return fail;
        }

        let mut buffer = CleanBuffer::new(return_length as usize);
        let token_privileges = buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES;

        if unsafe { GetTokenInformation(safe_handle.as_raw(), TokenPrivileges as u32 as TOKEN_INFORMATION_CLASS, token_privileges as *mut _, return_length, &mut return_length, ) } == 0 {
            debug_log!(format!("Error checking if tokens are enabled: {}", unsafe { GetLastError() }));
            return fail;
        }

        let privileges = unsafe {
            std::slice::from_raw_parts((*token_privileges).Privileges.as_ptr(), (*token_privileges).PrivilegeCount as usize)
        };

        for privilege in privileges {
            if self.is_matching_privilege(privilege, token_identifier) {
                if privilege.Attributes & SE_PRIVILEGE_ENABLED != 0 {
                    return 1;
                }
            }
        }

        0
    }


    /// Retrieves the amount of data written to disk by the process associated with this handle.
    ///
    /// This method uses Windows API to query I/O statistics for the process, specifically focusing on
    /// the amount of data written. It handles potential errors by returning them, allowing for
    /// explicit error management by the caller.
    ///
    /// # Returns
    /// - `Ok(f64)`: Contains the total amount of data written to disk in megabytes if successful.
    /// - `Err(i32)`: An error code if the operation fails, where the `i32` represents the Windows error code.
    pub fn get_process_write_amount(&self) -> Result<f64, ProcessError>
    {
        let mut io_counters: IO_COUNTERS = unsafe { std::mem::zeroed() };

        let handle = self.process_handle as HANDLE;

        if unsafe { GetProcessIoCounters(handle, &mut io_counters) } == 0
        {
            debug_log!(format!("Error checking IO counters for process: {}", unsafe { GetLastError() }));
            return Err(ProcessError::ProcessInfoQueryFailed);
        }

        let written_gb = io_counters.WriteTransferCount as f64 / (1024.0 * 1024.0);

        Ok(written_gb)
    }
}