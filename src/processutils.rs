//! src/processutils.rs

// This module contains process utility function based around process interactions.





use std::collections::{HashMap};
use std::ffi::{c_void, OsStr, OsString};
use std::path::Path;
use std::{mem, ptr};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{BOOL, BOOLEAN, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, LUID, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetProcessIdOfThread, OpenProcessToken, OpenThread, PEB, PROCESS_BASIC_INFORMATION, THREAD_ACCESS_RIGHTS, THREAD_QUERY_INFORMATION};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;

use windows_sys::Win32::Security::{GetTokenInformation, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::SystemServices::PRIVILEGE_SET_ALL_NECESSARY;

use crate::memorymanage::CleanHandle;
use crate::ntexapi_h::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, SystemInformationClass};
use crate::ntexapi_h::SystemInformationClass::SystemHandleInformation;
use crate::ntpsapi_h::{NtPrivilegeCheck, NtQueryInformationProcess, NtQueryInformationThread, NtQuerySystemInformation, PROCESS_EXTENDED_BASIC_INFORMATION, ProcessInformationClass, THREAD_BASIC_INFORMATION, THREADINFOCLASS};


macro_rules! check_process_handle {
    ($handle:expr) => {
        if $handle == 0 {
            println!("No process. Error code: {}", unsafe { GetLastError() });
        }
    };
}


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
    pid: u32,
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
        
        check_process_handle!(self.process_handle);

        const MAX_MODULES: usize = 1024;
        let mut h_modules: Vec<HMODULE> = vec![0; MAX_MODULES];
        let mut cb_needed: u32 = 0;

        if unsafe { EnumProcessModulesEx(self.process_handle, h_modules.as_mut_ptr(), (MAX_MODULES * std::mem::size_of::<HMODULE>()) as u32, &mut cb_needed, LIST_MODULES_ALL,) } == 0 
        {
            return false;
        }

        let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();
        let mut buffer = vec![0u16; 260];

        //  Idiomatic because im an idiot.
        (0..module_count).any(|i| 
        {
            let result = unsafe { GetModuleFileNameExW( self.process_handle, h_modules[i], buffer.as_mut_ptr(), buffer.len() as u32,) };

            if result == 0 
            {
                return false;
            }

            let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
            let module_path = OsString::from_wide(&buffer[..len]);
            let module_name_in_path = Path::new(&module_path).file_name().unwrap_or(OsStr::new(""));

            module_name_in_path == module_name
        })
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
    pub fn get_main_module_ex(&self) -> Result<(*const u8, usize), String> 
    {

        check_process_handle!(self.process_handle);

        let mut h_module: HMODULE = unsafe { std::mem::zeroed() };
        let mut cb_needed: u32 = 0;

        if unsafe { EnumProcessModulesEx(self.process_handle, &mut h_module, std::mem::size_of_val(&h_module) as u32, &mut cb_needed, LIST_MODULES_ALL) == 0 } {
            return Err(format!("Failed to enumerate process modules. Error code: {}", unsafe { GetLastError() }));
        }

        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        if unsafe { GetModuleInformation(self.process_handle, h_module, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32) == 0 } {
            return Err(format!("Failed to get module information. Error code: {}", unsafe { GetLastError() }));
        }

        let base_address: *const u8 = module_info.lpBaseOfDll as *const u8;

        if base_address.is_null() {
            return Err("Module base address is null.".to_string());
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
    pub fn get_process_image_path_ex(&self) -> Result<OsString, &'static str> 
    {

        check_process_handle!(self.process_handle);
    
        const MAX_PATH: usize = 260;
        let mut buffer = vec![0u16; MAX_PATH];
    
        let result = unsafe {
            GetModuleFileNameExW(
                self.process_handle,
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
    
        if result == 0 
        {
            return Err("Failed to get qualified image name.");
        }
    
        let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
        buffer.truncate(len);
    
        let output = OsString::from_wide(&buffer);
        Ok(output)
    }
    


    // Checks if the process is being debugged by querying the debug port.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is being debugged, otherwise `false`.
    pub fn is_debugger(&self) -> Result<bool, String>
    {

        check_process_handle!(self.process_handle);

        let mut debug_port: isize = 0;
        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle,
                ProcessInformationClass::ProcessDebugPort as u32,
                &mut debug_port as *mut _ as *mut c_void,
                size_of::<isize>() as u32,
                &mut return_length,
            )
        };

        if status != 0
        {
            return Err(format!("Failed to query debug port. NTSTATUS: {}", status));
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
    pub fn get_peb_base_address(&self) -> Result<*mut PEB, String>
    {

        check_process_handle!(self.process_handle);

        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle,
                ProcessInformationClass::ProcessBasicInformation as u32,
                &mut pbi as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            )
        };

        if status != 0
        {
            return Err(format!("Failed to query process information. NTSTATUS: {}", status));
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
    pub fn is_wow64(&self) -> Result<bool, String>
    {

        check_process_handle!(self.process_handle);

        let mut pebi: PROCESS_EXTENDED_BASIC_INFORMATION = PROCESS_EXTENDED_BASIC_INFORMATION::new();
        pebi.Size = size_of::<PROCESS_EXTENDED_BASIC_INFORMATION>();

        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle,
                ProcessInformationClass::ProcessBasicInformation as u32,
                &mut pebi as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            )
        };

        if status != 0
        {
            return Err(format!("Failed to query process information. NTSTATUS: {}", status));
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
    pub fn is_protected_process(&self) -> Result<bool, String>
    {

        check_process_handle!(self.process_handle);

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
            return Err(format!("Failed to query process information. NTSTATUS: {}", status));
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
    pub fn is_secure_process(&self) -> Result<bool, String>
    {

        check_process_handle!(self.process_handle);

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
            return Err(format!("Failed to query process information. NTSTATUS: {}", status));
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
    pub fn is_process_elevated(&self) -> Result<bool, String>
    {

        check_process_handle!(self.process_handle);

        let mut token_handle: HANDLE = 0;

        let token_opened: BOOL = unsafe {
            OpenProcessToken(
                self.process_handle,
                TOKEN_ACCESS_TYPE,
                &mut token_handle,
            )
        };

        if token_opened == 0 {
            return Err(format!("No Process Token Opened: {}", unsafe { GetLastError() }));
        }

        let safe_handle = match CleanHandle::new(token_handle) {
            Some(handle) => handle,
            None => return Ok(false)
        };

        let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: u32 = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let token_info: BOOL = unsafe {
            GetTokenInformation(
                safe_handle.as_raw(),
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            )
        };

        if token_info == 0
        {
            return Err(format!("Token Information Was Zero: {}", unsafe { GetLastError() }));
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

        unsafe {

            let mut buffer_size = 0;
            let mut buffer: Vec<u8>;
            let mut status: NTSTATUS;

            status = NtQuerySystemInformation(SystemInformationClass::SystemHandleInformation, std::ptr::null_mut(), 0, &mut buffer_size);

            if status != STATUS_INFO_LENGTH_MISMATCH {
                return Err(status);
            }

            loop {
                buffer = vec![0; buffer_size as usize];
                status = NtQuerySystemInformation(SystemInformationClass::SystemHandleInformation, buffer.as_mut_ptr() as *mut _, buffer.len() as u32, &mut buffer_size);

                if status != STATUS_INFO_LENGTH_MISMATCH {
                    break;
                }
            }

            let handle_count = usize::from_ne_bytes(buffer[0..8].try_into().unwrap());

            let handles_offset = 8;
            let handle_size = 24;
            let mut count = 0;

            for i in 0..handle_count
            {
                let base = handles_offset + i * handle_size;
                let handle_pid = u16::from_ne_bytes(buffer[base..base+2].try_into().unwrap()) as u32;
                let handle_type = buffer[base + 4];

                if handle_pid == pid && handle_type == object_type
                {
                    count += 1;
                }
            }

            Ok(count)
        }
    }




    //// Checks if the current process has a specified privilege enabled.
    ///
    /// # Arguments
    /// * `privilege_type` - The name of the privilege to check, as a string slice.
    ///
    /// # Returns
    /// An `i32` value:
    /// - `1` if the process has the specified privilege enabled.
    /// - `-1` if the process does not have the privilege or if an error occurs.
    ///
    /// # Safety
    /// This function contains unsafe code that interacts with the Windows API for Foreign Function Interface (FFI) operations. It calls several Windows API functions that require careful handling to maintain safety guarantees. The caller must ensure that the provided `privilege_type` is valid and that the function is used in a context where the necessary privileges are held by the process.
    pub(crate) fn is_token_present(&self, privilege_type: &str) -> i32
    {

        check_process_handle!(self.process_handle);

        let fail = -1;
        let mut status: NTSTATUS = 0;

        let privilege_type_wide: Vec<u16> = privilege_type.encode_utf16().chain(Some(0)).collect();

        let mut luid = LUID { LowPart: 0, HighPart: 0 };

        if unsafe { LookupPrivilegeValueW(ptr::null(), privilege_type_wide.as_ptr(), &mut luid) } == 0 {
            return fail;
        }

        let mut required_privileges = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: PRIVILEGE_SET_ALL_NECESSARY,
            Privilege: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }; 1],
        };

        let mut token_handle: HANDLE = INVALID_HANDLE_VALUE;

        let res = unsafe { OpenProcessToken(self.process_handle, TOKEN_ACCESS_TYPE, &mut token_handle) };

        if res == 0 {
            return fail;
        }

        let safe_handle = match CleanHandle::new(token_handle) {
            Some(handle) => handle,
            None => return fail,
        };

        let mut has_privilege: BOOLEAN = 0;

        status = unsafe { NtPrivilegeCheck(safe_handle.as_raw(), &mut required_privileges, &mut has_privilege) };

        if status == STATUS_SUCCESS && has_privilege != 0
        {
            1
        }
        else
        {
            fail
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

        let mut thread_info: THREAD_BASIC_INFORMATION = unsafe {mem::zeroed()};

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
        }
        else
        {
            None
        }
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
}