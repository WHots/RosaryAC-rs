use std::collections::HashMap;
use std::ffi::{c_void, OsStr, OsString};
use std::{mem, ptr};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::{GetProcessId, OpenThread, PEB, PROCESS_BASIC_INFORMATION, THREAD_QUERY_INFORMATION};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;

use crate::memorymanage::CleanHandle;
use crate::ntpsapi_h::{NtQueryInformationProcess, NtQueryInformationThread, PROCESS_EXTENDED_BASIC_INFORMATION, ProcessInformationClass, THREAD_BASIC_INFORMATION, THREADINFOCLASS};
use crate::ntpsapi_h::THREADINFOCLASS::ThreadHideFromDebugger;






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



const THREAD_HIDE_FROM_DEBUGGER: THREADINFOCLASS = ThreadHideFromDebugger;


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


    /// Retrieves the handle and size of the main module of the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<(HMODULE, usize), String>` - The handle and size of the main module or an error.
    pub fn get_main_module_ex(&self) -> Result<(*mut c_void, usize), String>
    {
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }


        let mut h_module: HMODULE = unsafe { std::mem::zeroed() };
        let mut cb_needed: u32 = 0;

        if unsafe { EnumProcessModulesEx(self.process_handle, &mut h_module, std::mem::size_of_val(&h_module) as u32, &mut cb_needed, LIST_MODULES_ALL) == 0 }
        {
            unsafe { return Err(format!("Failed to enumerate process modules. Error code: {}", GetLastError())); }
        }

        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        if unsafe { GetModuleInformation(self.process_handle, h_module, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32) == 0 }
        {
            return Err(format!("Failed to get module information. Error code: {}", unsafe { GetLastError() }));
        }

        let base_address: *mut c_void = module_info.lpBaseOfDll as *mut c_void;

        if base_address.is_null()
        {
            return Err("Module base address is null.".to_string());
        }

        Ok((base_address, module_info.SizeOfImage as usize))
    }


    /// Retrieves a list of module handles for a given process.
    ///
    /// # Arguments
    ///
    /// * `h_process` - A handle to the process.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of module handles if successful, or an error string otherwise.
    pub fn get_process_modules(&self) -> Result<Vec<HMODULE>, String>
    {
        let mut modules: Vec<HMODULE> = Vec::with_capacity(1024);

        unsafe {
            modules.set_len(1024);
        }

        let mut cb_needed = 0;

        let success = unsafe {
            EnumProcessModules(
                self.process_handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
            )
        };

        if success == 0 {
            return Err(format!("Failed to enumerate process modules. Error code: {}", unsafe { GetLastError() }));
        }

        let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

        unsafe {
            modules.set_len(module_count);
        }

        Ok(modules)
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
    pub fn get_process_image_path_ex<'a>(&self, buffer: &'a mut Vec<u16>, output: &'a mut OsString) -> Result<&'a OsStr, &'static str>
    {
        const MAX_PATH: usize = 260;
        buffer.resize(MAX_PATH, 0);

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

        *output = OsString::from_wide(&buffer);

        Ok(output.as_os_str())
    }


    // Checks if the process is being debugged by querying the debug port.
    ///
    /// # Returns
    ///
    /// * `Result<bool, String>` - `true` if the process is being debugged, otherwise `false`.
    pub fn is_debugger(&self) -> Result<bool, String>
    {
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }

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
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }


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
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }


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
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }


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
        if self.process_handle == 0
        {
            return Err(format!("No process. Error code: {}", unsafe { GetLastError() }));
        }


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
    pub fn get_violent_threads(&self) -> HashMap<String, usize>
    {

        let mut counts = HashMap::new();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid) };
        let snapshot = match CleanHandle::new(snapshot) {
            Some(handle) => handle,
            None => return counts,
        };

        let mut thread_entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut owned_count = 0;
        let mut not_owned = 0;
        let mut hidden_thread_count = 0;


        unsafe {

            if Thread32First(snapshot.as_raw(), &mut thread_entry) != 0
            {
                loop {

                    if thread_entry.th32OwnerProcessID == self.pid
                    {
                        let h_thread = OpenThread(THREAD_QUERY_INFORMATION, 0, thread_entry.th32ThreadID);

                        if let Some(thread_handle) = CleanHandle::new(h_thread)
                        {
                            if Self::is_thread_hidden_from_debugger(thread_handle.as_raw())
                            {
                                hidden_thread_count += 1;
                            }

                            if let Some(client_id) = Self::get_thread_client_id(thread_handle.as_raw())
                            {
                                if client_id.UniqueProcess != INVALID_HANDLE_VALUE
                                {
                                    let thread_owner_id = GetProcessId(client_id.UniqueProcess);

                                    if thread_owner_id != 0
                                    {
                                        if thread_owner_id == thread_entry.th32OwnerProcessID
                                        {
                                            owned_count += 1;
                                        }
                                        else
                                        {
                                            not_owned += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if Thread32Next(snapshot.as_raw(), &mut thread_entry) == 0 {
                        break;
                    }
                }
            }
        }

        counts.insert("Owned".to_string(), owned_count);
        counts.insert("NOT Owned".to_string(), not_owned);
        counts.insert("Hidden Flag".to_string(), hidden_thread_count);

        counts
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