use std::collections::HashMap;
use std::ffi::{c_void, OsStr, OsString};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::{OpenThread, PEB, PROCESS_BASIC_INFORMATION, THREAD_QUERY_INFORMATION};

use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use crate::ntpsapi_h::{NtQueryInformationProcess, NtQueryInformationThread, THREADINFOCLASS};
use crate::ntpsapi_h::THREADINFOCLASS::ThreadHideFromDebugger;


#[repr(C)]
struct PROCESS_EXTENDED_BASIC_INFORMATION
{
    /// The size of the structure, in bytes.
    Size: usize,
    /// Basic information about the process.
    BasicInfo: PROCESS_BASIC_INFORMATION,
    /// Flags that indicate additional information about the process.
    Flags: u32,
}

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


struct HandleGuard(HANDLE);
impl Drop for HandleGuard
{
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}


#[repr(u32)]
enum ProcessInformationClass
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
}




pub struct ProcessInfo
{
    pid: u32,
    process_handle: HANDLE,
}


const THREAD_HIDE_FROM_DEBUGGER: THREADINFOCLASS = ThreadHideFromDebugger;

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
    /// # Errors
    ///
    /// If the snapshot handle is equal to `0`, no counts are performed, and an empty `HashMap` is returned.
    pub fn enumerate_threads(&self) -> HashMap<String, usize>
    {

        let mut counts = HashMap::new();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid) };

        if snapshot != 0
        {
            let mut thread_entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut owned_count = 0;
            let mut other_count = 0;

            unsafe {
                if Thread32First(snapshot, &mut thread_entry) != 0
                {
                    loop {

                        if thread_entry.th32OwnerProcessID == self.pid
                        {
                            owned_count += 1;
                        } else
                        {
                            other_count += 1;
                        }

                        if Thread32Next(snapshot, &mut thread_entry) == 0
                        {
                            break;
                        }
                    }
                }
                CloseHandle(snapshot);
            }

            counts.insert("Owned threads".to_string(), owned_count);

            if other_count > 0
            {
                counts.insert("Anomaly threads".to_string(), other_count);
            }

            let hidden_thread_count = Self::get_hidden_thread_count(self.pid);

            if hidden_thread_count > 0
            {
                counts.insert("Hidden threads".to_string(), hidden_thread_count as usize);
            }
        }

        counts
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


    /// This function creates a snapshot of all threads in the process and counts how many have the "hide from debugger" flag set.
    ///
    /// # Arguments
    /// * `pid` - The process ID of the target process.
    ///
    /// # Returns
    /// * The count of threads with the "hide from debugger" flag set.
    ///
    /// # Safety
    /// This function uses unsafe blocks to call Windows API functions and perform FFI operations.
    #[inline]
    fn get_hidden_thread_count(pid: u32) -> i32
    {

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) };

        if snapshot == 0
        {
            return 0;
        }

        let mut te32: THREADENTRY32 = unsafe { std::mem::zeroed() };
        let mut hidden_thread_count = 0;

        unsafe {
            if Thread32First(snapshot, &mut te32) != 0
            {
                loop {

                    if te32.th32OwnerProcessID == pid
                    {
                        let h_thread = OpenThread(THREAD_QUERY_INFORMATION, 0, te32.th32ThreadID);

                        if h_thread != 0
                        {
                            if Self::is_thread_hidden_from_debugger(h_thread)
                            {
                                hidden_thread_count += 1;
                            }
                            CloseHandle(h_thread);
                        }
                    }
                    if Thread32Next(snapshot, &mut te32) == 0
                    {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }

        hidden_thread_count
    }
}