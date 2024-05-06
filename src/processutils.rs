use std::ffi::{c_void, OsStr, OsString};
//  use std::borrow::Borrow;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, HMODULE, NTSTATUS};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::{PEB, PROCESS_BASIC_INFORMATION};





#[repr(C)]
pub struct PROCESS_EXTENDED_BASIC_INFORMATION
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


#[repr(u32)]
pub enum ProcessInformationClass
{
    ProcessBasicInformation = 0,
}


#[link(name = "ntdll")]
extern "system"
{
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
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
    pub fn is_process64(&self) -> Result<bool, String>
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
}