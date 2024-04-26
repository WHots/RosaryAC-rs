use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};




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



    /// Retrieves the base address of the main module of the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process handle is invalid or if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<*const c_void, String>` - The base address of the main module or an error.
    pub fn get_module_base_address_ex(&self) -> Result<*const c_void, String>
    {

        if self.process_handle == 0
        {
            return Err("Process handle is null.".into());
        }

        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        let result = unsafe { GetModuleInformation(self.process_handle, 0, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32,) };

        if result == 0
        {
            return Err(format!("Failed to enumerate process modules. Error code: {}", unsafe { GetLastError() },));
        }

        Ok(module_info.lpBaseOfDll as *const c_void)
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
    pub unsafe fn get_main_module_ex(&self) -> Result<(HMODULE, usize), String>
    {

        let mut h_module: HMODULE = std::mem::zeroed();
        let mut cb_needed: u32 = 0;

        if EnumProcessModulesEx(self.process_handle, &mut h_module, std::mem::size_of_val(&h_module) as u32, &mut cb_needed, LIST_MODULES_ALL) == 0
        {
            return Err(format!("Failed to enumerate process modules. Error code: {}", GetLastError()));
        }


        let mut module_info: MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(self.process_handle, h_module, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32) == 0 {
            return Err(format!("Failed to get module information. Error code: {}", GetLastError()));
        }

        match self.get_module_size() {
            Ok(size) => Ok((h_module, size)),
            Err(e) => Err(e),
        }
    }


    /// Retrieves the file path of the main module of the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<OsString, &'static str>` - The file path of the main module or an error.
    pub fn get_process_image_path_ex(&self) -> Result<OsString, &'static str>
    {

        const MAX_PATH: usize = 260;
        let mut buffer = vec![0u16; MAX_PATH];

        let result = unsafe { GetModuleFileNameExW(self.process_handle, 0, buffer.as_mut_ptr(), buffer.len() as u32,) };

        if result == 0
        {
            return Err("Failed to get qualified image name.");
        }

        let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
        buffer.truncate(len);

        Ok(OsString::from_wide(&buffer))
    }


    /// Helper method to retrieve the size of a module given its handle.
    ///
    /// # Arguments
    ///
    /// ...
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Returns
    ///
    /// * `Result<usize, String>` - The size of the module or an error.
    #[inline]
    fn get_module_size(&self) -> Result<usize, String>
    {

        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        let result = unsafe { GetModuleInformation(self.process_handle, 0, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32,) };

        if result == 0
        {
            return Err(format!("Failed to get module information. Error code: {}", unsafe { GetLastError() },));
        }

        Ok(module_info.SizeOfImage as usize)
    }
}