// src/processfilters.rs

//  Module used to create a filtered list of processes.
//  Currently only filtering by process whom have the same owner SID as this current process.


pub mod process_enum
{

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, PSID};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::Threading::{OpenProcess, GetCurrentProcessId, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, GetCurrentProcess};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER, TOKEN_QUERY, TOKEN_INFORMATION_CLASS, EqualSid, TOKEN_ACCESS_MASK};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    use std::mem::size_of;
    use std::ptr::null_mut;

    use crate::memorymanage::CleanHandle;




    const TOKEN_ACCESS_TYPE: TOKEN_ACCESS_MASK = TOKEN_QUERY;


    /// Struct to hold the list of process IDs owned by the same user as the current process.
    pub struct ProcessEnumerator
    {
        matching_pids: Vec<u32>,
        current_process_sid: Option<*mut u16>,
    }


    impl ProcessEnumerator
    {
        /// Creates a new `ProcessEnumerator`.
        ///
        /// # Returns
        ///
        /// A new instance of `ProcessEnumerator`.
        pub fn new() -> Self
        {
            let current_process_handle = unsafe { GetCurrentProcess() };
            let current_process_sid = Self::get_process_sid(current_process_handle);
            Self {
                matching_pids: Vec::new(),
                current_process_sid,
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
        fn get_process_sid(process_handle: HANDLE) -> Option<*mut u16>
        {

            let mut token_handle: HANDLE = 0;

            if unsafe { OpenProcessToken(process_handle, TOKEN_ACCESS_TYPE, &mut token_handle) } == 0
            {
                return None;
            }

            let mut token_info: Vec<u8> = vec![0; 256];
            let mut return_length: u32 = 0;

            if unsafe {
                GetTokenInformation(
                    token_handle,
                    TokenUser,
                    token_info.as_mut_ptr() as *mut _,
                    token_info.len() as u32,
                    &mut return_length,
                )
            } == 0
            {
                unsafe { CloseHandle(token_handle) };
                return None;
            }

            let token_user: TOKEN_USER = unsafe { std::ptr::read(token_info.as_ptr() as *const TOKEN_USER) };
            let mut sid_string: *mut u16 = null_mut();

            if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) } == 0
            {
                unsafe { CloseHandle(token_handle) };
                return None;
            }

            unsafe { CloseHandle(token_handle) };
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
        fn compare_sids(sid1: PSID, sid2: PSID) -> bool
        {
            unsafe { EqualSid(sid1 as *mut _, sid2 as *mut _) != 0 }
        }


        /// Enumerates processes and fills the list of process IDs owned by the same user as the current process.
        ///
        /// # Arguments
        ///
        /// None.
        ///
        /// # Returns
        ///
        /// Nothing. Fills `matching_pids` with process IDs owned by the same user as the current process.
        pub fn enumerate_processes(&mut self)
        {

            let current_process_sid = match self.current_process_sid {
                Some(sid) => sid,
                None => return,
            };

            let snapshot_handle = CleanHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) });

            if snapshot_handle.is_none()
            {
                return;
            }

            let mut process_entry = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..unsafe { std::mem::zeroed() }
            };

            if unsafe { Process32FirstW(snapshot_handle.as_ref().unwrap().as_raw(), &mut process_entry) } != 0
            {
                loop {

                    let process_handle = CleanHandle::new(unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_entry.th32ProcessID) });

                    if let Some(process_handle) = process_handle
                    {
                        if let Some(process_sid) = Self::get_process_sid(process_handle.as_raw())
                        {
                            if Self::compare_sids(process_sid as PSID, current_process_sid as PSID)
                            {
                                self.matching_pids.push(process_entry.th32ProcessID);
                            }

                            unsafe { LocalFree(process_sid as *mut _) };
                        }
                    }

                    if unsafe { Process32NextW(snapshot_handle.as_ref().unwrap().as_raw(), &mut process_entry) } == 0
                    {
                        break;
                    }
                }
            }
        }


        /// Returns the list of matching process IDs.
        ///
        /// # Returns
        ///
        /// A reference to the vector containing the matching process IDs.
        pub fn get_matching_pids(&self) -> &Vec<u32>
        {
            &self.matching_pids
        }
    }
}