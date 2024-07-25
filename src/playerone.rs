//! src/playerone.rs

// This module is used to query information about the host machine and its overall environment.
// The information gathered plays a role in determining wildcard factors for undetermined threats.
// It is essentially used to see if the host machine has a typical setup for a machine that is used to cheat in games,
// such as having anti-virus turned off, secure boot disabled, Hyper-V enabled, etc.





use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::{
    Foundation::{GetLastError, BOOL, HANDLE},
    System::{
        Services::{
            OpenSCManagerW, QueryServiceStatus, SC_MANAGER_ENUMERATE_SERVICE,
            SERVICE_QUERY_STATUS, OpenServiceW, SERVICE_STATUS,
        },
        WindowsProgramming::GetFirmwareEnvironmentVariableW,
    },
};

use crate::memorymanage::CleanHandle;
use crate::stringutils::to_wide_chars;




/// A module for managing Windows services.
pub mod player_one
{

    use std::ptr::null;
    use super::*;

    /// Defender real-time protection services.
    pub const DEF_SERV: [&str; 2] = ["WdNisDrv", "WdNisSvc"];



    /// Opens a service with the specified access rights.
    ///
    /// # Arguments
    ///
    /// * `scm_handle` - The handle to the service control manager.
    /// * `service_name` - The name of the service.
    /// * `access` - The desired access rights.
    ///
    /// # Returns
    ///
    /// `Some(CleanHandle)` if the service was opened successfully, `None` otherwise.
    #[inline]
    fn open_service(scm_handle: HANDLE, service_name: &OsStr, access: u32, ) -> Option<CleanHandle>
    {

        let service_handle = unsafe {
            OpenServiceW(
                scm_handle,
                service_name.encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr(),
                access,
            )
        };

        if service_handle == 0
        {
            None
        }
        else
        {
            Some(CleanHandle::new(service_handle)?)
        }
    }


    /// Checks the status of a specified service.
    ///
    /// # Arguments
    ///
    /// * `service_name` - The name of the service to check.
    ///
    /// # Returns
    ///
    /// `true` if the service is running, `false` otherwise.
    pub fn is_service_running(service_name: &str) -> bool
    {

        let scm_handle = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };

        if scm_handle == 0
        {
            return false;
        }

        let scm_handle = CleanHandle::new(scm_handle);

        if let Some(scm_handle) = scm_handle
        {
            let service_handle = open_service(scm_handle.as_raw(), OsStr::new(service_name), SERVICE_QUERY_STATUS, );

            if let Some(service_handle) = service_handle
            {

                let mut service_status = SERVICE_STATUS {
                    dwServiceType: 0,
                    dwCurrentState: 0,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: 0,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };

                let success = unsafe
                    {
                    QueryServiceStatus(service_handle.as_raw(), &mut service_status)
                };

                success == 1 && service_status.dwCurrentState == 4
            }
            else
            {
                false
            }
        }
        else
        {
            false
        }
    }


    /// Checks if Secure Boot is enabled on the system.
    ///
    /// # Returns
    ///
    /// `true` if Secure Boot is enabled, `false` otherwise or if an error occurs.
    pub fn is_secure_boot() -> bool
    {
        let name = to_wide_chars("SecureBoot");
        let guid = to_wide_chars("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}");

        let result = unsafe {
            GetFirmwareEnvironmentVariableW(
                name.as_ptr(),
                guid.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        result > 0
    }


    /// Checks if the system is running Hyper-V.
    ///
    /// # Returns
    ///
    /// `true` if Hyper-V is present, `false` otherwise.
    pub fn is_hyperv() -> bool
    {
        let cpuid_result: std::arch::x86_64::CpuidResult;

        unsafe {
            cpuid_result = std::arch::x86_64::__cpuid_count(1, 0);
        }

        cpuid_result.ecx & (1 << 31) != 0
    }
}