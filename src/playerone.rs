// src/service_manager.rs

// This module is used to query information about the host machine and its overall environment.
// The information gathered plays a role in determining wildcard factors for undetermined threats.
// It is essentially used to see if the host machine has a typical setup for a machine that is used to cheat in games,
// such as having anti-virus turned off, secure boot disabled, Hyper-V enabled, etc.







use windows_sys::Win32::Foundation::{BOOL, HANDLE, GetLastError};
use windows_sys::Win32::System::Services::{ OpenSCManagerW, QueryServiceStatus, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, OpenServiceW, SERVICE_STATUS, };
use windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

use crate::memorymanage::CleanHandle;
use crate::stringutils::to_wide_chars;


/// A module for managing Windows services.
pub mod player_one
{
    use super::*;

    /// A macro to open a service with the specified access rights.
    ///
    /// # Arguments
    ///
    /// * `$scm_handle` - The handle to the service control manager.
    /// * `$service_name` - The name of the service.
    /// * `$access` - The desired access rights.
    macro_rules! open_service {
        ($scm_handle:expr, $service_name:expr, $access:expr) => {{
            let service_handle: HANDLE = unsafe {
                OpenServiceW(
                    $scm_handle,
                    $service_name.encode_utf16().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
                    $access,
                )
            };
            CleanHandle::new(service_handle)
        }};
    }



    /// Defender real-time protection services.
    const DEF_SERV: [&str; 2] = [
        "WdNisDrv", //  Driver component of real-time protection.
        "WdNisSvc"  //  Generic service for real-time protection.
    ];




    /// Checks the status of a specified service.
    ///
    /// # Arguments
    ///
    /// * `service_name` - The name of the service to check.
    ///
    /// # Returns
    ///
    /// `true` if the service is running, `false` otherwise.
    pub fn check_service_status(service_name: &str) -> bool
    {
        let scm_handle = match CleanHandle::new(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE) }) {
            Some(handle) => handle,
            None => return false,
        };

        let service_handle = match open_service!(scm_handle.as_raw(), service_name, SERVICE_QUERY_STATUS) {
            Some(handle) => handle,
            None => return false,
        };

        let mut service_status = SERVICE_STATUS {
            dwServiceType: 0,
            dwCurrentState: 0,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };

        let success: BOOL = unsafe { QueryServiceStatus(service_handle.as_raw(), &mut service_status) };

        success == 1 && service_status.dwCurrentState == 4
    }


    /// Checks if Secure Boot is enabled on the system.
    ///
    /// # Returns
    ///
    /// `true` if Secure Boot is enabled, `false` otherwise or if an error occurs.
    pub fn is_secure_boot() -> bool
    {
        let mut buffer: [u16; 1] = [0; 1];
        let name = to_wide_chars("SecureBoot");
        let guid = to_wide_chars("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}");

        let result = unsafe { GetFirmwareEnvironmentVariableW(name.as_ptr(), guid.as_ptr(), buffer.as_mut_ptr() as *mut _, buffer.len() as u32, ) };

        if result > 0
        {
            true
        }
        else
        {
            false
        }
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