//! src/playerone.rs

// This module is used to query information about the host machine and its overall environment.
// The information gathered plays a role in determining wildcard factors for undetermined threats.
// It is essentially used to see if the host machine has a typical setup for a machine that is used to cheat in games,
// such as having anti-virus turned off, secure boot disabled, Hyper-V enabled, etc.





use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use std::thread;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_STATUS, SERVICE_STATUS,
};
use windows_sys::Win32::System::Registry::{
    RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ
};
use windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

use crate::memorymanage::CleanHandle;
use crate::stringutils::to_wide_chars;




pub mod player_one
{

    use super::*;


    /// Defender real-time protection services.
    pub const DEF_SERV: [&str; 2] = ["WdNisDrv", "WdNisSvc"];

    const UAC_REGISTRY_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    const UAC_CONSENT_VALUE: &str = "ConsentPromptBehaviorAdmin";



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

        if service_handle == INVALID_HANDLE_VALUE
        {
            None
        }
        else
        {
            Some(CleanHandle::new(service_handle)?)
        }
    }


    /// Gets the registry value for UAC elevation prompt behavior.
    ///
    /// # Returns
    ///
    /// `true` if UAC is configured to prompt for credentials (values 1 or 3), `false` otherwise.
    /// * Value 1 indicates prompting on secure desktop
    /// * Value 3 indicates prompting without secure desktop
    /// * Value 0 indicates a fail with code execution
    /// * Returns false if registry access fails
    pub fn requires_elevation_prompt() -> u32
    {

        let key_path = to_wide_chars(UAC_REGISTRY_KEY);
        let value_name = to_wide_chars(UAC_CONSENT_VALUE);
        let mut h_key = 0;

        let result = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.as_ptr(), 0, KEY_READ, &mut h_key) };

        if result != 0
        {
            return 0;
        }

        let mut data_type = 0;
        let mut data = 0u32;
        let mut data_size = std::mem::size_of::<u32>() as u32;

        let status = unsafe { RegQueryValueExW(h_key, value_name.as_ptr(), std::ptr::null_mut(), &mut data_type, &mut data as *mut u32 as *mut u8, &mut data_size) };

        if status != 0
        {
            return 0;
        }

        data
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

        if scm_handle == INVALID_HANDLE_VALUE
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

        let result = unsafe { GetFirmwareEnvironmentVariableW(name.as_ptr(), guid.as_ptr(), std::ptr::null_mut(), 0, ) };

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

        unsafe { cpuid_result = std::arch::x86_64::__cpuid_count(1, 0); }

        cpuid_result.ecx & (1 << 31) != 0
    }
}