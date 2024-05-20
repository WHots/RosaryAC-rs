use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;










#[repr(C)]
pub struct THREAD_BASIC_INFORMATION
{
    ExitStatus: NTSTATUS,
    TebBaseAddress: *mut c_void,
    pub client_id: CLIENT_ID,
    AffinityMask: usize,
    Priority: i32,
    BasePriority: i32,
}


#[repr(C)]
pub struct PROCESS_EXTENDED_BASIC_INFORMATION
{
    /// The size of the structure, in bytes.
    pub Size: usize,
    /// Basic information about the process.
    BasicInfo: PROCESS_BASIC_INFORMATION,
    /// Flags that indicate additional information about the process.
    pub Flags: u32,
}


#[repr(u32)]
pub enum ProcessInformationClass
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
}


#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum THREADINFOCLASS
{
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    ThreadSwitchLegacyState = 19,
    ThreadIsTerminated = 20,
    ThreadLastSystemCall = 21,
    ThreadIoPriority = 22,
    ThreadCycleTime = 23,
    ThreadPagePriority = 24,
    ThreadActualBasePriority = 25,
    ThreadTebInformation = 26,
    ThreadCSwitchMon = 27,
    ThreadCSwitchPmu = 28,
    ThreadWow64Context = 29,
    ThreadGroupInformation = 30,
    ThreadUmsInformation = 31,
    ThreadCounterProfiling = 32,
    ThreadIdealProcessorEx = 33,
    ThreadCpuAccountingInformation = 34,
    ThreadSuspendCount = 35,
    ThreadHeterogeneousCpuPolicy = 36,
    ThreadContainerId = 37,
    ThreadNameInformation = 38,
    ThreadSelectedCpuSets = 39,
    ThreadSystemThreadInformation = 40,
    ThreadActualGroupAffinity = 41,
    ThreadDynamicCodePolicyInfo = 42,
    ThreadExplicitCaseSensitivity = 43,
    ThreadWorkOnBehalfTicket = 44,
    ThreadSubsystemInformation = 45,
    ThreadDbgkWerReportActive = 46,
    ThreadAttachContainer = 47,
    ThreadManageWritesToExecutableMemory = 48,
    ThreadPowerThrottlingState = 49,
    ThreadWorkloadClass = 50,
    ThreadCreateStateChange = 51,
    ThreadApplyStateChange = 52,
    ThreadStrongerBadHandleChecks = 53,
    ThreadEffectiveIoPriority = 54,
    ThreadEffectivePagePriority = 55,
    MaxThreadInfoClass = 56,
}



#[link(name = "ntdll")]
extern "system"
{
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}


#[link(name = "ntdll")]
extern "system"
{
    pub fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: THREADINFOCLASS,
        ThreadInformation: *mut c_void,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}