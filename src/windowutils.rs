//! src/windowutils.rs

// This module contains utility functions for window operations and management.





use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, BOOL, GetLastError};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindow, GetWindowTextW, GetWindowThreadProcessId,
    IsWindowVisible, GW_OWNER,
};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
    GetDC, GetWindowDC, ReleaseDC, SelectObject, SRCCOPY,
};

use crate::debug_log;



/// Structure to hold window visibility statistics
#[derive(Debug)]
pub struct WindowStats
{
    pub visible_count: u32,
    pub invisible_count: u32,
}



/// Various errors that can occur during window operations.
#[derive(Debug)]
pub enum WindowError
{
    /// Failed to enumerate windows using EnumWindows API.
    EnumWindowsFailed,
    /// Failed to get device context for window.
    DeviceContextFailed,
    /// Failed to create compatible device context.
    CompatDeviceContextFailed,
    /// Failed to create bitmap for window capture.
    BitmapFailed,
    /// Failed to capture window contents.
    CaptureFailed,
    /// No visible window was found for the process.
    NoVisibleWindow,
    /// Other errors.
    Other(i32),
}

impl Display for WindowError
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
    {
        let msg = match self {
            WindowError::EnumWindowsFailed => "Failed to enumerate windows",
            WindowError::DeviceContextFailed => "Failed to get window device context",
            WindowError::CompatDeviceContextFailed => "Failed to create compatible device context",
            WindowError::BitmapFailed => "Failed to create window bitmap",
            WindowError::CaptureFailed => "Failed to capture window contents",
            WindowError::NoVisibleWindow => "No visible window found for process",
            WindowError::Other(code) => return write!(f, "Unknown error: {}", code),
        };
        write!(f, "{}", msg)
    }
}


/// Gets the title of the main window for a process.
///
/// # Arguments
/// * `pid` - Process ID to find the window for
///
/// # Returns
/// * `Result<Option<String>, WindowError>` - Window title if found
pub fn get_window_title(pid: u32) -> Result<Option<String>, WindowError>
{
    struct EnumWindowsState
    {
        pid: u32,
        window_title: Option<String>,
    }

    unsafe extern "system" fn enum_windows_callback(hwnd: HWND, state: isize) -> i32
    {

        let state = &mut *(state as *mut EnumWindowsState);
        let mut window_pid: u32 = 0;

        GetWindowThreadProcessId(hwnd, &mut window_pid);

        if window_pid == state.pid
        {
            let mut title = vec![0u16; 512];
            let length = GetWindowTextW(hwnd, title.as_mut_ptr(), 512) as usize;

            if length > 0
            {
                title.truncate(length);
                state.window_title = Some(String::from_utf16_lossy(&title));
                return 0;
            }
        }

        1
    }

    let mut state = EnumWindowsState {
        pid,
        window_title: None,
    };

    let result = unsafe {
        EnumWindows(Some(enum_windows_callback), &mut state as *mut EnumWindowsState as isize)
    };

    if result == 0 && state.window_title.is_none()
    {
        let e = WindowError::EnumWindowsFailed;
        debug_log!(e);
        return Err(e)
    }

    Ok(state.window_title)
}


/// Gets statistics about visible and invisible windows for a process.
///
/// # Arguments
/// * `pid` - Process ID to get window stats for
///
/// # Returns
/// * `Result<WindowStats, WindowError>` - Window statistics
pub fn get_window_stats(pid: u32) -> Result<WindowStats, WindowError>
{

    static VISIBLE_COUNT: AtomicU32 = AtomicU32::new(0);
    static INVISIBLE_COUNT: AtomicU32 = AtomicU32::new(0);
    static TARGET_PID: AtomicU32 = AtomicU32::new(0);

    VISIBLE_COUNT.store(0, Ordering::SeqCst);
    INVISIBLE_COUNT.store(0, Ordering::SeqCst);
    TARGET_PID.store(pid, Ordering::SeqCst);

    unsafe extern "system" fn enum_window_callback(window: HWND, _: LPARAM) -> BOOL
    {
        let mut process_id: u32 = 0;
        GetWindowThreadProcessId(window, &mut process_id);

        if process_id == TARGET_PID.load(Ordering::SeqCst)
        {
            let owner = GetWindow(window, GW_OWNER);

            if owner == 0
            {
                if IsWindowVisible(window) != 0
                {
                    VISIBLE_COUNT.fetch_add(1, Ordering::SeqCst);
                }
                else
                {
                    INVISIBLE_COUNT.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        1
    }

    let result = unsafe { EnumWindows(Some(enum_window_callback), 0) };

    if result == 0
    {
        let e = WindowError::EnumWindowsFailed;
        debug_log!(e);
        return Err(e)
    }

    Ok(WindowStats {
        visible_count: VISIBLE_COUNT.load(Ordering::SeqCst),
        invisible_count: INVISIBLE_COUNT.load(Ordering::SeqCst),
    })
}


/// Finds the main window handle for a process.
///
/// # Arguments
/// * `pid` - Process ID to find the window for
///
/// # Returns
/// * `Option<HWND>` - Window handle if found
pub fn find_main_window(pid: u32) -> Option<HWND>
{

    struct WindowInfo
    {
        window: HWND,
        pid: u32,
    }

    unsafe extern "system" fn enum_window_proc(window: HWND, lparam: LPARAM) -> BOOL
    {

        let target_info = &mut *(lparam as *mut WindowInfo);
        let mut process_id: u32 = 0;

        GetWindowThreadProcessId(window, &mut process_id);

        if process_id == target_info.pid && target_info.window == 0
        {
            target_info.window = window;
            return 0;
        }

        1
    }

    let mut info = WindowInfo {
        window: 0,
        pid,
    };

    unsafe { EnumWindows(Some(enum_window_proc), &mut info as *mut _ as LPARAM); }

    if info.window != 0
    {
        Some(info.window)
    }
    else
    {
        None
    }
}