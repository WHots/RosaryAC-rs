//! src/screenshot.rs

// This module contains functionality for capturing screenshots of process windows.





use std::mem;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT, FALSE, BOOL, TRUE};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
    GetDC, GetWindowDC, ReleaseDC, SelectObject, SRCCOPY,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClientRect, GetWindowRect, GetWindowThreadProcessId, IsWindowVisible,
    EnumWindows, IsIconic,
};

use crate::{debug_log, windowutils};

#[derive(Debug)]
pub enum ScreenshotError {
    NoDC,
    NoCompatDC,
    NoBitmap,
    CaptureFailure,
    NoVisibleWindow,
    WindowMinimized,
}

struct WindowInfo {
    window: HWND,
    pid: u32,
}



#[repr(C)]
struct BITMAPINFOHEADER
{
    biSize: u32,
    biWidth: i32,
    biHeight: i32,
    biPlanes: u16,
    biBitCount: u16,
    biCompression: u32,
    biSizeImage: u32,
    biXPelsPerMeter: i32,
    biYPelsPerMeter: i32,
    biClrUsed: u32,
    biClrImportant: u32,
}

#[repr(C)]
struct RGBQUAD
{
    rgbBlue: u8,
    rgbGreen: u8,
    rgbRed: u8,
    rgbReserved: u8,
}

#[repr(C)]
struct BITMAPINFO
{
    bmiHeader: BITMAPINFOHEADER,
    bmiColors: [RGBQUAD; 1],
}

extern "system" {
    fn GetDIBits(
        hdc: isize,
        hbm: isize,
        start: u32,
        cLines: u32,
        lpvBits: *mut core::ffi::c_void,
        lpbmi: *mut core::ffi::c_void,
        usage: u32,
    ) -> i32;
}

unsafe extern "system" fn enum_window_proc(window: HWND, lparam: LPARAM) -> BOOL
{
    let target_info = &mut *(lparam as *mut WindowInfo);
    let mut process_id: u32 = 0;
    GetWindowThreadProcessId(window, &mut process_id);

    if process_id == target_info.pid && target_info.window == 0 {
        target_info.window = window;
        return FALSE;
    }
    TRUE
}



/// Takes a screenshot of the main window for a given process ID.
///
/// # Arguments
/// * `pid` - The process ID whose window to capture
///
/// # Returns
/// * `Result<Vec<u8>, ScreenshotError>` - The bitmap data if successful
pub fn capture_window(pid: u32) -> Result<Vec<u8>, ScreenshotError>
{

    let hwnd = windowutils::find_main_window(pid).ok_or(ScreenshotError::NoVisibleWindow)?;

    unsafe {

        if IsWindowVisible(hwnd) == 0
        {
            return Err(ScreenshotError::NoVisibleWindow);
        }

        if IsIconic(hwnd) != 0
        {
            return Err(ScreenshotError::WindowMinimized);
        }

        let mut rect: RECT = mem::zeroed();
        GetWindowRect(hwnd, &mut rect);
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;

        let window_dc = GetWindowDC(hwnd);

        if window_dc == 0
        {
            debug_log!("Failed to get window DC");
            return Err(ScreenshotError::NoDC);
        }

        let compat_dc = CreateCompatibleDC(window_dc);

        if compat_dc == 0
        {
            ReleaseDC(hwnd, window_dc);
            debug_log!("Failed to create compatible DC");
            return Err(ScreenshotError::NoCompatDC);
        }

        let bitmap = CreateCompatibleBitmap(window_dc, width, height);

        if bitmap == 0
        {
            DeleteDC(compat_dc);
            ReleaseDC(hwnd, window_dc);
            debug_log!("Failed to create bitmap");
            return Err(ScreenshotError::NoBitmap);
        }

        let old_bitmap = SelectObject(compat_dc, bitmap as _);

        let success = BitBlt(compat_dc, 0, 0, width, height, window_dc, 0, 0, SRCCOPY);

        if success == 0
        {
            SelectObject(compat_dc, old_bitmap);
            DeleteObject(bitmap as _);
            DeleteDC(compat_dc);
            ReleaseDC(hwnd, window_dc);
            debug_log!("Failed to capture window contents");
            return Err(ScreenshotError::CaptureFailure);
        }

        let bytes_per_pixel = 4;
        let stride = ((width * bytes_per_pixel + 3) & !3) as usize;
        let size = stride * height as usize;
        let mut buffer = vec![0u8; size];

        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height, // Negative for top-down
                biPlanes: 1,
                biBitCount: (bytes_per_pixel * 8) as u16,
                biCompression: 0, // BI_RGB
                biSizeImage: size as u32,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 }],
        };

        GetDIBits(compat_dc, bitmap, 0, height as u32, buffer.as_mut_ptr() as _, &bmi as *const _ as *mut _, 0);

        SelectObject(compat_dc, old_bitmap);
        DeleteObject(bitmap as _);
        DeleteDC(compat_dc);
        ReleaseDC(hwnd, window_dc);

        Ok(buffer)
    }
}