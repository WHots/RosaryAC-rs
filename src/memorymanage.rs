use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};












pub struct CleanHandle {
    handle: HANDLE,
}
impl CleanHandle
{
    pub(crate) fn new(handle: HANDLE) -> Option<Self>
    {
        if handle == 0
        {
            None
        }
        else
        {
            Some(Self { handle })
        }
    }

    pub(crate) fn as_raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for CleanHandle
{
    fn drop(&mut self)
    {
        unsafe { CloseHandle(self.handle) };
    }
}

