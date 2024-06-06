use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use std::ptr;











/// A utility for managing a buffer of `u16` values.
pub struct CleanBuffer {
    buffer: Vec<u16>,
}

impl CleanBuffer 
{
    /// Creates a new `BufferManager` instance with the specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - The initial size of the buffer.
    ///
    /// # Returns
    ///
    /// A new `BufferManager` instance.
    pub fn new(size: usize) -> Self 
    {
        let mut buffer = Vec::with_capacity(size);

        unsafe {
            buffer.set_len(size);
        }

        Self { buffer }
    }

    /// Resizes the buffer to the specified new size.
    ///
    /// # Arguments
    ///
    /// * `new_size` - The new size for the buffer.
    pub fn resize(&mut self, new_size: usize) 
    {
        self.buffer.resize(new_size, 0);
    }


    /// Returns a mutable pointer to the buffer's data.
    ///
    /// # Returns
    ///
    /// A mutable pointer to the buffer's data.
    pub fn as_mut_ptr(&mut self) -> *mut u16 
    {
        self.buffer.as_mut_ptr()
    }


    /// Returns a slice of the buffer's data.
    ///
    /// # Returns
    ///
    /// A slice of the buffer's data.
    pub fn as_slice(&self) -> &[u16] 
    {
        &self.buffer
    }


     /// Truncates the buffer at the position of the first null character (0).
    pub fn truncate_at_null(&mut self) 
    {
        if let Some(null_pos) = self.buffer.iter().position(|&x| x == 0) 
        {
            self.buffer.truncate(null_pos);
        }
    }
}

impl Drop for CleanBuffer 
{
     /// Drops the `BufferManager`, clearing its memory.
    fn drop(&mut self) 
    {
        unsafe {
            ptr::write_bytes(self.buffer.as_mut_ptr(), 0, self.buffer.len());
        }
    }
}



/// A wrapper for the Windows `HANDLE` type that ensures the handle is closed properly.
pub struct CleanHandle {
    handle: HANDLE,
}

impl CleanHandle
{
    /// Creates a new `CleanHandle` instance with the specified handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle to wrap.
    ///
    /// # Returns
    ///
    /// A new `CleanHandle` instance.
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


    /// Returns the raw handle.
    ///
    /// # Returns
    ///
    /// The raw handle.
    pub(crate) fn as_raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for CleanHandle
{
    /// Drops the `CleanHandle`, closing the associated handle.
    fn drop(&mut self)
    {
        unsafe { CloseHandle(self.handle) };
    }
}

