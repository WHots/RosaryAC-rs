//! src/memorymanage.rs

// This module contains utility methods based around internal memory operation.




use std::alloc::{alloc, dealloc, Layout};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use std::{mem, ptr};
use std::ffi::{c_char, CStr};
use std::fmt::Display;
use std::ptr::NonNull;





/// An enum to represent the location of the data
enum DataLocation<T>
{
    Stack(T),
    Heap(NonNull<T>),
}


/// A utility for managing a buffer of `u16` values.
pub struct CleanBuffer {
    buffer: Vec<u16>,
}


/// A struct that can hold data either on the stack or heap
pub struct DynamicData<T>
{
    data: DataLocation<T>,
}


/// Enum to determine the allocation strategy for printing
pub enum PrintAllocation
{
    Stack,
    Heap,
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



impl<T> DynamicData<T>
{
    /// Creates a new DynamicData instance with stack-allocated data
    pub fn new_stack(value: T) -> Self
    {
        DynamicData {
            data: DataLocation::Stack(value),
        }
    }

    /// Creates a new DynamicData instance with heap-allocated data
    pub fn new_heap(value: T) -> Self
    {
        let layout = Layout::new::<T>();
        unsafe {
            let ptr = alloc(layout) as *mut T;
            ptr.write(value);
            DynamicData {
                data: DataLocation::Heap(NonNull::new_unchecked(ptr)),
            }
        }
    }

    /// Determines if the data is allocated on the stack or heap
    pub fn is_stack_allocated(&self) -> bool
    {
        matches!(self.data, DataLocation::Stack(_))
    }

    /// Frees the data if it's heap-allocated
    pub fn free(&mut self)
    {
        if let DataLocation::Heap(ptr) = self.data {
            unsafe {
                let layout = Layout::new::<T>();
                dealloc(ptr.as_ptr() as *mut u8, layout);
            }
            unsafe { self.data = DataLocation::Stack(mem::zeroed()); }
        }
    }

    /// Gets a reference to the contained data
    pub fn get(&self) -> &T
    {
        match &self.data {
            DataLocation::Stack(value) => value,
            DataLocation::Heap(ptr) => unsafe { ptr.as_ref() },
        }
    }

    /// Gets a mutable reference to the contained data
    pub fn get_mut(&mut self) -> &mut T
    {
        match &mut self.data {
            DataLocation::Stack(value) => value,
            DataLocation::Heap(ptr) => unsafe { ptr.as_mut() },
        }
    }


    /// Prints a C string (null-terminated), with the option to allocate on stack or heap
    ///
    /// # Arguments
    ///
    /// * *`c_str`* - A pointer to a null-terminated C string
    /// * *`allocation`* - Determines whether to use stack or heap allocation
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences a raw pointer.
    /// The caller must ensure that the pointer is valid and points to a null-terminated string.
    pub unsafe fn print_c_string(c_str: *const c_char, allocation: PrintAllocation)
    {
        let rust_str = match CStr::from_ptr(c_str).to_str() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("Invalid UTF-8 sequence in C string");
                return;
            }
        };

        let dynamic_string = match allocation {
            PrintAllocation::Stack => DynamicData::new_stack(rust_str.to_string()),
            PrintAllocation::Heap => DynamicData::new_heap(rust_str.to_string()),
        };

        println!("{}", dynamic_string.get());

        drop(dynamic_string);
    }


    /// Prints any type of string, with the option to allocate on stack or heap
    ///
    /// # Arguments
    ///
    /// * *`s`* - The string to be printed
    /// * *`allocation`* - Determines whether to use stack or heap allocation
    ///
    /// # Type Parameters
    ///
    /// * *`S`* - A type that can be converted to a String
    pub fn print_string<S: Into<String> + Display>(s: S, allocation: PrintAllocation)
    {
        let dynamic_string = match allocation {
            PrintAllocation::Stack => DynamicData::new_stack(s.to_string()),
            PrintAllocation::Heap => DynamicData::new_heap(s.to_string()),
        };

        println!("{}", dynamic_string.get());

        drop(dynamic_string);
    }
}


impl<T> Drop for DynamicData<T> {
    fn drop(&mut self) {
        self.free();
    }
}
