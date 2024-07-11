// src/ntobapi_h.rs

// This module contains custom type defs from ntobapi.





#[repr(u32)]
pub enum OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllTypesInformation = 3,
    ObjectHandleInformation = 4,
}


#[repr(C)]
pub struct UNICODE_STRING
{
    pub(crate) Length: u16,
    pub(crate) MaximumLength: u16,
    pub(crate) Buffer: *mut u16,
}


#[repr(C)]
pub struct OBJECT_NAME_INFORMATION
{
    pub(crate) Name: UNICODE_STRING,
}