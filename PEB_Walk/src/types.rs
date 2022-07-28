use windows_sys::Win32::Foundation::HWND;
use windows_sys::core::PCSTR;
use std::os::raw::c_ulong;

pub type DWORD = c_ulong;
pub type __uint64 = u64;
pub type DWORD64 = __uint64;
pub type UINT_PTR = __uint64;
pub type MessageBoxA = unsafe extern "system" fn (HWND, PCSTR, PCSTR, u32) -> i32;
pub type LoadLibraryA = unsafe extern "system" fn (PCSTR) -> i32;