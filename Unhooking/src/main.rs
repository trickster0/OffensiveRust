extern crate kernel32;
extern crate winapi;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::WriteProcessMemory;

fn main() {
    unsafe {
        let handle = kernel32::LoadLibraryA("ntdll\0".as_ptr() as *const i8);
        let mini = kernel32::GetProcAddress(handle, "NtClose\0".as_ptr() as *const i8);
        WriteProcessMemory(GetCurrentProcess(),mini as *mut c_void, b"\x4C\x8B\xD1\xB8\x0E".as_ptr() as *mut c_void,5,null_mut());
    }
}
