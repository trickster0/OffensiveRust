#![cfg(windows)]
use std::ptr::null_mut;
use winapi::{um::winuser::MessageBoxA, shared::minwindef::DWORD};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "C" fn popit() {
    unsafe {MessageBoxA(null_mut(),"Rust DLL Test\0".as_ptr() as *const i8,"Rust DLL Test\0".as_ptr() as *const i8,0x00004000);}
}

const DLL_PROCESS_ATTACH: DWORD = 1;
// const DLL_PROCESS_DETACH: DWORD = 0;

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(_inst: isize, reason: u32, _: *const u8) -> u32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            MessageBoxA(null_mut(),"Rust DLL Test\0".as_ptr() as *const i8,"Rust DLL Test\0".as_ptr() as *const i8,0x00004000);
        }
    }
    1 // Return true
}
