use std::{
    env,
    ptr,
    ffi::CString,
    mem::transmute
};

use winapi::{
    um::{
        memoryapi::{
            VirtualAllocEx,
            WriteProcessMemory
        },
        libloaderapi::{
            GetProcAddress,
            GetModuleHandleA
        },
        winnt::{
            PROCESS_ALL_ACCESS,
            HANDLE,
            PAGE_EXECUTE_READWRITE,
            MEM_COMMIT,
            MEM_RESERVE
        },
        processthreadsapi::{
            OpenProcess,
            CreateRemoteThread
        },
        handleapi::{
            INVALID_HANDLE_VALUE,
            CloseHandle
        }
    },
    shared::{
        minwindef::{
            FALSE,
            FARPROC,
        },
        ntdef::NULL
    }
};

use win32_error::Win32Error;

fn main() {
    let args: Vec<_> = env::args().collect();
    let pid: u32;
    let remote_handle: HANDLE;
    let load_library_address: FARPROC;

    if args.len() < 2 {
        println!("Usage: dllinjection.exe <pid> <dll_path>");
        return;
    }
    let target = &args[1];
    let dll_path = &args[2];

    // Validating the PID to spawn to.
    if target.parse::<u32>().is_ok() {
        pid = target.parse::<u32>().unwrap();
    }
    else {
        println!("[-] Not a valid PID!");
        return;
    }

    // Getting handle to the process.
    unsafe {
        remote_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);        
    }

    if remote_handle == NULL || remote_handle == INVALID_HANDLE_VALUE {
        print_err();
        return;
    }
    println!("[+] Got process handle");

    unsafe {
        // Allocating space for the dll name.
        let base_address = VirtualAllocEx(remote_handle, NULL, dll_path.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if base_address.is_null() {
            CloseHandle(remote_handle);
            print_err();
            return;
        }
        println!("[+] Mapped memory address");

        // Getting the address of LoadLibraryA.
        load_library_address = GetProcAddress(GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr()), CString::new("LoadLibraryA").unwrap().as_ptr());

        if load_library_address.is_null() {
            CloseHandle(remote_handle);
            print_err();
            return;
        }
        println!("[+] Got the address of LoadLibraryA");

        // Writting the address among with the dll name.
        let res = WriteProcessMemory(remote_handle, base_address, dll_path.as_ptr().cast(), dll_path.len(), ptr::null_mut());

        if res == FALSE {
            CloseHandle(remote_handle);
            print_err();
            return;
        }
        println!("[+] Written data to remote process");

        // Spawning remote thread.
        let dll_thread = CreateRemoteThread(remote_handle, ptr::null_mut(), 0, Some(transmute(load_library_address)), base_address, 0, ptr::null_mut());

        if dll_thread.is_null() {
            CloseHandle(remote_handle);
            print_err();
            return;
        }
        println!("[+] DLL executed!");

        CloseHandle(dll_thread);
        CloseHandle(remote_handle);
    }
}

fn print_err() {
    let err = Win32Error::new();
    println!("[-] {}", err.to_string());
}