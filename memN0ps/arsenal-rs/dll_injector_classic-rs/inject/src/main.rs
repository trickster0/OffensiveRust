use obfstr::obfstr;
use std::{env, mem::size_of, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::WriteProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                TH32CS_SNAPPROCESS,
            },
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS},
    },
};

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: inject.exe <process> <dll path>");
        std::process::exit(1);
    }

    let process_name = &args[1];
    let file_path = &args[2];

    log::info!("Process: {}", process_name);
    log::info!("Path: {}", file_path);

    let process_id =
        get_process_id_by_name(process_name).expect(obfstr!("Failed to get process ID"));

    log::info!("Process ID: {}", process_id);

    let hprocess = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };

    if hprocess == 0 {
        panic!("{}", obfstr!("[-] Error: failed to open process"));
    }

    let allocated_memory = unsafe {
        VirtualAllocEx(
            hprocess,
            null_mut(),
            file_path.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    log::info!("Allocated Memory: {:p}", allocated_memory);

    if allocated_memory.is_null() {
        panic!("{}", obfstr!("[-] Error: failed to allocate memory in the process"));
    }

    let mut tmp = 0;
    let wpm_result = unsafe {
        WriteProcessMemory(
            hprocess,
            allocated_memory,
            file_path.as_ptr() as _,
            file_path.len(),
            &mut tmp,
        )
    };

    if wpm_result == 0 {
        panic!("{}", obfstr!("[-] Error: failed to write to process memory"));
    }

    let k32_address = unsafe { GetModuleHandleA(obfstr!("KERNEL32.DLL\0").as_ptr()) };

    if k32_address == 0 {
        panic!("{}", obfstr!("[-] Error: failed to get module handle"));
    }

    log::info!("Kernel32 Address: {:#x}", k32_address);

    let loadlib_address = unsafe {
        GetProcAddress(k32_address, obfstr!("LoadLibraryA\0").as_ptr())
            .expect(obfstr!("Failed to get LoadLibraryA address"))
    };

    log::info!("LoadLibraryA address: {:#x}", loadlib_address as usize);

    let mut tmp = 0;
    let hthread = unsafe {
        CreateRemoteThread(
            hprocess,
            null_mut(),
            0,
            Some(std::mem::transmute(loadlib_address as usize)),
            allocated_memory,
            0,
            &mut tmp,
        )
    };

    if hthread == 0 {
        panic!("{}", obfstr!("[-] Error: failed to create remote thread"));
    }

    unsafe { CloseHandle(hthread) };
    unsafe { CloseHandle(hprocess) };

    log::info!("Injection Complete!");
}

/// Gets the process ID by name, take process name as a parameter
fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(obfstr!("Failed to call CreateToolhelp32Snapshot").to_owned());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err(obfstr!("Failed to call Process32First").to_owned());
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err(obfstr!("Failed to call Process32Next").to_owned());
        }
    }

    return Ok(process_entry.th32ProcessID);
}

/// Converts a C null terminated String to a Rust String
pub fn convert_c_array_to_rust_string(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}