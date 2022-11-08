use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::{arch::asm, collections::BTreeMap, ffi::CStr};
use sysinfo::{ProcessExt, SystemExt};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

use crate::obf::dbj2_hash;

pub fn get_ssn(module_hash: u32) -> Option<(u16, u64)> {
    let module_base = unsafe {
        get_loaded_module_by_hash(crate::obf!("ntdll.dll"))
            .expect("Failed to get loaded module by name")
    };

    let mut nt_exports = BTreeMap::new();

    for (name, addr) in unsafe { get_exports_by_name(module_base) } {
        //
        // FreshyCalls
        //

        /*
            // Check to see if stubs starts with Nt but not with Ntdll

            if name.starts_with("Nt") && !name.starts_with("Ntdll") {
                nt_exports.insert(name, addr);
            }

        */

        //
        // Syswhispers2 Patch
        //

        // Check to see if stubs starts with Zw and replace with Nt
        if name.starts_with("Zw") {
            nt_exports.insert(name.replace("Zw", "Nt"), addr);
        }
    }

    let mut nt_exports_vec: Vec<(String, usize)> = Vec::from_iter(nt_exports);
    // sort all Nt functions by address
    nt_exports_vec.sort_by_key(|k| k.1);

    // First Nt addresses has system call number of 0 and so on...

    let mut syscall_number: u16 = 0;

    for exports in nt_exports_vec {
        if module_hash == dbj2_hash(exports.0.as_bytes()) {
            let syscall_instruction = unsafe { get_syscall_instruction_address(exports.1 as _).expect("Failed to get syscall instruction address from ntdll") };
            return Some((syscall_number, syscall_instruction as u64));
        }
        syscall_number += 1;
    }

    return None;
}

const UP: isize = -32;
const DOWN: usize = 32;

/// Get the address of the syscall instruction from ntdll.dll (Similar to Hell's Gate / Halo's Gate and Tartarus' Gate)
pub unsafe fn get_syscall_instruction_address(function_address: *mut u8) -> Option<usize> {

    // we don't really care if there is a 'jmp' between the Nt API address and the `syscall; ret` instruction
    for x in 0..25 {
        if function_address.add(x).read() == 0x0f && function_address.add(x + 1).read() == 0x05 && function_address.add(x + 2).read() == 0xc3  {
            return Some(function_address.add(x) as _);
        }
    }
    
    // 
    // Hell's gate for `syscall` instruction rather than `SSN`
    //

    // check if the assembly instruction are (0x0f, 0x05, 0xc3):
    // syscall
    // ret
    if function_address.add(18).read() == 0x0f && function_address.add(19).read() == 0x05 && function_address.add(20).read() == 0xc3  {
        return Some(function_address.add(18) as _);
    }

    //
    // Halo's Gate and Tartarus' Gate Patch for `syscall` instruction rather than `SSN`
    //

    if function_address.read() == 0xe9 || function_address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            
            //
            // if hooked check the neighborhood to find clean syscall (downwards)
            //
            
            if function_address.add(18 + idx * DOWN).read() == 0x0f && function_address.add(19 + idx * DOWN).read() == 0x05 && function_address.add(20 + idx * DOWN).read() == 0xc3 {
                return Some(function_address.add(18 + idx * DOWN) as _);
            }
            
            //
            // if hooked check the neighborhood to find clean syscall (upwards)
            //
            if function_address.offset(18 + idx as isize * UP).read() == 0x0f && function_address.offset(19 + idx as isize * UP).read() == 0x05 && function_address.offset(20 + idx as isize * UP).read() == 0xc3 {
                return Some(function_address.add(18 + idx * DOWN) as _);
            }
        }
    }

    return None;
}


/// Get process ID by name
pub fn get_process_id_by_name(target_process: &str) -> usize {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id: usize = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }
    return process_id;
}

/// Gets a pointer to IMAGE_NT_HEADERS32 x86
#[cfg(target_arch = "x86")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS32> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Gets a pointer to IMAGE_NT_HEADERS32 x86_64
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Gets a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;

    let mut module_list =
        (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    return None;
}

/// Get the address of an export by hash
pub unsafe fn get_exports_by_name(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let nt_headers = get_nt_headers(module_base).unwrap();

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;

        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }

    return exports;
}

/// Get the length of a C String
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }
    (tmp - pointer as u64) as _
}
