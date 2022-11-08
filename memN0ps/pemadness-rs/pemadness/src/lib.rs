#![allow(dead_code)]

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::{arch::asm, mem::size_of};
use sysinfo::{ProcessExt, SystemExt};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64,
    },
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    SystemServices::{
        IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
        IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64,
        IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    },
    WindowsProgramming::IMAGE_THUNK_DATA64,
};

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

/// Process image relocations (rebase image)
pub unsafe fn rebase_image(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    // Calculate the difference between remote allocated memory region where the image will be loaded and preferred ImageBase (delta)
    let delta = module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    // Return early if delta is 0
    if delta == 0 {
        return Some(true);
    }

    // Resolve the imports of the newly allocated memory region

    // Get a pointer to the first _IMAGE_BASE_RELOCATION
    let mut base_relocation = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;

    if base_relocation.is_null() {
        return Some(false);
    }

    // Get the end of _IMAGE_BASE_RELOCATION
    let base_relocation_end = base_relocation as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size
            as usize;

    while (*base_relocation).VirtualAddress != 0u32
        && (*base_relocation).VirtualAddress as usize <= base_relocation_end
        && (*base_relocation).SizeOfBlock != 0u32
    {
        // Get the VirtualAddress, SizeOfBlock and entries count of the current _IMAGE_BASE_RELOCATION block
        let address = (module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;
        let item =
            (base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
        let count = ((*base_relocation).SizeOfBlock as usize
            - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
            / std::mem::size_of::<u16>() as usize;

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //IMAGE_REL_BASED_DIR32 does not exist
            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize)
            as *mut IMAGE_BASE_RELOCATION;
    }

    return Some(true);
}

/// Process image import table (resolve imports)
pub unsafe fn resolve_imports(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize)
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null() {
        return Some(false);
    }

    while (*import_directory).Name != 0x0 {
        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (module_base as usize + (*import_directory).Name as usize) as *const i8;

        if dll_name.is_null() {
            return Some(false);
        }

        // Load the DLL in the in the address space of the process by calling the function pointer LoadLibraryA
        let dll_handle = LoadLibraryA(dll_name as _);

        if dll_handle == 0 {
            return Some(false);
        }

        // Get a pointer to the Original Thunk or First Thunk via OriginalFirstThunk or FirstThunk
        let mut original_thunk = if (module_base as usize
            + (*import_directory).Anonymous.OriginalFirstThunk as usize)
            != 0
        {
            #[cfg(target_arch = "x86")]
            let orig_thunk = (module_base as usize
                + (*import_directory).Anonymous.OriginalFirstThunk as usize)
                as *mut IMAGE_THUNK_DATA32;
            #[cfg(target_arch = "x86_64")]
            let orig_thunk = (module_base as usize
                + (*import_directory).Anonymous.OriginalFirstThunk as usize)
                as *mut IMAGE_THUNK_DATA64;

            orig_thunk
        } else {
            #[cfg(target_arch = "x86")]
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA32;
            #[cfg(target_arch = "x86_64")]
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA64;

            thunk
        };

        if original_thunk.is_null() {
            return Some(false);
        }

        #[cfg(target_arch = "x86")]
        let mut thunk = (module_base as usize + (*import_directory).FirstThunk as usize)
            as *mut IMAGE_THUNK_DATA32;
        #[cfg(target_arch = "x86_64")]
        let mut thunk = (module_base as usize + (*import_directory).FirstThunk as usize)
            as *mut IMAGE_THUNK_DATA64;

        if thunk.is_null() {
            return Some(false);
        }

        while (*original_thunk).u1.Function != 0 {
            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0) or #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
            #[cfg(target_arch = "x86")]
            let snap_result = ((*original_thunk).u1.Ordinal) & IMAGE_ORDINAL_FLAG32 != 0;
            #[cfg(target_arch = "x86_64")]
            let snap_result = ((*original_thunk).u1.Ordinal) & IMAGE_ORDINAL_FLAG64 != 0;

            if snap_result {
                //#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff) or #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                let fn_ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as *const u8;

                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by ordinal
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_ordinal).unwrap() as _;
            } else {
                // Get a pointer to _IMAGE_IMPORT_BY_NAME
                let thunk_data = (module_base as usize
                    + (*original_thunk).u1.AddressOfData as usize)
                    as *mut IMAGE_IMPORT_BY_NAME;

                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr();
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by name
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_name).unwrap() as _;
                //
            }

            // Increment and get a pointer to the next Thunk and Original Thunk
            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        // Increment and get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory =
            (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }

    return Some(true);
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

/// Read memory from a location specified by an offset relative to the beginning of the GS segment.
#[cfg(target_arch = "x86_64")]
pub unsafe fn __readgsqword(offset: u64) -> u64 {
    let output: u64;
    std::arch::asm!("mov {}, gs:[{}]", out(reg) output, in(reg) offset);
    output
}

/// Read memory from a location specified by an offset relative to the beginning of the FS segment.
#[cfg(target_arch = "x86")]
pub unsafe fn __readfsdword(offset: u32) -> u32 {
    let output: u64;
    std::arch::asm!("mov {}, fs:[{}]", out(reg) output, in(reg) offset);
    output
}
